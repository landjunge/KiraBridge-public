from __future__ import annotations

import asyncio
import re
import time
import uuid
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from kirabridge.bridge_core.models import BridgeError, digest


class ObservedClientSession(ClientSession):
    def __init__(self, *args, notice, **kwargs):
        self.notice = notice
        super().__init__(*args, **kwargs)

    async def send_request(self, request, *args, **kwargs):
        initializing = isinstance(request.root, types.InitializeRequest)
        if initializing:
            self.notice("initialize.started")
        result = await super().send_request(request, *args, **kwargs)
        if initializing:
            self.notice("initialize.response")
        return result

    async def send_notification(self, notification, *args, **kwargs):
        result = await super().send_notification(notification, *args, **kwargs)
        if isinstance(notification.root, types.InitializedNotification):
            self.notice("initialized.sent", notification_receipt="unknown; queued to SDK stream")
        return result


@dataclass(frozen=True)
class Peer:
    """Trusted, explicitly configured endpoints. stdio programs are local execution authority."""

    id: str
    url: str | None = None
    command: str | None = None
    args: tuple[str, ...] = ()
    token: str | None = field(default=None, repr=False)
    ca_file: str | None = None
    env: dict[str, str] | None = field(default=None, repr=False)
    cwd: str | None = None


class MCPClientPool:
    """One dedicated owner coroutine per connection, preserving anyio cancel-scope ownership."""

    interface_version = "1"

    def __init__(self, max_connections: int = 8, call_timeout: float = 30, observer=None):
        self.max_connections, self.call_timeout = max_connections, call_timeout
        self.owners: dict[str, asyncio.Task] = {}
        self.sessions: dict[str, ClientSession] = {}
        self.stops: dict[str, asyncio.Event] = {}
        self.gate = asyncio.Semaphore(32)
        self.observer = observer
        self.connection_ids: dict[str, str] = {}
        self.previous_ids: dict[str, str] = {}
        self.observation_failures = 0
        self.phases: dict[str, str] = {}

    def notice(self, peer_id, phase, **metadata):
        self.phases[peer_id] = phase
        if self.observer:
            try:
                self.observer(
                    "connection",
                    {
                        "connection_id": self.connection_ids.get(peer_id),
                        "phase": phase,
                        "peer_ref": digest(peer_id),
                        "observer": "own_mcp_client",
                        "external_tunnel": "unknown",
                        **metadata,
                    },
                    task_id=metadata.get("task_id"),
                )
            except Exception:
                self.observation_failures += 1

    def failure(self, peer_id, code, message, *, task_id=None, operation="mcp.connect"):
        exc = BridgeError(code, message)
        exc.diagnostic = {
            "schema": "1",
            "diagnostic_id": uuid.uuid4().hex,
            "task_id": task_id,
            "at": time.time(),
            "operation": operation
            if re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", operation)
            else "unknown",
            "error_code": code,
            "connection_id": self.connection_ids.get(peer_id),
            "phase": self.phases.get(peer_id, "unknown"),
            "accepted": "unknown",
            "started": "unknown",
            "completed": "unknown",
            "execution_runtime": "unknown",
            "observer_runtime": getattr(self.observer, "runtime", "unknown"),
            "external_tunnel_lifecycle": "unknown",
            "automatic_retry": False,
            "guidance": "Reinitialize/reconnect only the connection; read the original task ID. "
            "Never blindly repeat a write with an uncertain outcome.",
        }
        return exc

    async def connect(self, peer: Peer) -> None:
        if peer.id in self.owners or len(self.owners) >= self.max_connections:
            raise BridgeError(
                "connection_limit", "Duplicate peer identity or connection capacity reached"
            )
        if bool(peer.url) == bool(peer.command):
            raise BridgeError("peer_config", "Configure exactly one transport per peer")
        if peer.url:
            parsed = urlparse(peer.url)
            local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            if parsed.username or parsed.password or parsed.fragment or parsed.query:
                raise BridgeError(
                    "peer_config", "Credentials and parameters must not be in endpoint URLs"
                )
            if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
                raise BridgeError("insecure_peer", "Remote MCP peers require HTTPS")
        ready = asyncio.get_running_loop().create_future()
        stop = asyncio.Event()
        self.stops[peer.id] = stop
        self.connection_ids[peer.id] = uuid.uuid4().hex
        self.notice(
            peer.id,
            "connect.started",
            transport="http" if peer.url else "stdio",
            previous_connection_id=self.previous_ids.get(peer.id),
        )

        async def owner():
            try:
                async with AsyncExitStack() as stack:
                    if peer.url:
                        import ssl

                        client = await stack.enter_async_context(
                            httpx.AsyncClient(
                                headers={"Authorization": f"Bearer {peer.token}"}
                                if peer.token
                                else {},
                                timeout=httpx.Timeout(self.call_timeout, read=300),
                                trust_env=False,
                                follow_redirects=False,
                                verify=ssl.create_default_context(cafile=peer.ca_file)
                                if peer.ca_file
                                else True,
                            )
                        )
                        read, write, _ = await stack.enter_async_context(
                            streamable_http_client(peer.url, http_client=client)
                        )
                    else:
                        read, write = await stack.enter_async_context(
                            stdio_client(
                                StdioServerParameters(
                                    command=peer.command,
                                    args=list(peer.args),
                                    env=peer.env or {},
                                    cwd=peer.cwd,
                                ),
                            )
                        )
                    self.notice(peer.id, "transport.context_opened")
                    session = await stack.enter_async_context(
                        ObservedClientSession(
                            read,
                            write,
                            notice=lambda phase, **meta: self.notice(peer.id, phase, **meta),
                        )
                    )
                    async with asyncio.timeout(self.call_timeout):
                        await session.initialize()
                    self.sessions[peer.id] = session
                    self.notice(peer.id, "connection.ready")
                    ready.set_result(None)
                    await stop.wait()
            except BaseException:
                self.notice(peer.id, "connection.interrupted", error_code="peer_connection")
                if not ready.done():
                    ready.set_exception(
                        self.failure(peer.id, "peer_connection", "MCP connection failed")
                    )
            finally:
                self.sessions.pop(peer.id, None)
                self.notice(peer.id, "connection.closed")

        self.owners[peer.id] = asyncio.create_task(owner())
        try:
            async with asyncio.timeout(self.call_timeout):
                await ready
        except TimeoutError:
            failure = self.failure(peer.id, "peer_connection", "MCP initialization timed out")
            self.notice(peer.id, "connect.timed_out", error_code="peer_connection")
            await self.disconnect(peer.id)
            raise failure from None
        except BaseException:
            await self.disconnect(peer.id)
            raise

    async def call(self, peer_id: str, tool: str, arguments: dict, *, task_id: str | None = None):
        request = arguments.get("request")
        task_id = (
            task_id
            or arguments.get("task_id")
            or (request.get("task_id") if isinstance(request, dict) else None)
        )
        if not isinstance(task_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", task_id):
            task_id = None
        session = self.sessions.get(peer_id)
        if session is None:
            raise self.failure(
                peer_id,
                "peer_disconnected",
                "MCP peer is not connected",
                task_id=task_id,
                operation=tool,
            )
        self.notice(peer_id, "call.started", tool=tool, task_id=task_id)
        # No automatic retries: a timed-out tool may have already executed remotely.
        try:
            async with self.gate, asyncio.timeout(self.call_timeout):
                result = await session.call_tool(tool, arguments)
                self.notice(
                    peer_id,
                    "call.returned",
                    tool=tool,
                    task_id=task_id,
                    outcome="response_received",
                )
                return result
        except TimeoutError:
            self.notice(
                peer_id,
                "call.outcome_unknown",
                tool=tool,
                task_id=task_id,
                error_code="peer_unknown",
            )
            raise self.failure(
                peer_id,
                "peer_unknown",
                "Tool outcome unknown; do not retry blindly",
                task_id=task_id,
                operation=tool,
            ) from None
        except Exception:
            self.notice(
                peer_id,
                "call.outcome_unknown",
                tool=tool,
                task_id=task_id,
                error_code="peer_unknown",
            )
            raise self.failure(
                peer_id,
                "peer_unknown",
                "Tool outcome unknown; reconcile before retry",
                task_id=task_id,
                operation=tool,
            ) from None
        except asyncio.CancelledError:
            self.notice(
                peer_id, "call.interrupted", tool=tool, task_id=task_id, error_code="peer_unknown"
            )
            raise

    async def disconnect(self, peer_id: str) -> None:
        owner = self.owners.get(peer_id)
        if owner:
            self.notice(peer_id, "disconnect.requested")
            self.stops[peer_id].set()
            try:
                async with asyncio.timeout(5):
                    await asyncio.shield(owner)
            except TimeoutError:
                owner.cancel()
                await asyncio.gather(owner, return_exceptions=True)
            self.owners.pop(peer_id, None)
            self.stops.pop(peer_id, None)
            self.previous_ids[peer_id] = self.connection_ids.pop(peer_id)
            self.phases.pop(peer_id, None)
            while len(self.previous_ids) > self.max_connections:
                self.previous_ids.pop(next(iter(self.previous_ids)))

    async def close(self) -> None:
        for peer_id in list(self.owners):
            await self.disconnect(peer_id)
        if self.observer:
            try:
                self.observer.close()
            except Exception:
                self.observation_failures += 1

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()
