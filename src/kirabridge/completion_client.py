"""Standing return-channel consumer. It invokes a callback, then acknowledges.

Read/ack calls may reconnect; execution requests are never retried here. A callback
must deduplicate notice IDs across its own crashes: transport delivery is at least once.
"""

from __future__ import annotations

import asyncio
import inspect

from kirabridge.bridge_core.models import BridgeError
from kirabridge.mcp_gateway.client import MCPClientPool


class CompletionClient:
    def __init__(self, endpoint, *, pool=None):
        self.endpoint = endpoint
        self.pool = pool or MCPClientPool(call_timeout=25)
        self.owns_pool = pool is None

    async def call(self, tool, arguments):
        # Only these idempotent delivery operations may be retried, not task submission.
        for attempt in range(3):
            try:
                if self.endpoint.id not in self.pool.sessions:
                    await self.pool.disconnect(self.endpoint.id)
                    await self.pool.connect(self.endpoint)
                result = await self.pool.call(self.endpoint.id, tool, arguments)
                value = result.structuredContent
                if result.isError or not isinstance(value, dict) or value.get("error"):
                    raise RuntimeError(f"Completion tool rejected: {value}")
                return value
            except BridgeError as exc:
                if exc.code not in {"peer_connection", "peer_disconnected", "peer_unknown"}:
                    raise
                await self.pool.disconnect(self.endpoint.id)
                if attempt == 2:
                    raise
                await asyncio.sleep(0.1 * (2**attempt))

    async def listen(self, target, callback, *, once=False, timeout=None):
        """No runtime-dependent registration delay or periodic task_get calls."""
        async with asyncio.timeout(timeout):
            while True:
                result = await self.call(
                    "completion_receive",
                    {
                        "target": target,
                        "limit": 1,
                        "wait_seconds": 20,
                    },
                )
                for notice in result["notices"]:
                    response = callback(notice)
                    if inspect.isawaitable(response):
                        await response
                    await self.call(
                        "completion_ack",
                        {
                            "notice_id": notice["id"],
                            "receipt": notice["receipt"],
                        },
                    )
                    if once:
                        return notice

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        if self.owns_pool:
            await self.pool.close()
