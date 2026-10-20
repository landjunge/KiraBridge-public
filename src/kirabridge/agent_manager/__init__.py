from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Protocol

import httpx

from kirabridge.agent_manager.claude import ClaudeCodeAdapter
from kirabridge.agent_manager.copilot import CopilotCLIAdapter
from kirabridge.agent_manager.gemini import GeminiAdapter
from kirabridge.agent_manager.opencode import OpenCodeAdapter
from kirabridge.bridge_core.config import AgentConfig, Config
from kirabridge.bridge_core.models import AgentInput, BridgeError, TerminalInput, UncertainExecution
from kirabridge.filesystem_manager import PathScope
from kirabridge.platform_adapters import reap_process, spawn_process
from kirabridge.terminal_manager import EvidenceCallback, TerminalManager, minimal_environment


async def bounded_lines(response, limit=1048576):
    pending = bytearray()
    async for chunk in response.aiter_bytes(chunk_size=8192):
        pending.extend(chunk)
        while b"\n" in pending:
            line, _, remainder = pending.partition(b"\n")
            if len(line) > limit:
                raise UncertainExecution("provider_protocol", "Provider event exceeds byte limit")
            pending = bytearray(remainder)
            yield line.decode("utf-8")
        if len(pending) > limit:
            raise UncertainExecution("provider_protocol", "Provider event exceeds byte limit")
    if pending:
        yield pending.decode("utf-8")


class AgentAdapter(Protocol):
    interface_version: str

    async def execute(
        self,
        task: dict,
        args: AgentInput,
        config: AgentConfig,
        roots: list[str],
        running: EvidenceCallback,
        progress: EvidenceCallback,
    ) -> dict: ...


def agent_environment(config: AgentConfig, terminal: TerminalManager | None = None) -> dict:
    env = terminal.environment.copy() if terminal else minimal_environment()
    env["HOME"] = str(Path.home())
    for key in (config.api_key_env, "CODEX_API_KEY"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


class CodexAdapter:
    interface_version = "1"

    def __init__(self, terminal: TerminalManager, bridge_config=None):
        self.terminal = terminal
        self.bridge_config = bridge_config

    async def execute(
        self,
        task,
        args,
        config,
        roots,
        running,
        progress,
        *,
        owned_resume_session=None,
        handoff_reply=False,
    ) -> dict:
        if not config.executable:
            raise BridgeError("agent_config", "Codex executable must be configured explicitly")
        if owned_resume_session is not None:
            try:
                if str(uuid.UUID(owned_resume_session)) != owned_resume_session:
                    raise ValueError()
            except (ValueError, TypeError, AttributeError):
                raise BridgeError(
                    "agent_identity", "An exact owned session UUID is required"
                ) from None
        session, completed, failed, started = owned_resume_session, False, False, False
        messages: list[str] = []
        message_bytes = 0
        provider_error = None

        async def event(line: str):
            nonlocal session, completed, failed, started, message_bytes, provider_error
            try:
                value = json.loads(line)
            except ValueError:
                return
            kind = value.get("type")
            if kind in {"error", "turn.failed"}:
                error = value.get("error")
                code = error.get("code") if isinstance(error, dict) else None
                categories = {
                    "insufficient_quota": "quota_exhausted",
                    "quota_exceeded": "quota_exhausted",
                    "rate_limit_exceeded": "rate_limit",
                    "invalid_api_key": "authentication",
                    "authentication_error": "authentication",
                }
                if isinstance(code, str) and code in categories:
                    from kirabridge.bridge_core.models import digest

                    provider_error = {
                        "provider": "codex",
                        "code": code,
                        "category": categories[code],
                        "source": "codex_jsonl",
                        "event": kind,
                        "event_sha256": digest(value),
                    }
                    await progress(
                        {
                            "agent": args.agent,
                            "session_id": session,
                            "event": "provider_error_observed",
                            "provider_error": provider_error,
                        }
                    )
            if kind == "thread.started" and isinstance(value.get("thread_id"), str):
                if session and session != value["thread_id"]:
                    raise UncertainExecution("agent_identity", "Codex changed session identity")
                session = value["thread_id"]
                await progress({"agent": args.agent, "session_id": session, "event": kind})
            elif kind == "turn.started" and session and not started:
                started = True
                await running({"agent": args.agent, "session_id": session, "event": kind})
            elif kind == "turn.completed" and session and started:
                completed = True
            elif kind == "turn.failed":
                failed = True
            elif kind == "item.completed":
                item = value.get("item", {})
                if item.get("type") == "agent_message" and isinstance(item.get("text"), str):
                    data = item["text"].encode()[: max(0, 65536 - message_bytes)]
                    message_bytes += len(data)
                    if data:
                        messages.append(data.decode("utf-8", "replace"))

        command = [
            config.executable,
            "exec",
            "--ignore-user-config",
            "--json",
            "--skip-git-repo-check",
            "--sandbox",
            config.sandbox_mode,
            "-c",
            'approval_policy="never"',
            "-c",
            "mcp_servers={}",
            "-c",
            "features.multi_agent=false",
        ]
        bridge_enabled = bool(config.bridge_tools and self.bridge_config)
        if bridge_enabled:
            from kirabridge.agent_manager.full_access import bridge_server

            spec = bridge_server(self.bridge_config._source_path, args.agent)
            position = command.index("mcp_servers={}")
            command[position] = "mcp_servers.kirabridge.command=" + json.dumps(spec["command"])
            command += ["-c", "mcp_servers.kirabridge.args=" + json.dumps(spec["args"])]
        if owned_resume_session is not None:
            command += ["resume", "--json", "--ignore-user-config", "--skip-git-repo-check"]
        if handoff_reply:
            command += [
                "--output-schema",
                str(Path(__file__).with_name("handoff_reply.schema.json")),
            ]
        if config.model:
            command += ["--model", config.model]
        if owned_resume_session is not None:
            command += [owned_resume_session]
        command += ["-"]

        async def spawned(evidence):
            await progress({"agent": args.agent, **evidence})

        result = await self.terminal.execute(
            task["id"],
            task["principal"],
            TerminalInput(argv=command, cwd=args.cwd, timeout=args.timeout),
            roots,
            [config.executable],
            spawned,
            env=agent_environment(config, self.terminal),
            stdin=args.prompt.encode(),
            line_callback=event,
        )
        evidence = {
            "agent": args.agent,
            "adapter": "codex",
            "sandbox_mode": config.sandbox_mode,
            "pid": result["pid"],
            "project_rules_enabled": True,
            "mcp_servers_enabled": bridge_enabled,
            "session_id": session,
            "exit_code": result["exit_code"],
            "turn_completed": completed,
            "turn_failed": failed,
            "timed_out": result["timed_out"],
            "terminated": result["terminated"],
            "provider_error": provider_error,
        }
        if not completed and not failed:
            await progress(evidence)
            raise UncertainExecution("agent_unconfirmed", "No Codex turn completion evidence")
        if not started:
            await running({**evidence, "event": "terminal_response_observed"})
        return {
            "evidence": evidence,
            "text": "\n".join(messages),
            "final_message": messages[-1] if messages else "",
            "success": completed and not failed and result["exit_code"] == 0,
            "scope": "agent_turn",
            "project_completion_verified": False,
        }


class GrokAPIAdapter:
    """One text-only model turn. No local tools and no implicit provider retries."""

    interface_version = "1"

    async def execute(self, task, args, config, roots, running, progress) -> dict:
        key = os.environ.get(config.api_key_env)
        if not key or not config.model:
            raise BridgeError("agent_config", "Grok API requires a model and API-key environment")
        text, response_id, finish, started = bytearray(), None, None, False
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(args.timeout), trust_env=False
            ) as client:
                async with client.stream(
                    "POST",
                    "https://api.x.ai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}"},
                    json={
                        "model": config.model,
                        "messages": [{"role": "user", "content": args.prompt}],
                        "stream": True,
                    },
                ) as response:
                    if response.status_code != 200:
                        uncertain = response.status_code >= 500 or response.status_code == 408
                        exc = (
                            UncertainExecution("provider_unknown", "Provider outcome is unknown")
                            if uncertain
                            else BridgeError("provider_rejected", "Grok API rejected the request")
                        )
                        exc.provider_error = {
                            "provider": "xai",
                            "source": "provider_http_status",
                            "http_status": response.status_code,
                            "category": {
                                401: "authentication",
                                403: "authentication",
                                429: "rate_limit",
                            }.get(response.status_code, "provider"),
                        }
                        # HTTP 429 is rate limiting, not evidence of exhausted quota.
                        raise exc
                    async for line in bounded_lines(response):
                        if line == "data: [DONE]":
                            break
                        if not line.startswith("data: "):
                            continue
                        if len(line) > 1048576:
                            raise UncertainExecution("provider_protocol", "Grok event too large")
                        event = json.loads(line[6:])
                        event_id = event.get("id")
                        if response_id and event_id != response_id:
                            raise UncertainExecution(
                                "agent_identity", "Grok response identity changed"
                            )
                        response_id = event_id
                        if not isinstance(response_id, str):
                            continue
                        if not started:
                            started = True
                            await running(
                                {
                                    "agent": args.agent,
                                    "response_id": response_id,
                                    "event": "model_response_chunk",
                                }
                            )
                        for choice in event.get("choices", []):
                            content = choice.get("delta", {}).get("content") or ""
                            text.extend(content.encode()[: max(0, 65536 - len(text))])
                            finish = choice.get("finish_reason") or finish
        except (httpx.HTTPError, ValueError) as exc:
            raise UncertainExecution(
                "provider_disconnected", "Grok response cannot be confirmed"
            ) from exc
        if not started or not finish:
            raise UncertainExecution("provider_unconfirmed", "No Grok completion evidence")
        return {
            "success": finish == "stop",
            "text": text.decode("utf-8", "replace"),
            "evidence": {
                "agent": args.agent,
                "adapter": "grok_api",
                "response_id": response_id,
                "finish_reason": finish,
            },
            "scope": "model_turn",
            "project_completion_verified": False,
        }


class GrokACPAdapter:
    """ACP v1: text by default; local tools require config, principal and task opt-in."""

    interface_version = "1"

    def __init__(self, terminal: TerminalManager | None = None, bridge_config=None):
        self.terminal = terminal
        self.bridge_config = bridge_config

    async def execute(self, task, args, config, roots, running, progress) -> dict:
        if not config.executable:
            raise BridgeError("agent_config", "Grok executable must be configured explicitly")
        local_tools = config.allow_local_tools and args.local_tools
        bridge_enabled = bool(config.bridge_tools and self.bridge_config)
        command = [
            config.executable,
            "--no-subagents",
            "--disable-web-search",
            "--permission-mode",
            "dontAsk",
            "--deny",
            "MCPTool",
            "--deny",
            "WebFetch",
            "--deny",
            "WebSearch",
            "agent",
            "--no-leader",
            "stdio",
        ]
        if bridge_enabled:
            command = [
                config.executable,
                "--permission-mode",
                "bypassPermissions",
                "agent",
                "--no-leader",
                "stdio",
            ]
        # No arbitrary MCP attachment, even for a development task. Receivers never
        # opt in through message text; their AgentInput keeps local_tools=False.
        if local_tools:
            command[1:1] = ["--allow", "Bash", "--allow", "Edit", "--allow", "Read"]
        else:
            command[1:1] = ["--deny", "Bash", "--deny", "Edit"]
        if config.model:
            command[1:1] = ["--model", config.model]
        with PathScope(roots).directory(args.cwd) as fd:
            process = await spawn_process(
                command,
                fd,
                env=agent_environment(config, self.terminal),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                limit=1048576,
            )
        session, started, text, counter = None, False, bytearray(), 0

        async def send(message):
            process.stdin.write((json.dumps(message) + "\n").encode())
            await process.stdin.drain()

        async def request(method, params):
            nonlocal counter, started
            counter += 1
            identifier = counter
            await send({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params})
            while line := await process.stdout.readline():
                value = json.loads(line)
                if value.get("method") == "session/update":
                    params = value.get("params", {})
                    if not session or params.get("sessionId") != session:
                        raise UncertainExecution("agent_identity", "Unexpected Grok session update")
                    update = params.get("update", {})
                    kind = update.get("sessionUpdate")
                    if kind in {"agent_message_chunk", "tool_call", "agent_thought_chunk"}:
                        if not started:
                            started = True
                            await running(
                                {"agent": args.agent, "session_id": session, "event": kind}
                            )
                        content = update.get("content", {})
                        if kind == "agent_message_chunk" and content.get("type") == "text":
                            text.extend(
                                content.get("text", "").encode()[: max(0, 65536 - len(text))]
                            )
                elif "method" in value and "id" in value:
                    if value["method"] == "session/request_permission":
                        permission = value.get("params", {})
                        bound_permission = (
                            bool(session)
                            and permission.get("sessionId") == session
                            and permission.get("toolCall", {}).get("kind")
                            in {"read", "edit", "delete", "move", "search", "execute"}
                        )
                        selected = next(
                            (
                                option.get("optionId")
                                for option in value.get("params", {}).get("options", [])
                                if isinstance(option, dict)
                                and option.get("kind") == "allow_once"
                                and isinstance(option.get("optionId"), str)
                            ),
                            None,
                        )
                        await send(
                            {
                                "jsonrpc": "2.0",
                                "id": value["id"],
                                "result": {
                                    "outcome": {"outcome": "selected", "optionId": selected}
                                    if local_tools and bound_permission and selected
                                    else {"outcome": "cancelled"}
                                },
                            }
                        )
                    else:
                        await send(
                            {
                                "jsonrpc": "2.0",
                                "id": value["id"],
                                "error": {"code": -32601, "message": "Capability not available"},
                            }
                        )
                elif value.get("id") == identifier:
                    if "error" in value:
                        raise UncertainExecution("agent_rpc", "Grok ACP returned an error")
                    return value.get("result", {})
            raise UncertainExecution("agent_disconnected", "Grok ACP disconnected")

        try:
            async with asyncio.timeout(args.timeout):
                await progress(
                    {"agent": args.agent, "pid": process.pid, "event": "process_spawned"}
                )
                init = await request("initialize", {"protocolVersion": 1, "clientCapabilities": {}})
                if init.get("protocolVersion") != 1:
                    raise BridgeError("agent_protocol", "Unsupported ACP version")
                methods = {item["id"] for item in init.get("authMethods", [])}
                method = "xai.api_key" if os.environ.get(config.api_key_env) else "cached_token"
                if method not in methods:
                    raise BridgeError("agent_auth", "No supported Grok authentication available")
                await request("authenticate", {"methodId": method, "_meta": {"headless": True}})
                servers = []
                if bridge_enabled:
                    from kirabridge.agent_manager.full_access import bridge_server

                    spec = bridge_server(self.bridge_config._source_path, args.agent)
                    servers = [{"name": "kirabridge", **spec, "env": []}]
                new = await request("session/new", {"cwd": args.cwd, "mcpServers": servers})
                session = new.get("sessionId")
                if not isinstance(session, str) or not session:
                    raise BridgeError("agent_protocol", "No Grok session identity")
                await progress(
                    {"agent": args.agent, "session_id": session, "event": "session_created"}
                )
                result = await request(
                    "session/prompt",
                    {"sessionId": session, "prompt": [{"type": "text", "text": args.prompt}]},
                )
                stop = result.get("stopReason")
                if not stop:
                    raise UncertainExecution("agent_unconfirmed", "Grok returned no stop reason")
                if not started:
                    await running(
                        {
                            "agent": args.agent,
                            "session_id": session,
                            "event": "prompt_response_observed",
                        }
                    )
                return {
                    "success": stop == "end_turn",
                    "text": text.decode("utf-8", "replace"),
                    "evidence": {
                        "agent": args.agent,
                        "adapter": "grok_acp",
                        "session_id": session,
                        "stop_reason": stop,
                        "local_tools": local_tools,
                        "mcp_servers_enabled": bridge_enabled,
                    },
                    "scope": "agent_turn",
                    "project_completion_verified": False,
                }
        except (TimeoutError, ValueError, OSError) as exc:
            raise UncertainExecution(
                "agent_interrupted", "Grok execution cannot be confirmed"
            ) from exc
        finally:
            await reap_process(process)


class AgentManager:
    def __init__(self, config: Config, terminal: TerminalManager):
        self.config = config
        self.adapters: dict[str, AgentAdapter] = {
            "codex": CodexAdapter(terminal, config),
            "grok_api": GrokAPIAdapter(),
            "grok_acp": GrokACPAdapter(terminal, config),
            "opencode": OpenCodeAdapter(terminal),
            "gemini_cli": GeminiAdapter(terminal),
            "claude_code": ClaudeCodeAdapter(terminal),
            "copilot_cli": CopilotCLIAdapter(terminal),
        }

    def register(self, kind: str, adapter: AgentAdapter) -> None:
        if kind in self.adapters or adapter.interface_version != "1":
            raise BridgeError(
                "adapter_version", "Duplicate adapter or unsupported interface version"
            )
        self.adapters[kind] = adapter

    def inventory(self, allowed: list[str]) -> dict:
        return {
            "agents": [
                {
                    "id": name,
                    "kind": config.kind,
                    **(
                        {
                            "sandbox_mode": config.sandbox_mode,
                            "project_rules_enabled": True,
                            "mcp_servers_enabled": config.bridge_tools,
                        }
                        if config.kind == "codex"
                        else {}
                    ),
                    "executable_present": bool(
                        config.executable and Path(config.executable).is_file()
                    ),
                    **(
                        {
                            "execution_mode": "native_full_access"
                            if config.bridge_tools
                            else "isolated_text_only",
                            "supports_local_tools": config.allow_local_tools
                            and config.bridge_tools,
                            "supports_owned_resume": False,
                            "authentication_status": "unknown",
                        }
                        if config.kind in {"opencode", "gemini_cli", "claude_code", "copilot_cli"}
                        else {}
                    ),
                    "daemon_status": "unknown",
                    "session_status": "unknown",
                    "task_status": "unknown",
                }
                for name, config in self.config.agents.items()
                if name in allowed
            ]
        }

    async def execute(
        self,
        task,
        args,
        principal,
        running,
        progress,
        *,
        owned_resume_session=None,
        handoff_reply=False,
    ):
        if args.agent not in principal.agents:
            raise BridgeError("agent_denied", "Agent identity not granted")
        config = self.config.agents.get(args.agent)
        if config is None or config.kind not in self.adapters:
            raise BridgeError("agent_unavailable", "Agent adapter is not configured")
        if self.config.visible_handoffs.enabled:
            if owned_resume_session is not None or handoff_reply:
                raise BridgeError(
                    "visible_owned_resume_unsupported",
                    "A provider-owned managed resume cannot replace the assigned visible "
                    "CLI session",
                )
            if getattr(self, "visible_handoffs", None) is None:
                raise BridgeError(
                    "visible_route_unavailable", "Visible handoff service is required"
                )
            return await self.visible_handoffs.execute(task, args, running, progress)
        full_access = (
            principal.permission_level is not None
            and config.bridge_tools
            and config.allow_local_tools
            and "agent.local_tools" in principal.capabilities
        )
        if full_access and config.kind == "grok_acp":
            args = args.model_copy(update={"local_tools": True})
        if args.local_tools and (
            (config.kind != "grok_acp" and not full_access)
            or not config.allow_local_tools
            or "agent.local_tools" not in principal.capabilities
        ):
            raise BridgeError(
                "agent_tools_denied",
                "Local agent tools require explicit operator and principal permission",
            )
        if (owned_resume_session is not None or handoff_reply) and config.kind != "codex":
            raise BridgeError(
                "agent_resume_unsupported", "Owned workflow continuation requires Codex"
            )
        extra = (
            {"owned_resume_session": owned_resume_session, "handoff_reply": handoff_reply}
            if owned_resume_session is not None or handoff_reply
            else {}
        )
        try:
            async with asyncio.timeout(args.timeout):
                if full_access and config.kind in {
                    "opencode",
                    "gemini_cli",
                    "claude_code",
                    "copilot_cli",
                }:
                    from kirabridge.agent_manager.full_access import FullAccessAdapter

                    return await FullAccessAdapter(
                        self.adapters[config.kind].terminal,
                        self.config._source_path,
                        principal.permission_level,
                    ).execute(task, args, config, principal.roots, running, progress)
                return await self.adapters[config.kind].execute(
                    task,
                    args,
                    config,
                    principal.roots,
                    running,
                    progress,
                    **extra,
                )
        except TimeoutError:
            raise UncertainExecution(
                "agent_timeout", "Agent completion could not be confirmed"
            ) from None
