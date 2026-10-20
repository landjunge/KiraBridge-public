"""Claude Code's native JSONL print protocol, with all local tools disabled."""

from __future__ import annotations

import json
from tempfile import TemporaryDirectory

from kirabridge.agent_manager.cli_support import BoundedText, bind_session, cli_environment
from kirabridge.bridge_core.models import BridgeError, TerminalInput, UncertainExecution
from kirabridge.filesystem_manager import PathScope


class ClaudeCodeAdapter:
    interface_version = "1"

    def __init__(self, terminal):
        self.terminal = terminal

    async def execute(self, task, args, config, roots, running, progress) -> dict:
        if not config.executable:
            raise BridgeError("agent_config", "Claude Code executable must be explicit")
        if args.local_tools:
            raise BridgeError("agent_tools_unsupported", "Claude Code currently supports text only")
        with PathScope(roots).directory(args.cwd):
            pass

        session = None
        started = False
        terminal_result = None
        output = BoundedText()

        async def mark_running(event):
            nonlocal started
            if not started:
                started = True
                await running({"agent": args.agent, "session_id": session, "event": event})

        async def event(line):
            nonlocal session, terminal_result
            try:
                value = json.loads(line)
            except ValueError:
                return
            if not isinstance(value, dict):
                return
            kind = value.get("type")
            if value.get("session_id") is not None:
                session = bind_session(session, value["session_id"])
            if kind == "system" and value.get("subtype") == "init":
                if any(value.get(key) for key in ("tools", "mcp_servers", "plugins")):
                    raise UncertainExecution(
                        "agent_tools_unexpected", "Claude Code reported disabled capabilities"
                    )
                if session:
                    await progress({"agent": args.agent, "session_id": session, "event": "init"})
            elif kind == "assistant" and session:
                if (
                    value.get("error")
                    or value.get("isApiErrorMessage")
                    or value.get("is_api_error_message")
                ):
                    return
                message = value.get("message")
                if not isinstance(message, dict):
                    return
                content = message.get("content", [])
                if not isinstance(content, list):
                    return
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") in {"tool_use", "server_tool_use"}:
                        raise UncertainExecution(
                            "agent_tools_unexpected", "Claude Code requested a disabled tool"
                        )
                await mark_running("assistant_message")
            elif kind == "result" and session:
                if terminal_result is not None:
                    raise UncertainExecution("agent_protocol", "Duplicate Claude Code result")
                subtype = value.get("subtype")
                if subtype not in {
                    "success",
                    "error_during_execution",
                    "error_max_turns",
                    "error_max_budget_usd",
                    "error_max_structured_output_retries",
                }:
                    raise UncertainExecution("agent_protocol", "Unknown Claude Code result subtype")
                success = subtype == "success" and value.get("is_error") is False
                terminal_result = {"subtype": subtype, "success": success}
                if success:
                    text = value.get("result")
                    if not isinstance(text, str):
                        raise UncertainExecution("agent_protocol", "Claude Code result has no text")
                    await mark_running("native_result_observed")
                    output.append(text)

        command = [
            config.executable,
            "--print",
            "--output-format",
            "stream-json",
            "--verbose",
            "--safe-mode",
            "--setting-sources",
            "",
            "--settings",
            '{"disableAllHooks":true}',
            "--tools",
            "",
            "--permission-mode",
            "dontAsk",
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--disable-slash-commands",
            "--no-chrome",
            "--no-session-persistence",
        ]
        if config.model:
            command += ["--model", config.model]

        async def spawned(evidence):
            await progress({"agent": args.agent, **evidence})

        # Native @file and leading /command preprocessing must not inspect files
        # before the tool policy applies. The model receives reconstructible text.
        prompt = "KiraBridge text-only request, decode this JSON string as the user text:\n"
        prompt += json.dumps(args.prompt, ensure_ascii=True).replace("@", "\\u0040")
        # A private empty cwd also excludes repository context before tool policy
        # evaluation. Safe mode still preserves the CLI's own cached authentication.
        with TemporaryDirectory(prefix="kirabridge-claude-") as workspace:
            result = await self.terminal.execute(
                task["id"],
                task["principal"],
                TerminalInput(argv=command, cwd=workspace, timeout=args.timeout),
                [workspace],
                [config.executable],
                spawned,
                env=cli_environment(config, self.terminal),
                stdin=prompt.encode("utf-8"),
                line_callback=event,
            )
        if result["timed_out"] or result.get("terminated"):
            raise UncertainExecution(
                "agent_timeout", "Claude Code was interrupted; outcome is unknown"
            )
        if terminal_result is None:
            raise UncertainExecution("agent_unconfirmed", "No native Claude Code result received")
        success = terminal_result["success"] and result["exit_code"] == 0
        return {
            "success": success,
            "text": output.text if success else "",
            "final_message": output.text if success else "",
            "evidence": {
                "agent": args.agent,
                "adapter": "claude_code",
                "session_id": session,
                "result_subtype": terminal_result["subtype"],
                "native_result_received": True,
                "exit_code": result["exit_code"],
                "timed_out": False,
                "local_tools_enabled": False,
                "mcp_servers_enabled": False,
                "customizations_enabled": False,
                "workspace_isolated": True,
                "session_persisted": False,
                "output_truncated": output.truncated,
            },
            "scope": "model_turn",
            "project_completion_verified": False,
        }
