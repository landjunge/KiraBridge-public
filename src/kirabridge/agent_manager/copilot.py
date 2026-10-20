"""GitHub Copilot CLI JSONL with an isolated, tool-free one-shot session."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from kirabridge.agent_manager.cli_support import BoundedText, bind_session, cli_environment
from kirabridge.bridge_core.models import BridgeError, TerminalInput, UncertainExecution
from kirabridge.filesystem_manager import PathScope


class CopilotCLIAdapter:
    interface_version = "1"

    def __init__(self, terminal):
        self.terminal = terminal

    async def execute(self, task, args, config, roots, running, progress) -> dict:
        if not config.executable:
            raise BridgeError("agent_config", "Copilot CLI executable must be explicit")
        if args.local_tools:
            raise BridgeError("agent_tools_unsupported", "Copilot CLI currently supports text only")
        # Validate the requested authorized cwd before any private workspace is created.
        with PathScope(roots).directory(args.cwd):
            pass

        session = None
        started = False
        completed_turn = False
        terminal_result = None
        failed = False
        output = BoundedText()

        async def mark_running(event):
            nonlocal started
            if not started:
                started = True
                await running({"agent": args.agent, "session_id": session, "event": event})

        async def event(line):
            nonlocal session, completed_turn, terminal_result, failed
            try:
                value = json.loads(line)
            except ValueError:
                return
            if not isinstance(value, dict):
                return
            kind = value.get("type")
            data = value.get("data")
            data = data if isinstance(data, dict) else {}
            if kind in {"session.start", "session.resume"}:
                if kind == "session.resume":
                    raise UncertainExecution(
                        "agent_identity", "Copilot resumed an unexpected session"
                    )
                session = bind_session(session, data.get("sessionId"))
                await progress(
                    {"agent": args.agent, "session_id": session, "event": "session.start"}
                )
            elif kind == "result":
                session = bind_session(session, value.get("sessionId"))
                if terminal_result is not None:
                    raise UncertainExecution("agent_protocol", "Duplicate Copilot CLI result")
                exit_code = value.get("exitCode")
                if type(exit_code) is not int:
                    raise UncertainExecution("agent_protocol", "Copilot result has no exit code")
                terminal_result = exit_code
            elif kind in {"session.error", "abort"}:
                failed = True
            elif kind == "session.idle" and data.get("aborted"):
                failed = True
            elif kind in {"tool.execution_start", "subagent.started", "hook.start"}:
                raise UncertainExecution(
                    "agent_tools_unexpected", "Copilot CLI started a disabled capability"
                )
            elif session:
                if kind == "assistant.message_delta":
                    text = data.get("deltaContent")
                    if isinstance(text, str):
                        await mark_running("assistant_message_delta")
                elif kind == "assistant.message":
                    text = data.get("content")
                    if isinstance(text, str):
                        await mark_running("assistant_message")
                        output.append(text)
                    if data.get("toolRequests"):
                        raise UncertainExecution(
                            "agent_tools_unexpected", "Copilot CLI requested disabled tools"
                        )
                elif kind == "assistant.turn_end":
                    completed_turn = True

        with TemporaryDirectory(prefix="kirabridge-copilot-") as directory:
            isolated = Path(directory)
            cli_home = isolated / "config"
            workspace = isolated / "workspace"
            cli_home.mkdir(mode=0o700)
            workspace.mkdir(mode=0o700)
            # Global config alone does not disable repository hooks in CLI 1.0.67.
            # Enter a fresh empty workspace before discovery and never load user plugins/MCP.
            (cli_home / "config.json").write_text(
                json.dumps(
                    {
                        "disableAllHooks": True,
                        "memory": False,
                        "ide": {"autoConnect": False},
                        "customAgents": {"defaultLocalOnly": True},
                        "enabledPlugins": {},
                    }
                ),
                encoding="utf-8",
            )
            env = cli_environment(config, self.terminal)
            env["COPILOT_HOME"] = str(cli_home)
            env["COPILOT_AUTO_UPDATE"] = "false"
            # Keep native @file and /command preprocessing away from user text.
            prompt = "KiraBridge text-only request, decode this JSON string as the user text:\n"
            prompt += json.dumps(args.prompt, ensure_ascii=True).replace("@", "\\u0040")
            command = [
                config.executable,
                "-C",
                str(workspace),
                "--prompt",
                prompt,
                "--output-format",
                "json",
                # CLI 1.0.67 normalizes an empty list to undefined (= all tools).
                # A nonempty exact allowlist with no matching native tool is empty.
                "--available-tools=kirabridge_text_only_no_tools",
                "--deny-tool=*",
                "--disable-builtin-mcps",
                "--no-custom-instructions",
                "--no-ask-user",
                "--no-auto-update",
                "--no-remote-export",
                "--no-experimental",
                "--no-bash-env",
                "--log-level",
                "none",
            ]
            if config.model:
                command += ["--model", config.model]

            async def spawned(evidence):
                await progress({"agent": args.agent, **evidence})

            result = await self.terminal.execute(
                task["id"],
                task["principal"],
                TerminalInput(argv=command, cwd=str(workspace), timeout=args.timeout),
                [str(workspace)],
                [config.executable],
                spawned,
                env=env,
                line_callback=event,
            )
        if result["timed_out"] or result.get("terminated"):
            raise UncertainExecution(
                "agent_timeout", "Copilot CLI was interrupted; outcome is unknown"
            )
        if terminal_result is None:
            raise UncertainExecution("agent_unconfirmed", "No native Copilot CLI result received")
        success = terminal_result == 0 and result["exit_code"] == 0 and not failed
        if success and not (started and completed_turn):
            raise UncertainExecution(
                "agent_unconfirmed", "No completed Copilot model turn observed"
            )
        return {
            "success": success,
            "text": output.text if success else "",
            "final_message": output.text if success else "",
            "evidence": {
                "agent": args.agent,
                "adapter": "copilot_cli",
                "session_id": session,
                "native_result_received": True,
                "native_exit_code": terminal_result,
                "exit_code": result["exit_code"],
                "turn_completed": completed_turn,
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
