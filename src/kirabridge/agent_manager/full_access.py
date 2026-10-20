"""Native CLI access for the explicitly selected full permission level."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from kirabridge.agent_manager.cli_support import BoundedText, bind_session, cli_environment
from kirabridge.bridge_core.models import BridgeError, TerminalInput, UncertainExecution


def bridge_server(source_path, identity):
    if not source_path:
        raise BridgeError(
            "bridge_config", "Die Agentenverbindung benötigt die geladene Konfiguration"
        )
    return {
        "command": sys.executable,
        "args": [
            "-m",
            "kirabridge.cli",
            "--config",
            source_path,
            "--principal",
            identity,
            "connect",
        ],
    }


def opencode_settings(profile, server, *, full):
    settings = {
        "mcp": {
            "kirabridge": {
                "type": "local",
                "command": [server["command"], *server["args"]],
                "enabled": True,
            }
        }
    }
    if full:
        settings["permission"] = "allow"
    if profile.model:
        settings["model"] = profile.model
    if profile.base_url and profile.model:
        provider, model = profile.model.split("/", 1)
        settings["provider"] = {
            provider: {
                "npm": "@ai-sdk/openai-compatible",
                "options": {"baseURL": profile.base_url},
                "models": {
                    model: {
                        "name": model,
                        "tool_call": True,
                        "limit": {"context": 32768, "output": 4096},
                    }
                },
            }
        }
    return settings


class FullAccessAdapter:
    def __init__(self, terminal, source_path, permission_level="full"):
        self.terminal, self.source_path = terminal, source_path
        self.permission_level = permission_level

    async def execute(self, task, args, config, roots, running, progress):
        if not config.executable:
            raise BridgeError("agent_config", "Das Agentenprogramm fehlt")
        server = bridge_server(self.source_path, args.agent)
        text, session, complete, failed, started = BoundedText(), None, False, False, False
        native_result = None

        async def mark(kind):
            nonlocal started
            if not started:
                started = True
                await running({"agent": args.agent, "session_id": session, "event": kind})

        async def event(line):
            nonlocal session, complete, failed, native_result
            try:
                value = json.loads(line)
            except ValueError:
                return
            if not isinstance(value, dict):
                return
            kind = value.get("type", "")
            data, part = value.get("data") or {}, value.get("part") or {}
            identifier = value.get("session_id") or value.get("sessionID")
            if config.kind == "gemini_cli" and kind == "init":
                identifier = value.get("session_id")
            if config.kind == "copilot_cli" and kind == "session.start":
                identifier = data.get("sessionId") or data.get("session_id")
            if identifier:
                session = bind_session(session, identifier)
            if kind in {"error", "session.error", "abort"}:
                failed = True
                await progress({"agent": args.agent, "event": "provider_error", "error": value})
            if config.kind == "claude_code":
                if kind == "result":
                    native_result = value
                    complete = value.get("subtype") == "success" and value.get("is_error") is False
                    failed = failed or not complete
                    if isinstance(value.get("result"), str):
                        text.append(value["result"])
                    await mark(kind)
            elif config.kind == "gemini_cli":
                if kind == "message" and value.get("role") == "assistant":
                    text.append(value.get("content", ""))
                    await mark(kind)
                if kind == "result":
                    native_result = value
                    complete = value.get("status") == "success"
                    failed = failed or not complete
            elif config.kind == "opencode":
                if kind == "text" and part.get("type") == "text":
                    text.append(part.get("text", ""))
                    await mark(kind)
                if kind == "step_finish" and part.get("reason") == "stop":
                    native_result, complete = value, True
            elif config.kind == "copilot_cli":
                if kind == "assistant.message":
                    content = data.get("content")
                    if isinstance(content, str):
                        text.append(content)
                        await mark(kind)
                if kind == "result":
                    native_result = value
                    complete = value.get("exitCode", data.get("exitCode")) == 0
                    if isinstance(value.get("result"), str) and not text.text:
                        text.append(value["result"])
                    failed = failed or not complete

        with TemporaryDirectory(prefix="kirabridge-full-") as temporary:
            env = cli_environment(config, self.terminal)
            command = [config.executable]
            stdin = None
            if config.kind == "claude_code":
                command += [
                    "--print",
                    "--output-format",
                    "stream-json",
                    "--verbose",
                    "--permission-mode",
                    "bypassPermissions",
                    "--mcp-config",
                    json.dumps({"mcpServers": {"kirabridge": server}}),
                ]
                stdin = args.prompt.encode()
            elif config.kind == "gemini_cli":
                settings = Path(temporary) / "settings.json"
                settings.write_text(json.dumps({"mcpServers": {"kirabridge": server}}))
                settings.chmod(0o600)
                env["GEMINI_CLI_SYSTEM_SETTINGS_PATH"] = str(settings)
                command += [
                    "--output-format",
                    "stream-json",
                    "--approval-mode",
                    "yolo",
                    "--prompt",
                    args.prompt,
                ]
            elif config.kind == "opencode":
                native = opencode_settings(config, server, full=True)
                env["OPENCODE_CONFIG_CONTENT"] = json.dumps(native)
                if config.base_url and config.model:
                    env.pop(config.api_key_env, None)
                env["OPENCODE_PERMISSION"] = '{"*":"allow"}'
                command += ["run", "--format", "json"]
                stdin = args.prompt.encode()
            elif config.kind == "copilot_cli":
                command += [
                    "--prompt",
                    args.prompt,
                    "--output-format",
                    "json",
                    "--allow-all",
                    "--additional-mcp-config",
                    json.dumps({"mcpServers": {"kirabridge": server}}),
                    "--no-ask-user",
                ]
            else:
                raise BridgeError("agent_config", "Unbekannter nativer Adapter")
            if config.model:
                command += ["--model", config.model]

            async def spawned(evidence):
                await progress({"agent": args.agent, **evidence})

            result = await self.terminal.execute(
                task["id"],
                task["principal"],
                TerminalInput(argv=command, cwd=args.cwd, timeout=args.timeout),
                roots,
                [config.executable],
                spawned,
                env=env,
                stdin=stdin,
                line_callback=event,
            )
        if result["timed_out"] or result.get("terminated") or native_result is None:
            raise UncertainExecution(
                "agent_unconfirmed", "Der Agentenabschluss ist nicht bestätigt"
            )
        if not started:
            await mark("native_result_observed")
        return {
            "success": complete and not failed and result["exit_code"] == 0,
            "text": text.text,
            "scope": "agent_turn",
            "project_completion_verified": False,
            "evidence": {
                "agent": args.agent,
                "adapter": config.kind,
                "session_id": session,
                "pid": result["pid"],
                "exit_code": result["exit_code"],
                "native_completion": complete,
                "local_tools_enabled": True,
                "mcp_servers_enabled": True,
                "permission_level": self.permission_level,
            },
        }
