"""OpenCode V1 JSONL adapter with an isolated, text-only execution profile."""

from __future__ import annotations

import getpass
import json
import re
import sys
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from kirabridge.agent_manager.cli_support import BoundedText, bind_session, cli_environment
from kirabridge.bridge_core.models import BridgeError, TerminalInput, UncertainExecution
from kirabridge.filesystem_manager import PathScope


def _managed_configuration_present() -> bool:
    """Managed settings override injected config; do not circumvent that policy."""
    if sys.platform == "darwin":
        directory = Path("/Library/Application Support/opencode")
        preferences = Path("/Library/Managed Preferences")
        if any(
            path.is_file()
            for path in (
                preferences / "ai.opencode.managed.plist",
                preferences / getpass.getuser() / "ai.opencode.managed.plist",
            )
        ):
            return True
    elif sys.platform == "win32":
        # Use the same built-in default as OpenCode; no caller-selected config path.
        directory = Path("C:/ProgramData/opencode")
    else:
        directory = Path("/etc/opencode")
    return any((directory / name).is_file() for name in ("opencode.json", "opencode.jsonc"))


@contextmanager
def _isolated_environment(config, terminal):
    env = cli_environment(config, terminal)
    with TemporaryDirectory(prefix="kirabridge-opencode-") as temporary:
        base = Path(temporary).resolve()
        for kind in ("CONFIG", "DATA", "CACHE", "STATE"):
            directory = base / kind.lower()
            directory.mkdir(mode=0o700)
            env[f"XDG_{kind}_HOME"] = str(directory)
        # V1 otherwise starts a background npm install in each new config directory.
        # Its own writable-access check skips this empty, read-only config directory.
        global_config = base / "config" / "opencode"
        global_config.mkdir(mode=0o500)
        workspace = base / "workspace"
        workspace.mkdir(mode=0o700)
        profile = {
            "permission": "deny",
            "default_agent": "kirabridge",
            "model": config.model,
            "small_model": config.model,
            "enabled_providers": [config.model.split("/", 1)[0]],
            "agent": {
                "kirabridge": {
                    "mode": "primary",
                    "description": "KiraBridge isolated text-only turn",
                    "permission": "deny",
                    # V1 inserts an assistant MAX_STEPS message at step >= limit.
                    # Two leaves the first text response free of that synthetic prefill.
                    "steps": 2,
                    "prompt": "Answer the supplied text directly and briefly. Do not use tools.",
                },
                "title": {"disable": True},
                "summary": {"disable": True},
            },
            "mcp": {},
            "plugin": [],
            "instructions": [],
            "skills": {"paths": [], "urls": []},
            "snapshot": False,
            "share": "disabled",
            "autoupdate": False,
            "formatter": False,
            "lsp": False,
        }
        base_url = getattr(config, "base_url", None)
        if base_url:
            # The local inference profile is unauthenticated; never hand it a cloud key.
            env.pop(config.api_key_env, None)
            provider_id, model_id = config.model.split("/", 1)
            profile["provider"] = {
                provider_id: {
                    "npm": "@ai-sdk/openai-compatible",
                    "name": "KiraBridge local inference",
                    "options": {"baseURL": base_url},
                    "models": {
                        model_id: {
                            "name": model_id,
                            "limit": {"context": 4096, "output": config.local_output_tokens or 128},
                            "tool_call": False,
                        }
                    },
                }
            }
        elif env.get(config.api_key_env):
            profile["provider"] = {
                config.model.split("/", 1)[0]: {
                    "options": {"apiKey": "{env:" + config.api_key_env + "}"}
                }
            }
        env.update(
            OPENCODE_CONFIG_CONTENT=json.dumps(profile, separators=(",", ":")),
            OPENCODE_PERMISSION='{"*":"deny"}',
            OPENCODE_PURE="1",
            OPENCODE_DISABLE_PROJECT_CONFIG="1",
            OPENCODE_DISABLE_CLAUDE_CODE="1",
            OPENCODE_DISABLE_EXTERNAL_SKILLS="1",
            OPENCODE_DISABLE_AUTOUPDATE="1",
            OPENCODE_DISABLE_MODELS_FETCH="1",
            OPENCODE_DISABLE_LSP_DOWNLOAD="1",
            OPENCODE_DISABLE_AUTOCOMPACT="1",
        )
        try:
            yield env, str(workspace), str(base)
        finally:
            global_config.chmod(0o700)


class OpenCodeAdapter:
    """A fresh native session per task; no existing interactive session is adopted."""

    interface_version = "1"

    def __init__(self, terminal):
        self.terminal = terminal

    async def execute(self, task, args, config, roots, running, progress) -> dict:
        if not config.executable:
            raise BridgeError("agent_config", "OpenCode executable must be configured explicitly")
        if not config.model or not re.fullmatch(
            r"[a-z0-9][a-z0-9_-]{0,100}/[A-Za-z0-9][A-Za-z0-9._:/-]{0,240}", config.model
        ):
            raise BridgeError("agent_config", "OpenCode requires an explicit provider/model")
        if config.allow_local_tools and args.local_tools:
            raise BridgeError(
                "agent_capability", "OpenCode local tools require a separately verified sandbox"
            )
        if _managed_configuration_present():
            raise BridgeError(
                "agent_config",
                "Managed OpenCode configuration requires a separately verified profile",
            )

        session, started, completed, failed, finish_reason = None, False, False, False, None
        text = BoundedText()

        async def event(line: str):
            nonlocal session, started, completed, failed, finish_reason
            try:
                value = json.loads(line)
            except ValueError:
                return
            if not isinstance(value, dict):
                return
            kind = value.get("type")
            if not isinstance(kind, str) or kind not in {
                "step_start",
                "step_finish",
                "text",
                "reasoning",
                "tool_use",
                "error",
            }:
                return
            session_id = value.get("sessionID")
            session = bind_session(session, session_id)
            part = value.get("part", {})
            if not isinstance(part, dict):
                raise UncertainExecution("agent_protocol", "Invalid OpenCode event part")
            if "sessionID" in part:
                bind_session(session, part["sessionID"])
            await progress({"agent": args.agent, "session_id": session, "event": kind})
            if kind == "tool_use":
                raise UncertainExecution(
                    "agent_permission", "OpenCode reported a disabled tool use"
                )
            if kind == "error":
                failed = True
            elif kind == "step_start" and part.get("type") == "step-start":
                completed, finish_reason = False, None
                if not started:
                    started = True
                    await running({"agent": args.agent, "session_id": session, "event": kind})
            elif kind == "text" and part.get("type") == "text":
                if isinstance(part.get("text"), str):
                    text.append(part["text"])
                    if not started:
                        started = True
                        await running(
                            {"agent": args.agent, "session_id": session, "event": "model_text"}
                        )
            elif kind == "step_finish" and part.get("type") == "step-finish":
                finish_reason = part.get("reason") if isinstance(part.get("reason"), str) else None
                completed = started and finish_reason == "stop"
                if finish_reason in {"length", "content-filter", "error"}:
                    failed = True

        async def spawned(evidence):
            await progress({"agent": args.agent, **evidence})

        command = [
            config.executable,
            "run",
            "--pure",
            "--format",
            "json",
            "--agent",
            "kirabridge",
            "--model",
            config.model,
            "--title",
            "KiraBridge " + task["id"],
        ]
        with (
            PathScope(roots).directory(args.cwd),
            _isolated_environment(config, self.terminal) as (env, workspace, temporary_root),
        ):
            result = await self.terminal.execute(
                task["id"],
                task["principal"],
                TerminalInput(argv=command, cwd=workspace, timeout=args.timeout, max_output=65536),
                [*roots, temporary_root],
                [config.executable],
                spawned,
                env=env,
                stdin=args.prompt.encode("utf-8"),
                line_callback=event,
            )
        if result["timed_out"] or result.get("terminated"):
            raise UncertainExecution("agent_unconfirmed", "OpenCode turn was interrupted")
        if not completed and not failed:
            raise UncertainExecution(
                "agent_unconfirmed", "No OpenCode final turn completion evidence"
            )
        if completed and not failed and not text.text.strip():
            raise UncertainExecution(
                "agent_unconfirmed", "No OpenCode final response text observed"
            )
        # Raw stdout/stderr and provider error messages deliberately never become evidence.
        return {
            "success": completed and not failed and result["exit_code"] == 0,
            "text": text.text,
            "final_message": text.text,
            "evidence": {
                "agent": args.agent,
                "adapter": "opencode",
                "session_id": session,
                "exit_code": result["exit_code"],
                "turn_completed": completed,
                "turn_failed": failed,
                "output_truncated": text.truncated,
                "finish_reason": finish_reason
                if finish_reason in {"stop", "length", "content-filter", "tool-calls", "error"}
                else None,
                "local_tools_enabled": False,
                "mcp_servers_enabled": False,
                "external_plugins_enabled": False,
                "config_isolated": True,
                "execution_workspace": "private_temporary_directory",
                "requested_cwd_validated": True,
                "requested_workspace_access": False,
                "native_permissions": "deny",
                "timed_out": False,
            },
            "scope": "agent_turn",
            "project_completion_verified": False,
        }
