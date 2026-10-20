from __future__ import annotations

import json
import os
import stat
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

from kirabridge.agent_manager.cli_support import BoundedText, bind_session, cli_environment
from kirabridge.bridge_core.models import BridgeError, TerminalInput, UncertainExecution
from kirabridge.filesystem_manager import PathScope
from kirabridge.terminal_manager import TerminalManager


def _copy_auth_file(source: Path, target: Path) -> bool:
    """Copy only named native authentication caches, never user configuration."""
    try:
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    except OSError:
        raise BridgeError(
            "agent_auth", "Gemini authentication cache cannot be opened safely"
        ) from None
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > 1048576
            or (os.name == "posix" and metadata.st_uid != os.getuid())
        ):
            raise BridgeError(
                "agent_auth", "Gemini authentication cache is not an owned bounded file"
            )
        with os.fdopen(fd, "rb", closefd=False) as source_file:
            data = source_file.read(1048577)
        if len(data) > 1048576:
            raise BridgeError("agent_auth", "Gemini authentication cache exceeds byte limit")
    finally:
        os.close(fd)
    # A private temporary parent also protects legacy source caches with broad modes.
    target.write_bytes(data)
    target.chmod(0o600)
    return True


@contextmanager
def isolated_gemini_environment(config, terminal):
    """Fresh native HOME/settings prevent hooks, .env and workspace injection.

    The caller must validate the requested workspace before entering this helper.
    Only this internally generated directory is added to the execution roots.
    """
    env = cli_environment(config, terminal)
    source_home = Path(env["HOME"])
    # Canonicalize macOS /var -> /private/var for descriptor-based PathScope.
    with tempfile.TemporaryDirectory(prefix="kirabridge-gemini-") as temporary:
        base = Path(temporary).resolve()
        home = base / "home"
        workspace = base / "workspace"
        native = home / ".gemini"
        native.mkdir(parents=True, mode=0o700)
        workspace.mkdir(mode=0o700)
        # Stop Gemini's automatic upward .env search at an empty, owned file.
        (workspace / ".env").write_text("")
        key = env.get(config.api_key_env)
        if key:
            # The operator selects this one key. No other provider keys are read.
            env["GEMINI_API_KEY"] = key
            auth_type = "gemini-api-key"
        else:
            cached = _copy_auth_file(
                source_home / ".gemini/oauth_creds.json", native / "oauth_creds.json"
            )
            if not cached:
                raise BridgeError(
                    "agent_auth_required",
                    "Gemini needs an existing Google login or its explicitly configured API key",
                )
            _copy_auth_file(
                source_home / ".gemini/google_accounts.json", native / "google_accounts.json"
            )
            auth_type = "oauth-personal"
        # An empty MCP allowlist means "allow all" in Gemini 0.37.2. Use a
        # nonempty singleton and exclude that same name: every possible server
        # is rejected, including servers injected by remote enterprise settings.
        no_mcp_server = f"kirabridge-no-mcp-{uuid.uuid4().hex}"
        settings = {
            "general": {
                "enableAutoUpdate": False,
                "enableAutoUpdateNotification": False,
                "enableNotifications": False,
                "defaultApprovalMode": "default",
                "maxAttempts": 1,
                "retryFetchErrors": False,
            },
            "tools": {"core": [], "allowed": [], "sandbox": False},
            "hooksConfig": {"enabled": False},
            "hooks": {},
            "mcpServers": {},
            "mcp": {"allowed": [no_mcp_server], "excluded": [no_mcp_server]},
            "skills": {"enabled": False},
            "ide": {"enabled": False},
            "experimental": {"enableAgents": False, "jitContext": False},
            "context": {
                "fileName": f".kirabridge-no-context-{uuid.uuid4().hex}.md",
                "includeDirectoryTree": False,
                "includeDirectories": [],
                "discoveryMaxDirs": 0,
                "memoryBoundaryMarkers": [],
            },
            "model": {"maxSessionTurns": 1},
            "billing": {"overageStrategy": "never"},
            "privacy": {"usageStatisticsEnabled": False},
            "telemetry": {"enabled": False},
            "security": {
                "disableYoloMode": True,
                "disableAlwaysAllow": True,
                "auth": {"selectedType": auth_type},
            },
        }
        system_settings = base / "settings.json"
        system_settings.write_text(json.dumps(settings), encoding="utf-8")
        system_settings.chmod(0o600)
        defaults = base / "system-defaults.json"
        defaults.write_text("{}", encoding="utf-8")
        policy = base / "deny-tools.toml"
        policy.write_text('[[rule]]\ntoolName = "*"\ndecision = "deny"\npriority = 999\n')
        env.update(
            {
                "HOME": str(home),
                "GEMINI_CLI_HOME": str(home),
                "GEMINI_CLI_SYSTEM_SETTINGS_PATH": str(system_settings),
                "GEMINI_CLI_SYSTEM_DEFAULTS_PATH": str(defaults),
                "GEMINI_CLI_TRUSTED_FOLDERS_PATH": str(base / "trusted-folders.json"),
                "NO_BROWSER": "true",
                "CI": "true",
            }
        )
        yield env, workspace, policy, auth_type


class GeminiAdapter:
    """Native Gemini JSONL text-only turns; KiraBridge never resubmits a turn."""

    interface_version = "1"

    def __init__(self, terminal: TerminalManager):
        self.terminal = terminal

    async def execute(self, task, args, config, roots, running, progress) -> dict:
        if not config.executable:
            raise BridgeError("agent_config", "Gemini executable must be configured explicitly")
        if args.local_tools:
            raise BridgeError(
                "agent_tools_unsupported", "Gemini currently supports isolated text-only tasks"
            )
        # Validate the caller's directory even though text-only Gemini never enters it.
        with PathScope(roots).directory(args.cwd):
            pass
        session, started, outcome, fatal = None, False, None, False
        messages = BoundedText()
        warnings = 0

        async def actual_start(event):
            nonlocal started
            if not started:
                started = True
                await running({"agent": args.agent, "session_id": session, "event": event})

        async def event(line: str):
            nonlocal session, outcome, fatal, warnings
            try:
                value = json.loads(line)
            except ValueError:
                return
            if not isinstance(value, dict):
                raise UncertainExecution("agent_protocol", "Gemini event must be a JSON object")
            kind = value.get("type")
            if kind == "init":
                if outcome is not None:
                    raise UncertainExecution(
                        "agent_protocol", "Gemini emitted metadata after result"
                    )
                session = bind_session(session, value.get("session_id"))
                await progress({"agent": args.agent, "session_id": session, "event": "init"})
            elif kind in {"tool_use", "tool_result"}:
                # Fail closed even if a future CLI disregards the native deny policy.
                # The process is reaped by TerminalManager before propagating this.
                raise UncertainExecution(
                    "agent_tool_denied", "Gemini emitted a tool event during a text-only task"
                )
            elif kind == "message" and value.get("role") == "assistant":
                if not session or outcome is not None:
                    raise UncertainExecution(
                        "agent_protocol", "Gemini response is outside its turn"
                    )
                text = value.get("content")
                if not isinstance(text, str):
                    raise UncertainExecution("agent_protocol", "Gemini message content is invalid")
                if text:
                    await actual_start("assistant_message")
                    messages.append(text)
            elif kind == "error":
                # Provider error messages can contain prompts, keys or file contents.
                # Persist only a bounded category; never the native message/parameters.
                if value.get("severity") == "warning":
                    warnings = min(warnings + 1, 1000)
                else:
                    fatal = True
            elif kind == "result":
                if outcome is not None or value.get("status") not in {"success", "error"}:
                    raise UncertainExecution(
                        "agent_protocol", "Gemini result is invalid or repeated"
                    )
                outcome = value["status"]
                if outcome == "success":
                    if not session:
                        raise UncertainExecution(
                            "agent_unconfirmed", "Gemini result has no session"
                        )
                    await actual_start("native_result_observed")

        async def spawned(evidence):
            await progress({"agent": args.agent, **evidence})

        with isolated_gemini_environment(config, self.terminal) as (
            env,
            workspace,
            policy,
            auth_type,
        ):
            command = [
                config.executable,
                "--output-format",
                "stream-json",
                "--approval-mode",
                "default",
                "--extensions",
                "none",
                "--admin-policy",
                str(policy),
                "--prompt",
                "Process the text-only request supplied on stdin.",
            ]
            if config.model:
                command += ["--model", config.model]
            # The prefix prevents slash-command execution; escaping every @ prevents
            # Gemini's pre-policy local-file/resource expansion. Never send prompt in argv.
            prompt = "KiraBridge literal text-only request:\n\n" + args.prompt.replace("@", "\\@")
            result = await self.terminal.execute(
                task["id"],
                task["principal"],
                TerminalInput(
                    argv=command, cwd=str(workspace), timeout=args.timeout, max_output=65536
                ),
                [str(workspace)],
                [config.executable],
                spawned,
                env=env,
                stdin=prompt.encode("utf-8"),
                line_callback=event,
            )
        if result["timed_out"] or result.get("terminated"):
            raise UncertainExecution(
                "agent_unconfirmed", "Gemini process ended before confirmed exit"
            )
        if outcome is None:
            # Native 0.37.2 emits these diagnostics from its authentication
            # startup path before entering runNonInteractive (and its init).
            # Do not classify by exit code alone or retain provider text/URLs.
            auth_lines = [
                line
                for line in result["stderr"].splitlines()
                if line.startswith("Error authenticating: ")
            ]
            if session is None and not started and result["exit_code"] != 0 and auth_lines:
                unsupported = any(
                    line.startswith("Error authenticating: IneligibleTierError: ")
                    and "This client is no longer supported for Gemini Code Assist for individuals"
                    in line
                    for line in auth_lines
                )
                code = "agent_auth_unsupported_client" if unsupported else "agent_auth_failed"
                await progress(
                    {
                        "agent": args.agent,
                        "event": "native_auth_rejected_before_session",
                        "failure_code": code,
                        "exit_code": result["exit_code"],
                    }
                )
                raise BridgeError(
                    code,
                    "Google no longer serves this individual-account Gemini CLI login"
                    if unsupported
                    else "Gemini authentication failed before a native session",
                )
            await progress(
                {
                    "agent": args.agent,
                    "event": "native_process_exited_without_result",
                    "exit_code": result["exit_code"],
                    "session_observed": session is not None,
                }
            )
            raise UncertainExecution("agent_unconfirmed", "No native Gemini result event observed")
        return {
            "success": outcome == "success" and not fatal and result["exit_code"] == 0,
            "text": messages.text,
            "final_message": messages.text,
            "evidence": {
                "agent": args.agent,
                "adapter": "gemini_cli",
                "session_id": session,
                "exit_code": result["exit_code"],
                "native_result": outcome,
                "fatal_error_observed": fatal,
                "warning_count": warnings,
                "output_truncated": messages.truncated,
                "configured_model_attempts": 1,
                "retry_fetch_errors": False,
                "timed_out": result["timed_out"],
                "local_tools_enabled": False,
                "execution_mode": "text-only",
                "text_only": True,
                "isolated_cwd": True,
                "workspace_config_enabled": False,
                "mcp_servers_enabled": False,
                "hooks_enabled": False,
                "extensions_enabled": False,
                "auth_method": auth_type,
                "os_sandbox_enforced": False,
            },
            "scope": "agent_turn",
            "project_completion_verified": False,
        }
