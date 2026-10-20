"""Explicit macOS Authorization Services path; no passwords or sudoers changes."""

from __future__ import annotations

import json
import shlex
import sys

from kirabridge.bridge_core.models import BridgeError, TerminalInput, UncertainExecution
from kirabridge.terminal_manager import check_executable


def authorization_script(argv: list[str], cwd: str) -> str:
    if not argv or any("\x00" in value for value in [cwd, *argv]):
        raise BridgeError("invalid_command", "Invalid administrator command")
    # All words are quoted as data, then the complete command as a JavaScript string.
    # The sole shell here is the documented, visible macOS privileged-command API.
    command = "cd " + shlex.quote(cwd) + " && exec " + shlex.join(argv)
    return (
        "const app = Application.currentApplication(); app.includeStandardAdditions = true; "
        "app.doShellScript(" + json.dumps(command) + ", {administratorPrivileges:true, "
        'withPrompt:"KiraBridge: angeforderter Administratorbefehl / requested admin command", '
        "alteringLineEndings:false});"
    )


async def execute_admin(bridge, task, args, policy, running):
    if sys.platform != "darwin":
        raise BridgeError("unsupported_platform", "Local administrator authorization needs macOS")
    executable = check_executable(
        args.argv[0],
        policy.executables,
        policy.allow_any_executable,
        bridge.terminal.environment["PATH"],
    )
    script = authorization_script([executable, *args.argv[1:]], args.cwd)
    result = await bridge.terminal.execute(
        task["id"],
        task["principal"],
        TerminalInput(
            argv=["/usr/bin/osascript", "-l", "JavaScript", "-e", script],
            cwd=args.cwd,
            timeout=args.timeout,
            max_output=args.max_output,
        ),
        policy.terminal_roots or policy.roots,
        ["/usr/bin/osascript"],
        running,
    )
    if result["timed_out"] or result.get("terminated"):
        raise UncertainExecution(
            "admin_timeout" if result["timed_out"] else "admin_interrupted",
            "Administrator command outcome is unknown; do not retry blindly",
        )
    return {
        **result,
        "success": result["exit_code"] == 0 and not result["timed_out"],
        "evidence": {
            "authorization": "macos_local_dialog",
            "password_stored": False,
            "exit_code": result["exit_code"],
            "timed_out": result["timed_out"],
        },
        "scope": "one explicitly requested administrator command; local approval may be required",
    }
