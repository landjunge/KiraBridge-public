"""Small shared bounds for optional CLI adapters; no shell or implicit credentials."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from kirabridge.bridge_core.models import BridgeError, UncertainExecution
from kirabridge.terminal_manager import TerminalManager, minimal_environment


def cli_environment(config, terminal: TerminalManager | None = None) -> dict[str, str]:
    """Forward only a deliberately selected credential variable to its CLI."""
    env = terminal.environment.copy() if terminal else minimal_environment()
    env.setdefault("HOME", str(Path.home()))
    paths = env["PATH"].split(os.pathsep)
    if config.executable and Path(config.executable).is_absolute():
        directory = str(Path(config.executable).parent)
        if directory not in paths:
            paths.append(directory)
    if sys.platform == "darwin":
        for directory in ("/usr/sbin", "/sbin"):
            if directory not in paths:
                paths.append(directory)
    env["PATH"] = os.pathsep.join(paths)
    key = config.api_key_env
    forbidden = {
        "PATH",
        "HOME",
        "PYTHONPATH",
        "PYTHONHOME",
        "NODE_OPTIONS",
        "NODE_PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
    }
    if key and (not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key) or key in forbidden):
        raise BridgeError("agent_config", "Use a dedicated credential environment name")
    if key and key in os.environ:
        env[key] = os.environ[key]
    return env


class BoundedText:
    """Keep at most a fixed UTF-8 byte budget without retaining discarded text."""

    def __init__(self, max_bytes: int = 65536):
        if type(max_bytes) is not int or not 1 <= max_bytes <= 1048576:
            raise ValueError("invalid text bound")
        self.max_bytes = max_bytes
        self._data = bytearray()
        self.truncated = False

    def append(self, text: str) -> None:
        if not isinstance(text, str):
            raise UncertainExecution("agent_protocol", "Agent returned invalid text")
        raw = text.encode("utf-8")
        remaining = self.max_bytes - len(self._data)
        self._data.extend(raw[:remaining])
        self.truncated = self.truncated or len(raw) > remaining

    @property
    def text(self) -> str:
        return self._data.decode("utf-8", errors="ignore")


def bind_session(current: str | None, new: str) -> str:
    """A provider may announce one bounded session, never silently switch it."""
    if (
        not isinstance(new, str)
        or not new
        or len(new.encode("utf-8")) > 256
        or any(ord(char) < 32 or ord(char) == 127 for char in new)
    ):
        raise UncertainExecution("agent_identity", "Agent returned an invalid session ID")
    if current is not None and current != new:
        raise UncertainExecution("agent_identity", "Agent changed session identity")
    return new
