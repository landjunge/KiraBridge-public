"""Private local credentials, daemon clients and macOS service installation."""

from __future__ import annotations

import json
import os
import plistlib
import secrets
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from kirabridge.bridge_core.config import Config, private_directory
from kirabridge.bridge_core.models import BridgeError
from kirabridge.mcp_gateway.client import MCPClientPool, Peer

LABEL = "com.kirabridge.bridge"


def default_config() -> Path:
    return Path.home() / ".config/kirabridge/config.toml"


def private_json(path: Path) -> dict:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        info = os.fstat(source.fileno())
        if os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise BridgeError("unsafe_credentials", "Credentials must be owner-only")
        raw = source.read(65537)
        if len(raw) > 65536:
            raise BridgeError("unsafe_credentials", "Credentials file exceeds limit")
        return json.loads(raw)


def token_for(config: Config, principal: str) -> str:
    policy = config.principals.get(principal)
    if policy is None:
        raise BridgeError("forbidden", "Unknown principal")
    token = os.environ.get(policy.token_env, "") if policy.token_env else ""
    if not token and config.credentials_file:
        token = private_json(Path(config.credentials_file)).get(principal, "")
    if not isinstance(token, str) or len(token) < 32:
        raise BridgeError("credentials_missing", "Local credentials are not configured")
    return token


def load_service_credentials(config: Config) -> None:
    for name, policy in config.principals.items():
        if policy.token_env:
            os.environ[policy.token_env] = token_for(config, name)


def peer(config: Config, principal: str) -> Peer:
    # Installed local clients never forward local tokens to a reconfigured external host.
    if config.host not in {"127.0.0.1", "::1", "localhost"}:
        raise BridgeError("unsafe_local_endpoint", "Local client requires a loopback endpoint")
    host = "[::1]" if config.host == "::1" else config.host
    scheme = "https" if config.tls_cert else "http"
    return Peer(
        "daemon",
        url=f"{scheme}://{host}:{config.port}/mcp",
        token=token_for(config, principal),
        ca_file=config.tls_cert,
    )


async def daemon_health(config: Config, principal: str) -> dict:
    async with MCPClientPool(
        call_timeout=5, observer=connection_observer(config, principal)
    ) as pool:
        await pool.connect(peer(config, principal))
        result = await pool.call("daemon", "bridge_health", {})
        return result.structuredContent or {"error": {"code": "invalid_health"}}


def connection_observer(config: Config, principal: str):
    from kirabridge.diagnostics import AuditObserver
    from kirabridge.readiness import runtime_snapshot

    return AuditObserver(config, principal, runtime_snapshot(config))


def write_private(path: Path, text: str | bytes, *, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    with os.fdopen(fd, "wb") as output:
        output.write(text.encode() if isinstance(text, str) else text)
        output.flush()
        os.fsync(output.fileno())


def setup(workspace: str, destination: Path | None = None) -> dict:
    destination = destination or default_config()
    private_directory(destination.parent)
    if destination.exists():
        raise BridgeError("already_configured", "Existing configuration is never overwritten")
    root = Path(workspace).expanduser().absolute()
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    state = Path.home() / ".local/share/kirabridge"
    private_directory(state)
    credential_path = destination.parent / "credentials.json"
    credentials = {name: secrets.token_urlsafe(48) for name in ("local", "codex", "grok")}
    write_private(credential_path, json.dumps(credentials))
    executables = [
        str(Path(p).absolute())
        for p in [sys.executable, "/bin/ls", "/usr/bin/git", "/bin/zsh"]
        if Path(p).is_file()
    ]
    capabilities = [
        "bridge.health",
        "task.read",
        "task.cancel",
        "agent.inspect",
        "session.inspect",
        "session.catalog",
        "session.read",
        "session.input",
        "session.open",
        "file.read",
        "file.list",
        "file.write",
        "file.mkdir",
        "file.move",
        "terminal.execute",
        "clipboard.info",
        "clipboard.read",
        "clipboard.write",
        "process.list",
        "process.inspect",
        "process.terminate",
    ]
    agent_paths = {name: shutil.which(name) for name in ("codex", "grok")}
    content = (
        f"data_dir = {json.dumps(str(state))}\n"
        f"credentials_file = {json.dumps(str(credential_path))}\n"
        'host = "127.0.0.1"\nport = 8765\nconcurrency = 1\nallow_remote = false\n'
    )
    for name in credentials:
        caps = capabilities + (["agent.execute"] if name == "local" else [])
        content += (
            f"\n[principals.{name}]\ncapabilities = {json.dumps(caps)}\n"
            f"roots = {json.dumps([str(root)])}\n"
            f"executables = {json.dumps(executables)}\n"
            f"agents = {json.dumps([a for a, path in agent_paths.items() if path])}\n"
            f'token_env = "KIRABRIDGE_{name.upper()}_TOKEN"\n'
        )
    for name, executable in agent_paths.items():
        if executable:
            kind = "codex" if name == "codex" else "grok_acp"
            content += (
                f"\n[agents.{name}]\nkind = {json.dumps(kind)}\n"
                f"executable = {json.dumps(executable)}\n"
            )
    write_private(destination, content)
    command_path = Path.home() / ".local/bin/kirabridge"
    command_path.parent.mkdir(parents=True, exist_ok=True)
    wrapper = f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -m kirabridge.cli "$@"\n'
    if not command_path.exists():
        write_private(command_path, wrapper, mode=0o700)
    return {
        "config": str(destination),
        "workspace": str(root),
        "data_dir": str(state),
        "command": str(command_path),
        "agents": [name for name, path in agent_paths.items() if path],
        "secrets_printed": False,
    }


def install_service(config_path: Path) -> dict:
    if sys.platform != "darwin":
        raise BridgeError("unsupported_platform", "Use the documented systemd unit on Linux")
    launch_dir = Path.home() / "Library/LaunchAgents"
    launch_dir.mkdir(parents=True, exist_ok=True)
    plist_path = launch_dir / f"{LABEL}.plist"
    arguments = [
        sys.executable,
        "-m",
        "kirabridge.cli",
        "--config",
        str(config_path),
        "serve",
        "--transport",
        "http",
    ]
    if plist_path.exists():
        previous = plistlib.loads(plist_path.read_bytes())
        if previous.get("ProgramArguments") != arguments:
            raise BridgeError("service_conflict", "An existing service configuration differs")
    else:
        write_private(
            plist_path,
            plistlib.dumps(
                {
                    "Label": LABEL,
                    "ProgramArguments": arguments,
                    "RunAtLoad": True,
                    "KeepAlive": {"SuccessfulExit": False},
                    "ThrottleInterval": 3,
                    "Umask": 0o077,
                    "ProcessType": "Background",
                    "EnvironmentVariables": {
                        "HOME": str(Path.home()),
                        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                        "LANG": "en_US.UTF-8",
                    },
                }
            ),
        )
    target = f"gui/{os.getuid()}"
    check = subprocess.run(["/bin/launchctl", "print", f"{target}/{LABEL}"], capture_output=True)
    if check.returncode:
        result = subprocess.run(
            ["/bin/launchctl", "bootstrap", target, str(plist_path)],
            capture_output=True,
            timeout=15,
        )
        if result.returncode:
            raise BridgeError("service_install", "launchd could not load KiraBridge")
    return {"label": LABEL, "plist": str(plist_path), "loaded": True}
