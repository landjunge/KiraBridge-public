"""Explicit local account linking. Never takes a literal runtime key in command arguments."""

from __future__ import annotations

import getpass
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import time
import uuid
import webbrowser
from pathlib import Path

from kirabridge.bridge_core.config import Config
from kirabridge.bridge_core.models import BridgeError
from kirabridge.local_runtime import LABEL, private_json, write_private
from kirabridge.task_manager.store import Store

TUNNELS_URL = "https://platform.openai.com/settings/organization/tunnels"
KEYS_URL = "https://platform.openai.com/settings/organization/api-keys"
PLUGINS_URL = "https://chatgpt.com/#settings/Connectors"


def replace_private(path: Path, value: str) -> None:
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex)
    try:
        write_private(temporary, value)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def persist_stdio_notification(config_path: Path) -> None:
    """Native runtimes connect generates JSON-as-YAML and drops optional MCP fields.

    Keep the documented lifecycle shim across subsequent starts. This completes
    a successful initialize, never synthesizes initialize or replays a tool.
    """
    profile = config_path.parent / "tunnel/kirabridge.yaml"
    settings = private_json(profile)
    mcp = settings.get("mcp")
    if not isinstance(mcp, dict) or not isinstance(mcp.get("commands"), list):
        raise BridgeError("tunnel_profile_format", "Expected the generated native stdio profile")
    mcp["stdio_send_initialized_notification"] = True
    replace_private(profile, json.dumps(settings, indent=2) + "\n")


def runtime_status(binary: str) -> dict:
    result = subprocess.run(
        [binary, "runtimes", "status", "kirabridge", "--json"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode:
        return {"connected": False, "account_setup_required": True}
    payload = json.loads(result.stdout)
    evidence = {}

    def collect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"process_running", "healthy", "ready"} and isinstance(item, bool):
                    evidence[key] = evidence.get(key, True) and item
                else:
                    collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(payload)
    return {
        "connected": all(evidence.get(key) for key in ("process_running", "healthy", "ready")),
        "runtime_evidence": evidence,
        "chatgpt_tool_call": "unverified",
    }


def wait_for_service(config_path: Path, *, timeout: float = 30) -> None:
    """Wait for authenticated health after a restart; never retry an execution."""
    deadline = time.monotonic() + timeout
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "kirabridge.cli",
                    "--config",
                    str(config_path),
                    "--principal",
                    "chatgpt",
                    "status",
                ],
                capture_output=True,
                text=True,
                timeout=min(6, remaining),
            )
            if result.returncode == 0:
                health = json.loads(result.stdout)
                if (
                    isinstance(health, dict)
                    and health.get("name") == "KiraBridge"
                    and health.get("api_version") == "1"
                    and health.get("dispatcher_active") is True
                ):
                    return
        except (subprocess.TimeoutExpired, ValueError):
            pass
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    raise BridgeError(
        "service_not_ready", "Local service is not ready; check kirabridge service status"
    )


def configure_tunnel(
    config: Config, config_path: Path, tunnel_id: str, runtime_key: str, binary: str
) -> dict:
    if not re.fullmatch(r"tunnel_[a-zA-Z0-9_-]{8,128}", tunnel_id):
        raise BridgeError("invalid_tunnel", "Use the tunnel ID from your OpenAI account")
    if len(runtime_key) < 32 or any(ch.isspace() for ch in runtime_key):
        raise BridgeError("invalid_runtime_key", "Use a restricted tunnel runtime key")
    if config.credentials_file is None or not config_path.is_file():
        raise BridgeError("setup_required", "Run the private local setup first")
    store = Store(config.state_path / "bridge.sqlite3")
    try:
        if store.db.execute(
            "SELECT 1 FROM tasks WHERE state IN ('accepted','running') LIMIT 1"
        ).fetchone():
            raise BridgeError("service_busy", "Wait for active local tasks before account setup")
    finally:
        store.close()
    credential_path = Path(config.credentials_file)
    credentials = private_json(credential_path)
    if "chatgpt" not in config.principals:
        policy = config.principals["local"].model_copy(deep=True)
        policy.token_env = "KIRABRIDGE_CHATGPT_TOKEN"
        section = "\n[principals.chatgpt]\n" + "".join(
            key + " = " + json.dumps(value) + "\n"
            for key, value in policy.model_dump().items()
            if value is not None
        )
        credentials["chatgpt"] = secrets.token_urlsafe(48)
        replace_private(credential_path, json.dumps(credentials))
        replace_private(config_path, config_path.read_text() + section)
        if sys.platform == "darwin":
            restarted = subprocess.run(
                ["/bin/launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{LABEL}"],
                capture_output=True,
                timeout=15,
            )
            if restarted.returncode:
                raise BridgeError("service_restart", "Restart the local KiraBridge service")
    wait_for_service(config_path)
    key_path = config_path.parent / "openai-tunnel-runtime.key"
    replace_private(key_path, runtime_key)
    command = shlex.join(
        [
            str(Path.home() / ".local/bin/kirabridge"),
            "--config",
            str(config_path.absolute()),
            "--principal",
            "chatgpt",
            "connect",
        ]
    )
    runtime_env = {**os.environ, "MCP_STDIO_SEND_INITIALIZED_NOTIFICATION": "true"}
    result = subprocess.run(
        [
            binary,
            "runtimes",
            "connect",
            "--alias",
            "kirabridge",
            "--tunnel-id",
            tunnel_id,
            "--runtime-api-key",
            "file:" + str(key_path),
            "--mcp-command",
            command,
            "--profile",
            "kirabridge",
            "--profile-dir",
            str(config_path.parent / "tunnel"),
        ],
        capture_output=True,
        text=True,
        timeout=90,
        env=runtime_env,
    )
    if result.returncode:
        raise BridgeError(
            "tunnel_access", "Tunnel setup failed; check account, workspace and Tunnels Read + Use"
        )
    persist_stdio_notification(config_path)
    return runtime_status(binary)


def wizard(config: Config, config_path: Path, action: str) -> dict:
    binary = shutil.which("tunnel-client")
    if not binary:
        raise BridgeError("tunnel_client_missing", "Install the official OpenAI tunnel-client")
    if action == "status":
        return {"tunnel_client_installed": True, **runtime_status(binary)}
    if not sys.stdin.isatty():
        raise BridgeError(
            "interactive_setup", "Run kirabridge chatgpt setup in your local Terminal"
        )
    print("Der lokale Dienst ist bereit. Jetzt wird dein OpenAI-Konto verbunden.")
    print(
        "1. Im Browser einen privaten Tunnel für deinen ChatGPT-Workspace anlegen oder auswählen."
    )
    webbrowser.open(TUNNELS_URL)
    tunnel_id = input("Tunnel-ID (beginnt mit tunnel_): ").strip()
    print("2. Einen eingeschränkten Runtime-Schlüssel mit Tunnels Read + Use anlegen.")
    webbrowser.open(KEYS_URL)
    runtime_key = getpass.getpass(
        "Runtime-Schlüssel (bleibt unsichtbar, nicht im Chat senden): "
    ).strip()
    result = configure_tunnel(config, config_path, tunnel_id, runtime_key, binary)
    if result["connected"]:
        print(
            "3. In ChatGPT: Benutzerdefinierten MCP-Server hinzufügen, Verbindung Tunnel auswählen."
        )
        print("Diesen Tunnel auswählen: " + tunnel_id)
        print("Danach bridge_health aufrufen. Erst dieser Aufruf belegt die ChatGPT-Verbindung.")
        webbrowser.open(PLUGINS_URL)
    return result
