"""Private browser login and a separate, loopback-only local operator service."""

from __future__ import annotations

import hmac
import os
import plistlib
import secrets
import shlex
import subprocess
import sys
import time
import uuid
import webbrowser
from pathlib import Path

import httpx

from kirabridge.approval_console import ORIGIN, PORT, ApprovalConsole, signature, signed_token
from kirabridge.bridge_core.bridge import Bridge
from kirabridge.bridge_core.config import Config, private_directory
from kirabridge.bridge_core.models import BridgeError
from kirabridge.local_runtime import private_json, write_private
from kirabridge.operator_application import operator_application

LABEL = "com.kirabridge.approvals"


def console_key(config_path: Path) -> str:
    import json

    private_directory(config_path.parent)
    path = config_path.parent / "console-credentials.json"
    if not path.exists():
        try:
            write_private(path, json.dumps({"token": secrets.token_urlsafe(48)}))
        except FileExistsError:
            pass
    key = private_json(path).get("token", "")
    if not isinstance(key, str) or len(key) < 32:
        raise BridgeError("unsafe_credentials", "Invalid console credential")
    return key


def install_console_service(config_path: Path) -> None:
    if sys.platform != "darwin":
        raise BridgeError("console_start", "Start kirabridge approval-server in a local terminal")
    path = Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"
    path.parent.mkdir(parents=True, exist_ok=True)
    arguments = [
        sys.executable,
        "-m",
        "kirabridge.cli",
        "--config",
        str(config_path),
        "approval-server",
    ]
    if path.exists():
        if plistlib.loads(path.read_bytes()).get("ProgramArguments") != arguments:
            raise BridgeError("service_conflict", "Existing approval service differs")
    else:
        write_private(
            path,
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
    result = subprocess.run(
        ["/bin/launchctl", "print", f"{target}/{LABEL}"], capture_output=True, timeout=10
    )
    command = (
        ["/bin/launchctl", "bootstrap", target, str(path)]
        if result.returncode
        else ["/bin/launchctl", "kickstart", f"{target}/{LABEL}"]
    )
    if subprocess.run(command, capture_output=True, timeout=15).returncode:
        raise BridgeError("console_start", "Could not start the local approval service")


def probe(client: httpx.Client, key: str) -> str | None:
    challenge = secrets.token_hex(16)
    try:
        response = client.get(ORIGIN + "/health", headers={"X-KiraBridge-Challenge": challenge})
    except (httpx.ConnectError, httpx.TimeoutException):
        return None
    try:
        payload = response.json()
        instance = payload["instance"]
        expected = signature(key, "probe", challenge + "." + instance)
        if (
            response.status_code != 200
            or payload.get("name") != "KiraBridge approvals"
            or not hmac.compare_digest(payload.get("proof", ""), expected)
        ):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise BridgeError(
            "console_conflict", "Port 8766 is not this private KiraBridge console"
        ) from None
    return instance


def open_console(config_path: Path) -> dict:
    key = console_key(config_path)
    with httpx.Client(trust_env=False, timeout=2, follow_redirects=False) as client:
        instance = probe(client, key)
        if instance is None:
            install_console_service(config_path)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                instance = probe(client, key)
                if instance is not None:
                    break
                time.sleep(0.2)
        if instance is None:
            raise BridgeError("console_start", "The local approval page is not ready")
    # The one-use ticket is passed in a POST body from a private file. No credential
    # is put in a URL, a process argument, a launchd plist, or terminal output.
    ticket = signed_token(key, "login:" + instance)
    page = (
        '<!doctype html><html lang="de"><meta charset="utf-8">'
        '<meta name="referrer" content="no-referrer"><title>KiraBridge öffnen</title>'
        "<body><p>Lokale KiraBridge-Freigaben öffnen …</p>"
        f'<form method="post" action="{ORIGIN}/login">'
        f'<input type="hidden" name="ticket" value="{ticket}">'
        '<button type="submit">Freigaben öffnen</button></form>'
        "<script>document.forms[0].submit()</script></body></html>"
    )
    destination = config_path.parent / "approval-login.html"
    temporary = destination.with_name(destination.name + "." + uuid.uuid4().hex)
    try:
        write_private(temporary, page)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    native = Path.home() / "Applications/KiraBridge.app"
    if os.environ.get("KIRABRIDGE_CONSOLE_EMBED") == "1":
        opened = False
    elif sys.platform == "darwin" and native.is_dir():
        result = subprocess.run(
            ["/usr/bin/open", "-a", str(native)],
            capture_output=True,
            timeout=10,
        )
        opened = result.returncode == 0
    elif sys.platform == "darwin":
        result = subprocess.run(
            ["/usr/bin/open", str(destination)], capture_output=True, timeout=10
        )
        opened = result.returncode == 0
    else:
        opened = webbrowser.open(destination.as_uri())
    launcher = config_path.parent / "KiraBridge-Freigaben.command"
    if not launcher.exists():
        command = shlex.join(
            [sys.executable, "-m", "kirabridge.cli", "--config", str(config_path), "approvals"]
        )
        write_private(launcher, "#!/bin/sh\nexec " + command + "\n", mode=0o700)
    desktop = Path.home() / "Desktop/KiraBridge Freigaben.command"
    if sys.platform == "darwin" and desktop.parent.is_dir() and not desktop.exists():
        try:
            desktop.symlink_to(launcher)
        except FileExistsError:
            pass
    return {
        "url": ORIGIN + "/",
        "opened": opened,
        "launcher": str(launcher),
        "login_file": str(destination),
    }


async def serve_console(config: Config, config_path: Path) -> None:
    import uvicorn

    bridge = Bridge(config)
    try:
        server = uvicorn.Server(
            uvicorn.Config(
                ApprovalConsole(operator_application(bridge), console_key(config_path)),
                host="127.0.0.1",
                port=PORT,
                access_log=False,
                log_level="critical",
                limit_concurrency=16,
                timeout_keep_alive=5,
            )
        )
        await server.serve()
    finally:
        bridge.store.close()
