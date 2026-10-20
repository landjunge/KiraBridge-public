"""Local operator setup and a separately supervised, authenticated Grok app gateway."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import plistlib
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import tomllib
import uuid
from pathlib import Path

import uvicorn

from kirabridge.bridge_core.config import (
    Config,
    GrokConnectorConfig,
    load_config,
    private_directory,
)
from kirabridge.bridge_core.models import BridgeError
from kirabridge.grok_connector import effective_settings, state_dir
from kirabridge.local_runtime import private_json, write_private

LABEL = "com.kirabridge.grok-app"
OWNER = "kirabridge-grok-app"


def replace_private(path: Path, value: str):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex)
    try:
        write_private(temporary, value)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def section(text: str, name: str, values: dict) -> str:
    """Replace only the operator-owned section, preserving all other policies verbatim."""
    content = (
        "\n["
        + name
        + "]\n"
        + "".join(
            key + " = " + json.dumps(value, ensure_ascii=False) + "\n"
            for key, value in values.items()
            if value is not None
        )
    )
    pattern = re.compile(r"(?m)^\[" + re.escape(name) + r"\][ \t]*(?:#[^\n]*)?$")
    matches = list(pattern.finditer(text))
    if len(matches) > 1:
        raise BridgeError("connector_config", "Duplicate connector configuration")
    if not matches:
        return text.rstrip() + "\n" + content
    match = matches[0]
    following = re.search(r"(?m)^\[", text[match.end() :])
    end = match.end() + following.start() if following else len(text)
    return text[: match.start()].rstrip() + "\n" + content + "\n" + text[end:]


def finish_prepare(config_path, credential_path, folder, manifest, plan):
    """Reconcile only our exact saved file transition after an interrupted setup."""
    targets = ((config_path, "config"), (credential_path, "credentials"))
    for path, name in targets:
        current = hashlib.sha256(path.read_bytes()).hexdigest()
        if current not in {plan[name + "_before"], plan[name + "_after"]}:
            raise BridgeError(
                "connector_setup_conflict", "Changed local files preserved; inspect setup intent"
            )
    for path, name in reversed(targets):
        if hashlib.sha256(path.read_bytes()).hexdigest() == plan[name + "_before"]:
            staged = (folder / ("staged-" + name)).read_text()
            if hashlib.sha256(staged.encode()).hexdigest() != plan[name + "_after"]:
                raise BridgeError(
                    "connector_setup_conflict", "Inspect changed connector staging files"
                )
            replace_private(path, staged)
    replace_private(manifest, json.dumps({**plan, "prepared": True}))


def ensure_idle(config):
    path = config.state_path / "bridge.sqlite3"
    if not path.exists():
        return
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2) as db:
        for table, states in (
            ("tasks", "'created','queued','accepted','running'"),
            ("message_jobs", "'queued','running'"),
            (
                "team_work",
                "'queued','dispatching','created','accepted','running','processing_result'",
            ),
        ):
            exists = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if (
                exists
                and db.execute(
                    f"SELECT 1 FROM {table} WHERE state IN ({states}) LIMIT 1"
                ).fetchone()
            ):
                raise BridgeError(
                    "service_busy", "Let current bridge work finish before account setup"
                )


def prepare(config_path: Path, *, access="team", cloudflared=None, public_origin=None):
    config = load_config(str(config_path))
    if not config.credentials_file or access not in {"team", "same-as-chatgpt"}:
        raise BridgeError(
            "setup_required", "Existing private setup and a valid access profile required"
        )
    settings = GrokConnectorConfig(public_origin=public_origin)
    if settings.port in {config.port, 8766}:
        raise BridgeError("connector_port", "Connector must use a separate loopback port")
    folder = state_dir(config)
    private_directory(folder)
    manifest = folder / "setup.json"
    if manifest.exists():
        existing = private_json(manifest)
        if existing.get("owner") != OWNER or existing.get("access") != access:
            raise BridgeError(
                "connector_existing", "Existing connector policy preserved; inspect it first"
            )
        if not existing.get("prepared"):
            ensure_idle(config)
            finish_prepare(config_path, Path(config.credentials_file), folder, manifest, existing)
            return {
                "prepared": True,
                "recovered": True,
                "principal": "grok_app",
                "reload_required": True,
            }
        return {
            "prepared": True,
            "existing": True,
            "principal": "grok_app",
            "reload_required": False,
        }
    ensure_idle(config)
    credential_path = Path(config.credentials_file)
    credentials = private_json(credential_path)
    if "grok_app" in config.principals or "grok_app" in credentials:
        raise BridgeError(
            "connector_existing", "Existing Grok app identity preserved; inspect it first"
        )
    if access == "same-as-chatgpt":
        if "chatgpt" not in config.principals:
            raise BridgeError("connector_source", "No ChatGPT policy is configured to copy")
        policy = config.principals["chatgpt"].model_copy(deep=True)
        policy.message_peers = []
    else:
        from kirabridge.bridge_core.config import PrincipalConfig

        source = config.principals.get("local")
        policy = PrincipalConfig(
            approval_mode=source.approval_mode if source else "manual",
            capabilities=[
                "bridge.health",
                "task.read",
                "agent.inspect",
                "team.read",
                "team.write",
                "team.manage",
            ],
            team_only_execution=True,
        )
    policy.token_env = "KIRABRIDGE_GROK_APP_TOKEN"
    text = section(config_path.read_text(), "principals.grok_app", policy.model_dump())
    if config.team.enabled:
        text = section(text, "team.workers.grok_app", {})
    text = section(text, "grok_connector", settings.model_dump())
    Config.model_validate(tomllib.loads(text))
    binary = (
        str(Path(cloudflared).expanduser().absolute())
        if cloudflared
        else shutil.which("cloudflared")
    )
    if not public_origin and (
        not binary or not Path(binary).is_file() or not os.access(binary, os.X_OK)
    ):
        raise BridgeError(
            "tunnel_binary_missing", "Install official cloudflared or provide --cloudflared PATH"
        )
    ident = uuid.uuid4().hex
    write_private(folder / ("config-before-" + ident + ".toml"), config_path.read_text())
    write_private(folder / ("credentials-before-" + ident + ".json"), json.dumps(credentials))
    credentials["grok_app"] = secrets.token_urlsafe(48)
    staged_credentials = json.dumps(credentials)
    write_private(folder / "staged-config", text)
    write_private(folder / "staged-credentials", staged_credentials)
    plan = {
        "owner": OWNER,
        "prepared": False,
        "access": access,
        "cloudflared": binary,
        "mode": "external" if public_origin else "cloudflare_quick",
        "public_origin": public_origin,
        "created": time.time(),
        "principal": "grok_app",
        "config_before": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "config_after": hashlib.sha256(text.encode()).hexdigest(),
        "credentials_before": hashlib.sha256(credential_path.read_bytes()).hexdigest(),
        "credentials_after": hashlib.sha256(staged_credentials.encode()).hexdigest(),
    }
    write_private(
        manifest,
        json.dumps(plan),
    )
    finish_prepare(config_path, credential_path, folder, manifest, plan)
    return {
        "prepared": True,
        "existing": False,
        "principal": "grok_app",
        "access": access,
        "approval_mode": policy.approval_mode,
        "reload_required": True,
        "voice_app_verified": False,
        "provider_voice_api_used": False,
    }


def connector_status(config):
    settings = effective_settings(config)
    data = {
        "enabled": settings.enabled,
        "principal": "grok_app",
        "cli_principal": "grok",
        "connector_url": settings.public_origin + "/mcp" if settings.public_origin else None,
        "gateway_healthy": False,
        "grok_app_call_verified": False,
        "eve_voice_verified": False,
        "provider_voice_api_used": False,
        "operator_url": "http://127.0.0.1:8766/grok-connector",
    }
    profile = state_dir(config) / "runtime-profile.json"
    if profile.exists():
        runtime = private_json(profile)
        data.update(
            supervisor_state=runtime.get("state"),
            tunnel_mode=runtime.get("mode"),
            url_changes_on_tunnel_restart=runtime.get("mode") == "cloudflare_quick",
        )
    if settings.enabled:
        import httpx

        try:
            response = httpx.get(
                f"http://127.0.0.1:{settings.port}/health", timeout=3, trust_env=False
            )
            health = response.json() if response.status_code == 200 else {}
            data["gateway_healthy"] = (
                health.get("name") == "KiraBridge Grok connector" and health.get("healthy") is True
            )
        except (httpx.HTTPError, ValueError):
            pass
        from kirabridge.grok_connector.auth_store import OAuthStore

        store = OAuthStore(
            state_dir(config) / "oauth.sqlite3",
            issuer=settings.public_origin,
            principal=settings.principal,
            redirect_hosts=settings.redirect_hosts,
        )
        try:
            data["oauth"] = store.status()
        finally:
            store.close()
    return data


def service_command(config_path):
    return [
        sys.executable,
        "-m",
        "kirabridge.cli",
        "--config",
        str(config_path),
        "grok-connector",
        "serve",
    ]


async def start(config_path: Path, *, timeout=60):
    config = load_config(str(config_path))
    folder = state_dir(config)
    manifest = private_json(folder / "setup.json")
    if manifest.get("owner") != OWNER or not manifest.get("prepared"):
        raise BridgeError("setup_required", "Prepare the private connector first")
    # Starting is idempotent; never replace an already running tunnel and URL.
    current = await asyncio.to_thread(connector_status, config)
    if current.get("gateway_healthy"):
        ready = await bridge_access_readiness(config)
        return {
            **current,
            "bridge_access_ready": ready,
            "reload_required": not ready,
            "local_services_reloaded": False,
        }
    if sys.platform == "darwin":
        path = Path.home() / "Library/LaunchAgents" / (LABEL + ".plist")
        if path.exists():
            existing = plistlib.loads(path.read_bytes())
            if existing.get("ProgramArguments") != service_command(config_path):
                raise BridgeError(
                    "connector_service_conflict", "Existing connector service preserved"
                )
        else:
            environment = {"PATH": os.pathsep.join(config.terminal.search_path)}
            write_private(
                path,
                plistlib.dumps(
                    {
                        "Label": LABEL,
                        "ProgramArguments": service_command(config_path),
                        "EnvironmentVariables": environment,
                        "RunAtLoad": True,
                        "KeepAlive": True,
                        "ThrottleInterval": 30,
                    }
                ).decode(),
            )
        check = await asyncio.to_thread(
            subprocess.run,
            ["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"],
            capture_output=True,
            timeout=5,
        )
        if check.returncode:
            await asyncio.to_thread(
                subprocess.run,
                ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)],
                check=True,
                capture_output=True,
                timeout=15,
            )
    elif sys.platform.startswith("linux") and shutil.which("systemctl"):
        unit = Path.home() / ".config/systemd/user/kirabridge-grok-app.service"
        unit.parent.mkdir(parents=True, exist_ok=True)
        command = " ".join(
            '"' + a.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"') + '"'
            for a in service_command(config_path)
        )
        body = "[Unit]\nDescription=KiraBridge Grok application connector\n[Service]\n" + (
            "ExecStart="
            + command
            + "\nRestart=on-failure\nRestartSec=30\n[Install]\nWantedBy=default.target\n"
        )
        if unit.exists() and unit.read_text() != body:
            raise BridgeError("connector_service_conflict", "Existing connector service preserved")
        if not unit.exists():
            write_private(unit, body)
        await asyncio.to_thread(
            subprocess.run,
            ["systemctl", "--user", "daemon-reload"],
            check=True,
            capture_output=True,
            timeout=10,
        )
        await asyncio.to_thread(
            subprocess.run,
            ["systemctl", "--user", "enable", "--now", unit.name],
            check=True,
            capture_output=True,
            timeout=15,
        )
    else:
        raise BridgeError(
            "connector_service_manager", "Run kirabridge grok-connector serve in a local terminal"
        )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        profile = folder / "runtime-profile.json"
        if profile.exists():
            runtime = private_json(profile)
            if runtime.get("owner") != OWNER or runtime.get("port") != config.grok_connector.port:
                raise BridgeError(
                    "connector_profile_conflict", "Inspect connector runtime ownership"
                )
            try:
                os.kill(runtime["supervisor_pid"], 0)
                alive = True
            except (ProcessLookupError, PermissionError, KeyError):
                alive = False
            if runtime.get("state") == "ready" and alive:
                settings = config.grok_connector.model_copy(
                    update={"enabled": True, "public_origin": runtime["public_origin"]}
                )
                candidate = config.model_copy(update={"grok_connector": settings})
                report = await asyncio.to_thread(connector_status, candidate)
                if not report["gateway_healthy"]:
                    await asyncio.sleep(0.25)
                    continue
                replace_private(
                    config_path,
                    section(config_path.read_text(), "grok_connector", settings.model_dump()),
                )
                ready = await bridge_access_readiness(candidate)
                return {
                    **report,
                    "bridge_access_ready": ready,
                    "reload_required": not ready,
                    "local_services_reloaded": False,
                }
        await asyncio.sleep(0.25)
    raise BridgeError(
        "connector_start_timeout", "Inspect the connector status; do not start duplicate tunnels"
    )


async def bridge_access_readiness(config):
    """Observe the loaded app identity without stopping or restarting other services.

    A missing identity requires a separately planned, orderly core reload. An
    idle snapshot cannot authorize SIGTERM: new work may arrive immediately.
    """
    from kirabridge.local_runtime import daemon_health

    try:
        health = await daemon_health(config, "grok_app")
    except Exception:
        return False
    return (
        isinstance(health, dict)
        and health.get("name") == "KiraBridge"
        and health.get("dispatcher_active") is True
    )


def stop():
    if sys.platform == "darwin":
        command = ["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"]
    elif sys.platform.startswith("linux"):
        command = ["systemctl", "--user", "stop", "kirabridge-grok-app.service"]
    else:
        raise BridgeError("connector_service_manager", "Stop only your own foreground connector")
    result = subprocess.run(command, capture_output=True, timeout=20)
    return {"stop_requested": result.returncode == 0, "bridge_and_cli_sessions_stopped": False}


async def serve(config_path: Path):
    config = load_config(str(config_path))
    folder = state_dir(config)
    manifest = private_json(folder / "setup.json")
    if manifest.get("owner") != OWNER or manifest.get("principal") != "grok_app":
        raise BridgeError("connector_profile_conflict", "Inspect local connector ownership")
    from kirabridge.platform_adapters import RuntimeLock

    lock = RuntimeLock(folder / "supervisor.lock")
    lock.acquire()
    loop = asyncio.get_running_loop()
    owner = asyncio.current_task()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, owner.cancel)
    tunnel = None
    reader = None
    profile = {
        "owner": OWNER,
        "port": config.grok_connector.port,
        "mode": manifest["mode"],
        "state": "starting",
        "supervisor_pid": os.getpid(),
        "generation": uuid.uuid4().hex,
    }
    try:
        if manifest["mode"] == "cloudflare_quick":
            binary = manifest.get("cloudflared")
            if not binary or not Path(binary).is_file():
                raise BridgeError(
                    "tunnel_binary_missing", "Prepared cloudflared binary is unavailable"
                )
            environment = {
                k: os.environ[k]
                for k in ("PATH", "HOME", "TMPDIR", "SSL_CERT_FILE")
                if k in os.environ
            }
            tunnel = await asyncio.create_subprocess_exec(
                binary,
                "tunnel",
                "--config",
                "/dev/null",
                "--no-autoupdate",
                "--metrics",
                "127.0.0.1:0",
                "--url",
                f"http://127.0.0.1:{config.grok_connector.port}",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
                start_new_session=True,
            )
            async with asyncio.timeout(45):
                while True:
                    line = await tunnel.stderr.readline()
                    if not line:
                        raise BridgeError(
                            "tunnel_start_failed", "Cloudflare tunnel exited before becoming ready"
                        )
                    match = re.search(rb"https://[a-z0-9-]+\.trycloudflare\.com", line)
                    if match:
                        origin = match[0].decode()
                        break

            async def discard_output():
                while await tunnel.stderr.read(4096):
                    pass

            reader = asyncio.create_task(discard_output())
            profile["tunnel_pid"] = tunnel.pid
        else:
            origin = manifest["public_origin"]
        config.grok_connector = GrokConnectorConfig.model_validate(
            {**config.grok_connector.model_dump(), "enabled": True, "public_origin": origin}
        )
        profile["public_origin"] = origin
        replace_private(folder / "runtime-profile.json", json.dumps(profile))
        from kirabridge.grok_connector.gateway import create_gateway

        server = uvicorn.Server(
            uvicorn.Config(
                create_gateway(config),
                host="127.0.0.1",
                port=config.grok_connector.port,
                log_level="critical",
                access_log=False,
                proxy_headers=False,
                timeout_graceful_shutdown=30,
            )
        )
        running = asyncio.create_task(server.serve())
        try:
            async with asyncio.timeout(15):
                while not server.started:
                    if running.done():
                        await running
                        raise BridgeError(
                            "connector_start_failed", "Gateway stopped before readiness"
                        )
                    await asyncio.sleep(0.05)
            profile["state"] = "ready"
            replace_private(folder / "runtime-profile.json", json.dumps(profile))
            if tunnel:
                monitor = asyncio.create_task(tunnel.wait())
                try:
                    done, _ = await asyncio.wait(
                        [running, monitor], return_when=asyncio.FIRST_COMPLETED
                    )
                    unexpected_tunnel_exit = monitor in done and not server.should_exit
                    if monitor in done:
                        server.should_exit = True
                    await running
                    if unexpected_tunnel_exit:
                        raise BridgeError(
                            "connector_tunnel_exited",
                            "Tunnel exited unexpectedly; the connector supervisor must restart",
                        )
                finally:
                    monitor.cancel()
                    await asyncio.gather(monitor, return_exceptions=True)
            else:
                await running
        finally:
            server.should_exit = True
            if not running.done():
                await running
    finally:
        profile["state"] = "stopped"
        if "public_origin" in profile:
            replace_private(folder / "runtime-profile.json", json.dumps(profile))
        if tunnel and tunnel.returncode is None:
            tunnel.terminate()
            try:
                await asyncio.wait_for(tunnel.wait(), 10)
            except TimeoutError:
                tunnel.kill()
                await tunnel.wait()
        if reader:
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
        lock.release()
