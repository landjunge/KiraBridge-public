#!/usr/bin/env python3
"""Pinned, foreground KiraBridge installation. Does not need the checkout's venv."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import io
import json
import os
import plistlib
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
import time
import tomllib
import uuid
from pathlib import Path

LABEL = "com.kirabridge.bridge"


def say(message):
    print(message, flush=True)


def run(argv, *, capture=False, timeout=600, **kwargs):
    if "env" not in kwargs:
        kwargs["env"] = {
            k: v
            for k, v in os.environ.items()
            if k not in {"PYTHONPATH", "PYTHONHOME", "UV_PROJECT_ENVIRONMENT"}
        }
    process = subprocess.Popen(
        [str(x) for x in argv],
        start_new_session=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        **kwargs,
    )
    try:
        stdout, _ = process.communicate(timeout=timeout)
        if process.returncode:
            raise RuntimeError(f"command failed ({process.returncode}): {Path(str(argv[0])).name}")
        return stdout if capture else None
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
        raise


def private_dir(path):
    if path.is_symlink():
        raise RuntimeError(f"symlink directory refused: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError(f"owner-only directory required, permissions not changed: {path}")


def atomic(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError(f"symlink destination refused: {path}")
    temporary = path.with_name("." + path.name + "-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data.encode() if isinstance(data, str) else data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def jwrite(path, value):
    atomic(path, json.dumps(value, indent=2) + "\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def settings(config):
    return tomllib.loads(config.read_text())


def state_file(config):
    return Path(settings(config)["data_dir"]).expanduser() / "bridge.sqlite3"


@contextlib.contextmanager
def idle_guard(config):
    path = state_file(config)
    if not path.exists():
        yield None
        return
    db = sqlite3.connect(f"file:{path}?mode=rw", uri=True, isolation_level=None, timeout=5)
    try:
        db.execute("BEGIN IMMEDIATE")
        tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        tasks = (
            db.execute(
                "select count(*) from tasks "
                "where state in ('created','queued','accepted','running')"
            ).fetchone()[0]
            if "tasks" in tables
            else 0
        )
        jobs = (
            db.execute(
                "select count(*) from message_jobs where state in ('queued','running')"
            ).fetchone()[0]
            if "message_jobs" in tables
            else 0
        )
        if tasks or jobs:
            raise RuntimeError(f"BUSY: {tasks} tasks, {jobs} receiver jobs. Nothing switched.")
        say("Leerlauf unter Schreibsperre: 0 aktive Tasks, 0 Empfängerjobs.")
        yield db
    finally:
        db.rollback()
        db.close()


def python(release):
    return release / "source/.venv/bin/python"


def cli(release, config, *args, timeout=30):
    return json.loads(
        run(
            [python(release), "-m", "kirabridge.cli", "--config", config, *args],
            capture=True,
            timeout=timeout,
        )
    )


def prepare(args):
    ref = args.ref
    if not re.fullmatch("[a-f0-9]{40}", ref or ""):
        raise RuntimeError("--ref must be an exact 40-character Git commit SHA")
    actual = (
        run(["git", "-C", args.repo, "rev-parse", ref + "^{commit}"], capture=True).decode().strip()
    )
    if actual != ref:
        raise RuntimeError("Git commit mismatch")
    project = tomllib.loads(
        run(["git", "-C", args.repo, "show", ref + ":pyproject.toml"], capture=True).decode()
    )
    version = project["project"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?", version):
        raise RuntimeError("Unsupported release version")
    releases = args.prefix / "releases"
    private_dir(releases)
    destination = releases / (version + "-" + ref[:12])
    if destination.exists():
        manifest = json.loads((destination / "release.json").read_text())
        if manifest["commit"] != ref or cli_version(destination) != version:
            raise RuntimeError("Existing release identity differs")
        say(f"Bereits vorbereitet: {version} @ {ref}")
        return destination
    stage = releases / (".preparing-" + uuid.uuid4().hex)
    private_dir(stage)
    source = stage / "source"
    source.mkdir(mode=0o700)
    say(f"Bereite {version} aus Git-Commit {ref} vor; Arbeitskopie wird nicht kopiert.")
    archive = run(["git", "-C", args.repo, "archive", "--format=tar", ref], capture=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source, filter="data")
    uv = shutil.which("uv")
    if not uv:
        raise RuntimeError("uv is required; install it explicitly before running this installer")
    run(
        [
            uv,
            "sync",
            "--project",
            source,
            "--frozen",
            "--no-dev",
            "--no-editable",
            "--python",
            sys.executable,
            "--cache-dir",
            args.cache_dir,
        ]
    )
    if cli_version(stage) != version:
        raise RuntimeError("Installed package version differs from release")
    jwrite(
        stage / "release.json",
        {"version": version, "commit": ref, "lock_sha256": sha(source / "uv.lock")},
    )
    # venv Python entry points use absolute paths. Build in the final path instead
    # of renaming a venv; recreate once there with the same frozen lock.
    destination.mkdir(mode=0o700)
    shutil.move(str(source), str(destination / "source"))
    shutil.rmtree(destination / "source/.venv")
    run(
        [
            uv,
            "sync",
            "--project",
            destination / "source",
            "--frozen",
            "--no-dev",
            "--no-editable",
            "--python",
            sys.executable,
            "--cache-dir",
            args.cache_dir,
        ]
    )
    atomic(destination / "release.json", (stage / "release.json").read_bytes())
    shutil.rmtree(stage)
    say(f"Versionspaket geprüft: {version}; bisherige Installation unverändert.")
    return destination


def cli_version(release):
    return (
        run(
            [python(release), "-c", "import kirabridge;print(kirabridge.__version__)"], capture=True
        )
        .decode()
        .strip()
    )


def fresh_config(args, release):
    if args.config.exists():
        # Never rewrite an existing policy, even if its permissions differ.
        return
    if not args.full_access:
        raise RuntimeError(
            "Fresh installation requires --full-access; existing policy is never overwritten"
        )
    private_dir(args.config.parent)
    data = args.prefix / "data"
    private_dir(data)
    credentials = args.config.parent / "credentials.json"
    if credentials.exists():
        raise RuntimeError("Credentials exist without config; refusing to overwrite")
    code = (
        "import json;from kirabridge.bridge_core.bridge import INPUTS;"
        "print(json.dumps(list(INPUTS)))"
    )
    capabilities = json.loads(run([python(release), "-c", code], capture=True))
    capabilities += [
        "bridge.health",
        "task.read",
        "task.cancel",
        "agent.inspect",
        "message.send",
        "message.read",
        "message.ack",
        "session.inspect",
    ]
    import secrets

    tokens = {name: secrets.token_urlsafe(48) for name in ("local", "chatgpt")}
    text = (
        f"data_dir = {json.dumps(str(data))}\n"
        f"credentials_file = {json.dumps(str(credentials))}\n"
        'host = "127.0.0.1"\nport = 8765\nallow_remote = false\n'
    )
    for name in tokens:
        text += (
            f'\n[principals.{name}]\napproval_mode = "automatic"\n'
            'permission_level = "full"\n'
            + ('automatic_operations = ["session.input"]\n' if name == "chatgpt" else "")
            + f"capabilities = {json.dumps(capabilities)}\n"
            'roots = ["/"]\nread_roots = ["/"]\nterminal_roots = ["/"]\n'
            "allow_any_executable = true\nexecutables = []\nagents = []\n"
            f'token_env = "KIRABRIDGE_{name.upper()}_TOKEN"\n'
        )
    text += (
        "\n[terminal]\nsearch_path = "
        + json.dumps(
            [
                str(Path.home() / ".local/bin"),
                "/usr/local/bin",
                "/opt/homebrew/bin",
                "/usr/bin",
                "/bin",
                "/usr/sbin",
                "/sbin",
            ]
        )
        + "\nhome = "
        + json.dumps(str(Path.home()))
        + "\n"
    )
    jwrite(credentials, tokens)
    atomic(args.config, text)
    say(
        "Neue lokale Vollzugriffs-Konfiguration erstellt; Zugangsdaten nicht ausgegeben. "
        "ChatGPT-Kontoverbindung separat erforderlich."
    )


def loaded(args):
    if args.service == "none":
        return False
    return (
        subprocess.run(
            ["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"], capture_output=True, timeout=10
        ).returncode
        == 0
    )


def stop_service(args):
    if loaded(args):
        run(["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"], capture=True, timeout=20)


def start_service(args):
    if args.service != "none" and args.plist.exists():
        run(["launchctl", "bootstrap", f"gui/{os.getuid()}", args.plist], capture=True, timeout=20)


def wait_health(args, release, version):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            health = cli(release, args.config, "status", timeout=8)
            if (
                health.get("version") == version
                and health.get("dispatcher_active")
                and health.get("runtime", {}).get("config_sha256") == sha(args.config)
            ):
                return health
        except (RuntimeError, subprocess.TimeoutExpired, ValueError):
            pass
        time.sleep(0.5)
    raise RuntimeError("New daemon readiness not proven within 30 seconds")


def validate_service_owner(args):
    if args.service == "none" or not args.plist.exists():
        return
    previous = plistlib.loads(args.plist.read_bytes())
    argv = previous.get("ProgramArguments", [])
    if (
        previous.get("Label") != LABEL
        or str(args.config) not in argv
        or "serve" not in argv
        or "kirabridge.cli" not in argv
    ):
        raise RuntimeError("Existing service is not the expected KiraBridge config; left untouched")


def snapshot_file(path, backup, name):
    if path.is_symlink():
        raise RuntimeError(f"Symlink file refused: {path}")
    if path.exists():
        atomic(backup / name, path.read_bytes(), path.stat().st_mode & 0o777)
        return True
    return False


def activate(args, release):
    fresh_config(args, release)
    validate_service_owner(args)
    config_before = args.config.read_bytes()
    config = settings(args.config)
    credentials = Path(config["credentials_file"]) if config.get("credentials_file") else None
    credential_hash = sha(credentials) if credentials else None
    current = args.prefix / "current.json"
    old = json.loads(current.read_text()) if current.exists() else None
    manifest = json.loads((release / "release.json").read_text())
    if old and old["release"] == str(release):
        say("Diese Version ist bereits aktiviert. Keine Dienste neu gestartet.")
        return
    backup = args.prefix / "backups" / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
    private_dir(backup)
    had_wrapper = snapshot_file(args.launcher, backup, "launcher.before")
    had_plist = (
        snapshot_file(args.plist, backup, "service.before.plist")
        if args.service != "none"
        else False
    )
    atomic(backup / "config.before.toml", config_before)
    if credentials:
        snapshot_file(credentials, backup, "credentials.before.json")
    was_loaded = loaded(args)
    previous_health = None
    if args.service != "none":
        try:
            previous_health = cli(release, args.config, "status", timeout=8)
        except (RuntimeError, subprocess.TimeoutExpired, ValueError):
            if was_loaded:
                raise RuntimeError("Existing service health unavailable; no switch") from None
        if previous_health and not was_loaded:
            raise RuntimeError("Backend runs outside expected launchd service; no switch")
    before = {
        "previous": old,
        "release": str(release),
        "backup": str(backup),
        "had_wrapper": had_wrapper,
        "had_plist": had_plist,
        "was_loaded": was_loaded,
        "previous_version": (previous_health or {}).get("version"),
        "config": str(args.config),
        "launcher": str(args.launcher),
        "plist": str(args.plist),
        "service": args.service,
        **manifest,
    }
    jwrite(backup / "transaction.json", before)
    say(f"Rückweg gesichert: {backup}. Konfiguration und Zugangsdaten bleiben erhalten.")
    try:
        with idle_guard(args.config):
            dbpath = state_file(args.config)
            if dbpath.exists():
                with (
                    sqlite3.connect(f"file:{dbpath}?mode=ro", uri=True) as reader,
                    sqlite3.connect(backup / "bridge.before.sqlite3") as writer,
                ):
                    reader.backup(writer)
            if args.config.read_bytes() != config_before or (
                credentials and sha(credentials) != credential_hash
            ):
                raise RuntimeError(
                    "Configuration/credentials changed during preparation; no switch"
                )
            jwrite(current, before)  # Durable recovery record before any switch.
            stop_service(args)
            wrapper = (
                "#!/bin/sh\nexec "
                + shlex.quote(str(python(release)))
                + " -m kirabridge.cli --config "
                + shlex.quote(str(args.config))
                + ' "$@"\n'
            )
            atomic(args.launcher, wrapper, 0o700)
            if args.service != "none":
                plist = (
                    plistlib.loads((backup / "service.before.plist").read_bytes())
                    if had_plist
                    else {
                        "Label": LABEL,
                        "RunAtLoad": True,
                        "KeepAlive": {"SuccessfulExit": False},
                        "ThrottleInterval": 3,
                        "Umask": 0o077,
                        "EnvironmentVariables": {"HOME": str(Path.home()), "PATH": os.defpath},
                    }
                )
                plist["ProgramArguments"] = [
                    str(python(release)),
                    "-m",
                    "kirabridge.cli",
                    "--config",
                    str(args.config),
                    "serve",
                    "--transport",
                    "http",
                ]
                logs = args.prefix / "logs"
                private_dir(logs)
                plist.setdefault("StandardOutPath", str(logs / "service.stdout.log"))
                plist.setdefault("StandardErrorPath", str(logs / "service.stderr.log"))
                atomic(args.plist, plistlib.dumps(plist))
            before["installed_wrapper_sha256"] = sha(args.launcher)
            if args.service != "none":
                before["installed_plist_sha256"] = sha(args.plist)
            jwrite(current, before)
            start_service(args)
        if args.service != "none":
            health = wait_health(args, release, manifest["version"])
            say(f"Dienst gestartet: Version {health['version']}, PID {health['runtime']['pid']}.")
    except Exception:
        if current.exists() and json.loads(current.read_text()).get("backup") == str(backup):
            say("Umschaltung fehlgeschlagen. Rückweg wird unter erneuter Leerlaufprüfung versucht.")
            rollback(args)
        raise
    assert args.config.read_bytes() == config_before, "Configuration changed"
    assert not credentials or sha(credentials) == credential_hash, "Credentials changed"
    say(
        f"INSTALLIERT: {manifest['version']} @ {manifest['commit']}. "
        "Rechte und Zugangsdaten erhalten."
    )


def rollback(args):
    current = args.prefix / "current.json"
    if not current.exists():
        raise RuntimeError("No activated version/recovery record")
    active = json.loads(current.read_text())
    for key in ("config", "launcher", "plist", "service"):
        if str(getattr(args, key)) != active[key]:
            raise RuntimeError("Rollback arguments differ from activation; no switch")
    validate_service_owner(args)
    backup = Path(active["backup"])
    for path, key in [
        (args.launcher, "installed_wrapper_sha256"),
        (args.plist, "installed_plist_sha256"),
    ]:
        if active.get(key) and (not path.exists() or sha(path) != active[key]):
            raise RuntimeError(
                "Installed definition changed since activation; preserve and review first"
            )
    with idle_guard(args.config):
        stop_service(args)
        for path, flag, name in [
            (args.launcher, "had_wrapper", "launcher.before"),
            (args.plist, "had_plist", "service.before.plist"),
        ]:
            if path == args.plist and args.service == "none":
                continue
            if active[flag]:
                saved = backup / name
                atomic(path, saved.read_bytes(), saved.stat().st_mode & 0o777)
            else:
                path.unlink(missing_ok=True)
        if active["previous"]:
            jwrite(current, active["previous"])
        else:
            current.unlink()
        if active["was_loaded"]:
            start_service(args)
    if active["was_loaded"] and active.get("previous_version"):
        wait_health(args, Path(active["release"]), active["previous_version"])
    say(
        "ZURÜCKGEROLLT: vorheriger Launcher/Dienst wiederhergestellt. "
        "Konfiguration, Zugangsdaten und neue Ergebnisdaten bleiben erhalten."
    )


def status(args):
    current = args.prefix / "current.json"
    if not current.exists():
        say(json.dumps({"installed_by_versioned_installer": False}))
        return
    active = json.loads(current.read_text())
    result = {k: active[k] for k in ("version", "commit", "release")}
    result["config_sha256"] = sha(args.config)
    result["service_managed"] = args.service != "none"
    if args.service != "none":
        result["daemon"] = cli(Path(active["release"]), args.config, "status")
    say(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "install", "status", "rollback"])
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--ref")
    parser.add_argument(
        "--prefix", type=Path, default=Path.home() / ".local/share/kirabridge/install"
    )
    parser.add_argument(
        "--config", type=Path, default=Path.home() / ".config/kirabridge/config.toml"
    )
    parser.add_argument("--launcher", type=Path, default=Path.home() / ".local/bin/kirabridge")
    parser.add_argument(
        "--plist", type=Path, default=Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"
    )
    parser.add_argument(
        "--service",
        choices=["launchd", "none"],
        default="launchd" if sys.platform == "darwin" else "none",
    )
    parser.add_argument(
        "--cache-dir", type=Path, default=Path.home() / ".cache/kirabridge-installer"
    )
    parser.add_argument(
        "--full-access",
        action="store_true",
        help="Explicit operator grant for fresh config only; never modifies an existing policy",
    )
    args = parser.parse_args()
    for name in ("repo", "prefix", "config", "launcher", "plist", "cache_dir"):
        setattr(args, name, getattr(args, name).expanduser().absolute())
    if sys.version_info < (3, 11):
        parser.error("Python 3.11+ is required")

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    os.umask(0o077)
    private_dir(args.prefix)
    fd = os.open(args.prefix / "install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action in ("prepare", "install"):
            release = prepare(args)
            if args.action == "install":
                activate(args, release)
        elif args.action == "rollback":
            rollback(args)
        else:
            status(args)
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        say(
            "ABGEBROCHEN: eigene Build-Unterprozesse gestoppt; Rückweg steht im Transaktionsbackup."
        )
        sys.exit(130)
    except Exception as exc:
        say(f"FEHLER: {exc}")
        sys.exit(1)
