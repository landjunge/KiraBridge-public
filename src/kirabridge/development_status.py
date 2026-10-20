"""Bounded metadata views, never an attach/terminate or configuration endpoint."""

from __future__ import annotations

import asyncio
import hashlib
import os
import stat
import sys
import time
from pathlib import Path

from kirabridge.bridge_core.models import digest
from kirabridge.permissions import permission_summary

PS_BYTE_LIMIT = 65536
PS_RECORD_LIMIT = 256
PS_TIMEOUT = 3.0
TASK_LIMIT = 100
CONFIG_BYTE_LIMIT = 1048576
SOURCE_BYTE_LIMIT = 8388608
SOURCE_FILE_LIMIT = 256

# Exact executable names only. Node/Python/shell arguments must never be inspected
# to infer which agent they might host. Names are observation, not verified identity.
AGENT_NAMES = {"codex": "codex", "grok": "grok"}
HOST_NAMES = frozenset(
    {
        "Codex",
        "Codex Helper",
        "Codex Helper (Renderer)",
        "Codex Helper (GPU)",
        "Grok",
        "ChatGPT",
        "Terminal",
        "iTerm2",
        "ghostty",
        "wezterm-gui",
        "alacritty",
    }
)
RUNTIME_KEYS = (
    "instance_id",
    "version",
    "pid",
    "started_at",
    "config_path",
    "config_sha256",
    "effective_config_sha256",
    "source_tree_sha256",
    "source_file_count",
    "source_package_path",
    "source_scope",
)


def _runtime_metadata(runtime: dict) -> dict:
    return {
        key: runtime.get(key)
        for key in RUNTIME_KEYS
        if runtime.get(key) is None or isinstance(runtime.get(key), (str, int, float, bool))
    }


def _parse_processes(raw: bytes, uid: int, excluded_pids: set[int] | None = None) -> dict:
    """Parse only UID/PID/PPID/comm, rejecting malformed and foreign-UID rows."""
    truncated = len(raw) > PS_BYTE_LIMIT
    bounded = raw[:PS_BYTE_LIMIT]
    if truncated and not bounded.endswith(b"\n"):
        bounded = bounded.rsplit(b"\n", 1)[0]
    candidates, parents = [], {}
    for line in bounded.decode("utf-8", "replace").splitlines():
        columns = line.strip().split(None, 3)
        if len(columns) != 4:
            continue
        owner, pid_text, parent_text, comm = columns
        if not all(
            part.isascii() and part.isdecimal() and len(part) <= 10
            for part in (owner, pid_text, parent_text)
        ):
            continue
        if int(owner) != uid:
            continue
        pid, ppid = int(pid_text), int(parent_text)
        if not 0 < pid < 2**31 or not 0 <= ppid < 2**31:
            continue
        parents[pid] = ppid
        if len(comm) > 4096 or any(ord(char) < 32 for char in comm):
            continue
        name = comm.rsplit("/", 1)[-1]
        if name not in AGENT_NAMES and name not in HOST_NAMES:
            continue
        candidates.append(
            {
                "pid": pid,
                "ppid": ppid,
                # Do not export the containing directory, command arguments or env.
                "comm": name,
                "name": name,
                "kind": "agent_cli" if name in AGENT_NAMES else "interactive_host",
                "agent": AGENT_NAMES.get(name),
                "ownership": "observed_only",
                "working_status": "unknown",
                "session_status": "unknown",
            }
        )
    excluded = set(excluded_pids or ())
    # Hide known other-principal process trees, including intermediary processes
    # whose names are deliberately not exposed in the observation result.
    for _ in range(len(parents)):
        children = {pid for pid, ppid in parents.items() if ppid in excluded}
        if children.issubset(excluded):
            break
        excluded.update(children)
    visible = [row for row in candidates if row["pid"] not in excluded]
    return {
        "processes": visible[:PS_RECORD_LIMIT],
        "truncated": truncated or len(visible) > PS_RECORD_LIMIT,
    }


async def _observe_processes(excluded_pids: set[int]) -> dict:
    if not hasattr(os, "getuid") or sys.platform not in {"darwin", "linux"}:
        return {"status": "unsupported", "processes": [], "truncated": False}
    executable = Path("/bin/ps")
    if sys.platform == "linux" and not executable.is_file():
        executable = Path("/usr/bin/ps")
    if not executable.is_file():
        return {"status": "unavailable", "processes": [], "truncated": False}
    process = None
    raw = bytearray()
    try:
        async with asyncio.timeout(PS_TIMEOUT):
            process = await asyncio.create_subprocess_exec(
                str(executable),
                "-U",
                str(os.getuid()),
                "-o",
                "uid=,pid=,ppid=,ucomm=" if sys.platform == "darwin" else "uid=,pid=,ppid=,comm=",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env={"PATH": os.defpath, "LC_ALL": "C"},
            )
            while len(raw) <= PS_BYTE_LIMIT:
                chunk = await process.stdout.read(min(8192, PS_BYTE_LIMIT + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > PS_BYTE_LIMIT:
                return {"status": "byte_limit", **_parse_processes(raw, os.getuid(), excluded_pids)}
            await process.wait()
            if process.returncode != 0:
                return {"status": "unavailable", "processes": [], "truncated": False}
        return {"status": "observed", **_parse_processes(raw, os.getuid(), excluded_pids)}
    except TimeoutError:
        return {"status": "timeout", "processes": [], "truncated": False}
    except OSError:
        return {"status": "unavailable", "processes": [], "truncated": False}
    finally:
        # This is only our own read-only ps child, never an observed agent/host.
        if process is not None and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=0.5)
            except TimeoutError:
                pass


async def agent_status(bridge, principal: str) -> dict:
    bridge.security.principal(principal, "agent.inspect")
    rows = bridge.store.db.execute(
        "SELECT id,operation,agent,parent_id,state,created,updated,accepted,started,finished "
        "FROM tasks WHERE principal=? "
        "AND state IN ('created','queued','accepted','running','unknown') "
        "ORDER BY updated DESC,id LIMIT ?",
        (principal, TASK_LIMIT + 1),
    ).fetchall()
    own_sessions, other_pids = [], set()
    for session in tuple(bridge.terminal.sessions.values()):
        if session.principal != principal:
            other_pids.add(session.process.pid)
            continue
        if len(own_sessions) < TASK_LIMIT:
            own_sessions.append(
                {
                    "task_id": session.task_id,
                    "pid": session.process.pid,
                    "alive": session.process.returncode is None,
                    "timed_out": session.timed_out,
                    "termination_requested": session.terminated,
                    "ownership": "bridge_managed",
                }
            )
    observation = await _observe_processes(other_pids)
    own_pids = {row["pid"] for row in own_sessions}
    for row in observation["processes"]:
        if row["pid"] in own_pids:
            row["ownership"] = "bridge_managed"
    from kirabridge.terminal_access import terminal_access

    access = terminal_access(bridge.config, principal)
    catalog = {"sessions": [], "status": "not_granted"}
    if access["discovery_allowed"]:
        try:
            catalog = await bridge.sessions.catalog(principal)
        except Exception as exc:
            catalog = {"sessions": [], "status": getattr(exc, "code", "discovery_failed")}
    access["availability"] = catalog["status"]
    access["catalog_observed_at"] = time.time()
    access["transport_errors"] = catalog.get("transport_errors", {})
    return {
        "principal": principal,
        "at": time.time(),
        "runtime": _runtime_metadata(bridge.runtime),
        "managed_tasks": [dict(row) for row in rows[:TASK_LIMIT]],
        "tasks_truncated": len(rows) > TASK_LIMIT,
        "managed_terminal_sessions": own_sessions,
        "managed_terminal_sessions_scope": "only child processes started by this bridge principal",
        "interactive_terminal_sessions": catalog["sessions"],
        "terminal_access": access,
        "observed_processes": observation.pop("processes"),
        "process_observation": {
            **observation,
            "own_os_uid_only": True,
            "byte_limit": PS_BYTE_LIMIT,
            "record_limit": PS_RECORD_LIMIT,
            "timeout_seconds": PS_TIMEOUT,
            "fields": ["pid", "ppid", "comm", "name"],
            "discovery_scope": "exact names only; generic interpreter children are not inferred",
        },
        "scope": "interactive sessions are catalog targets, not bridge-owned processes; "
        "catalog discovery does not read output or prove agent readiness",
        "project_completion_verified": False,
    }


def _file_hash(path: Path, max_bytes: int) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise OSError("unsupported metadata file")
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(fd, min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                return hashlib.sha256(data).hexdigest()
            data.extend(chunk)
        raise OSError("metadata file limit")
    finally:
        os.close(fd)


def _configuration_drift(config, runtime: dict) -> dict:
    path = config._source_path
    loaded = runtime.get("config_sha256")
    if not path:
        return {
            "status": "not_file_configured",
            "loaded_sha256": loaded,
            "disk_sha256": None,
            "changed_on_disk": None,
        }
    try:
        current = _file_hash(Path(path), CONFIG_BYTE_LIMIT)
    except OSError:
        return {
            "status": "unavailable",
            "loaded_sha256": loaded,
            "disk_sha256": None,
            "changed_on_disk": None,
        }
    changed = current != loaded if loaded is not None else None
    return {
        "status": "changed_on_disk" if changed else "matches_loaded" if loaded else "unknown",
        "loaded_sha256": loaded,
        "disk_sha256": current,
        "changed_on_disk": changed,
    }


def _source_drift(runtime: dict) -> dict:
    loaded = runtime.get("source_tree_sha256")
    manifest, total, count = {}, 0, 0
    root = Path(__file__).parent
    try:
        for directory, directories, files in os.walk(root, followlinks=False):
            count += 1
            if count > 512:
                raise OSError("source traversal limit")
            directories[:] = sorted(name for name in directories if name != "__pycache__")
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                path = Path(directory) / name
                total += path.lstat().st_size
                if total > SOURCE_BYTE_LIMIT or len(manifest) >= SOURCE_FILE_LIMIT:
                    raise OSError("source byte limit")
                manifest[str(path.relative_to(root))] = _file_hash(path, CONFIG_BYTE_LIMIT)
        current = digest(manifest)
    except OSError:
        return {
            "status": "unavailable",
            "loaded_sha256": loaded,
            "disk_sha256": None,
            "changed_on_disk": None,
        }
    changed = current != loaded if loaded is not None else None
    return {
        "status": "changed_on_disk" if changed else "matches_loaded" if loaded else "unknown",
        "loaded_sha256": loaded,
        "disk_sha256": current,
        "changed_on_disk": changed,
    }


def permissions_snapshot(bridge, principal: str) -> dict:
    policy = bridge.security.principal(principal, "bridge.health")
    terminal_roots = list(getattr(policy, "terminal_roots", []))
    profiles = []
    for name in policy.agents:
        agent = bridge.config.agents.get(name)
        if agent is not None:
            profiles.append(
                {
                    "name": name,
                    "kind": agent.kind,
                    "sandbox_mode": agent.sandbox_mode,
                    "executable": agent.executable,
                    "local_tools_available": agent.allow_local_tools,
                }
            )
    from kirabridge.terminal_access import terminal_access

    return {
        "principal": principal,
        "at": time.time(),
        "approval_mode": policy.approval_mode,
        "approval_required": policy.approval_mode == "manual",
        "permission_detail": permission_summary(bridge.config, principal),
        "session_input_policy": bridge.config.session_input_policy.model_dump(),
        "terminal_access": terminal_access(bridge.config, principal),
        "automatic_operations": policy.automatic_operations,
        "voice_messaging": bridge.config.voice_messaging.model_dump(),
        **bridge.messages.voice_channel.profile(principal),
        "capabilities": list(policy.capabilities),
        "roots": list(policy.roots),
        "read_roots": list(policy.read_roots),
        "executables": list(policy.executables),
        "allow_any_executable": bool(getattr(policy, "allow_any_executable", False)),
        "terminal_roots": terminal_roots,
        "effective_terminal_roots": terminal_roots or list(policy.roots),
        "allowed_agents": list(policy.agents),
        "agent_profiles": profiles,
        "config_path": bridge.config._source_path,
        "runtime": _runtime_metadata(bridge.runtime),
        "configuration_file": _configuration_drift(bridge.config, bridge.runtime),
        "source_files": _source_drift(bridge.runtime),
        "scope": "loaded local policy and metadata; no automatic grant or session attachment",
    }
