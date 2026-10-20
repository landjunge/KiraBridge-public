"""Read-only prerequisites for one authenticated identity, never a workflow certificate."""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pydantic import Field

from kirabridge import __version__
from kirabridge.bridge_core.config import Config
from kirabridge.bridge_core.models import BridgeError, Input, digest
from kirabridge.filesystem_manager import PathScope
from kirabridge.permissions import state_exclusions
from kirabridge.terminal_manager import check_executable


class ReadinessInput(Input):
    read_paths: list[str] = Field(default_factory=list, max_length=16)
    image_paths: list[str] = Field(default_factory=list, max_length=16)
    working_directories: list[str] = Field(default_factory=list, max_length=16)
    executables: list[str] = Field(default_factory=list, max_length=16)
    operations: list[str] = Field(default_factory=list, max_length=16)
    workflow_id: str | None = Field(default=None, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")


def runtime_snapshot(config: Config) -> dict:
    # Capture once on daemon construction; editing the installed tree does not change
    # this assertion about the source tree observed at startup.
    root = Path(__file__).parent
    manifest = {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*.py"))
    }
    config._effective_sha256 = digest(config.model_dump())
    return {
        "instance_id": uuid.uuid4().hex,
        "version": __version__,
        "pid": os.getpid(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "config_path": config._source_path,
        "config_sha256": config._source_sha256,
        "effective_config_sha256": config._effective_sha256,
        "source_tree_sha256": digest(manifest),
        "source_file_count": len(manifest),
        "source_package_path": str(root),
        "source_scope": "package Python files observed at startup; no remote attestation",
    }


def _probe(action) -> dict:
    try:
        action()
        return {"ok": True, "code": "available"}
    except BridgeError as exc:
        return {"ok": False, "code": exc.code}
    except FileNotFoundError:
        return {"ok": False, "code": "path_missing"}
    except OSError:
        return {"ok": False, "code": "path_unavailable"}


def _file(scope: PathScope, path: str) -> None:
    # Same descriptor/no-follow boundary as file.read; inspect regularity/access,
    # without returning contents or writing an audit/task/queue entry.
    with scope.parent(path) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise BridgeError("file_type", "Only regular files can be read")
        finally:
            os.close(fd)


def _directory(scope: PathScope, path: str) -> None:
    with scope.directory(path):
        pass


def readiness(bridge, principal: str, requirements: ReadinessInput) -> dict:
    policy = bridge.security.principal(principal, "bridge.health")
    scope = PathScope(
        policy.roots + policy.read_roots, excluded=state_exclusions(bridge.config, policy)
    )

    def file(path):
        bridge.security.principal(principal, "file.read")
        _file(scope, path)

    def image(path):
        bridge.security.principal(principal, "file.image")
        _file(scope, path)

    def directory(path):
        if not {"file.read", "file.image", "file.list"}.intersection(policy.capabilities):
            raise BridgeError("forbidden", "File capability not granted")
        _directory(scope, path)

    def executable(path):
        bridge.security.principal(principal, "terminal.execute")
        check_executable(
            path,
            policy.executables,
            policy.allow_any_executable,
            bridge.terminal.environment["PATH"],
        )

    def working_directory(path):
        bridge.security.principal(principal, "terminal.execute")
        _directory(PathScope(policy.terminal_roots or policy.roots), path)

    def operation(name):
        from kirabridge.bridge_core.bridge import INPUTS

        if name not in INPUTS:
            raise BridgeError("unknown_operation", "Unknown operation")
        bridge.security.principal(principal, name)
        if name == "workflow.stop":
            bridge.security.principal(principal, "task.cancel")
            bridge.security.principal(principal, "process.terminate")
        if name.startswith(("threaddesk.", "handoff.")) and name != "handoff.status":
            bridge.threaddesk.check_configuration()
        if name in {"clipboard.read", "clipboard.write"}:
            bridge.clipboard.platform.clipboard_command(write=name == "clipboard.write")

    paths = [{"path": p, **_probe(lambda p=p: file(p))} for p in requirements.read_paths]
    images = [{"path": p, **_probe(lambda p=p: image(p))} for p in requirements.image_paths]
    programs = [{"path": p, **_probe(lambda p=p: executable(p))} for p in requirements.executables]
    working_dirs = [
        {"path": p, **_probe(lambda p=p: working_directory(p))}
        for p in requirements.working_directories
    ]
    operations = [
        {"operation": p, **_probe(lambda p=p: operation(p))} for p in requirements.operations
    ]
    for item in operations:
        if item["operation"] == "workflow.stop" and item["ok"]:

            def barrier_prerequisites():
                if bridge.workflow_control is None:
                    raise BridgeError("workflow_control_unavailable", "Control disabled")
                if checker := getattr(bridge.workflow_control, "check_configuration", None):
                    checker()

            item["owned_abort_available"] = True
            item["durable_barrier_prerequisites"] = _probe(barrier_prerequisites)
            item["barrier_confirmed"] = False
    roots = [
        {"path": p, **_probe(lambda p=p: directory(p))}
        for p in dict.fromkeys(policy.roots + policy.read_roots)
    ]
    health = bridge.health(principal)
    requested = bool(paths or images or programs or operations or working_dirs)
    checks = paths + images + programs + operations + working_dirs
    result = {
        "principal": principal,
        "runtime": bridge.runtime,
        "dispatcher_active": health["dispatcher_active"],
        "approval_mode": policy.approval_mode,
        "roots": policy.roots,
        "read_roots": policy.read_roots,
        "allowed_executables": policy.executables,
        "allow_any_executable": policy.allow_any_executable,
        "terminal_roots": policy.terminal_roots or policy.roots,
        "root_checks": roots,
        "read_path_checks": paths,
        "image_path_checks": images,
        "executable_checks": programs,
        "working_directory_checks": working_dirs,
        "operation_checks": operations,
        "workflow_id": requirements.workflow_id,
        "requested_prerequisites_ready": (
            health["dispatcher_active"] and all(x["ok"] for x in checks)
        )
        if requested
        else None,
        "scope": "Only requested prerequisites at this instant; no process is started, no file "
        "content is returned. No complete workflow, tunnel, ChatGPT, or future success claim. "
        "automatic approval does not extend roots or executable permissions.",
        "remediation": "path_denied: use file.read inside configured roots/read_roots; "
        "missing roots/config drift: local operator must correct policy and reload safely. "
        "executable_denied: use file tools for file access; no interpreter workaround.",
    }
    if requested and not result["requested_prerequisites_ready"]:
        from kirabridge.diagnostics import rejection_report

        failures = [x for x in checks if not x["ok"]]
        code = failures[0]["code"] if failures else "dispatcher_unavailable"
        result["diagnostic"] = rejection_report(
            bridge.runtime,
            "workflow.preflight",
            code,
            workflow_id=requirements.workflow_id,
        )
    if requirements.workflow_id:
        from kirabridge.diagnostics import AuditObserver, compact_checks

        observer = AuditObserver(bridge.config, principal, bridge.runtime, bridge.store)
        result["audit_recorded"] = observer(
            "workflow.preflight",
            {
                "workflow_id": requirements.workflow_id,
                "checks": compact_checks(checks),
                "outcome": "ready" if result["requested_prerequisites_ready"] else "not_ready",
            },
        )
        result["audit_storage"] = observer.status()
        if not result["audit_recorded"]:
            from kirabridge.diagnostics import rejection_report

            result["requested_prerequisites_ready"] = False
            result["diagnostic"] = rejection_report(
                bridge.runtime,
                "workflow.preflight",
                "diagnostic_recording_unavailable",
                workflow_id=requirements.workflow_id,
            )
    return result


def task_preflight(bridge, task: dict) -> dict:
    """Actual task prerequisites, before any content access or process start.

    The real manager still repeats its descriptor/permission checks at use time.
    No change to request hashes, grants, task states or historical idempotency.
    """
    from kirabridge.diagnostics import compact_checks, runtime_ref

    operation, args, principal = task["operation"], task["args"], task["principal"]
    from kirabridge.operations import OPERATIONS

    permission = bridge.security.authorize(principal, operation, text=args.get("text"))
    policy = bridge.security.principal(principal, operation)
    roots = policy.roots + (
        policy.read_roots if operation in {"file.read", "file.image", "file.list"} else []
    )
    scope = PathScope(roots, excluded=state_exclusions(bridge.config, policy))
    checks = []

    def check(kind, path, action):
        checks.append({"kind": kind, "path": path, **_probe(action)})

    if operation in {"file.read", "file.image"}:
        check("read_path", args["path"], lambda: _file(scope, args["path"]))
    elif operation == "file.list":
        check("directory", args["path"], lambda: _directory(scope, args["path"]))
    elif operation.startswith("file."):
        for path in [args["path"]] + ([args["destination"]] if operation == "file.move" else []):

            def parent(path=path):
                with scope.parent(path):
                    pass

            check("mutation_parent", path, parent)
    elif operation == "workflow.stop":

        def owned_control():
            from kirabridge.workflow_control_adapter import validate_owned_stop

            validate_owned_stop(
                bridge, principal, args["handoff_id"], args["revision"], args["stop_id"]
            )

        check("workflow_control", "owned_project_control", owned_control)
    elif operation.startswith(("threaddesk.", "handoff.")) and operation != "handoff.status":
        check("threaddesk_endpoint", "configured_threaddesk", bridge.threaddesk.check_configuration)
        if operation == "handoff.start":
            if selector := getattr(bridge.workflow_control, "select", None):
                check(
                    "workflow_control",
                    "configured_project",
                    lambda: selector({"cwd": args["cwd"]}),
                )
            check(
                "agent_workflow",
                args.get("agent", "codex"),
                lambda: bridge.handoffs.agent_preflight(
                    principal, args.get("agent", "codex"), args["cwd"]
                ),
            )
        elif operation == "handoff.answer":

            def waiting_agent():
                binding = bridge.handoffs.get(principal, args["handoff_id"], args["revision"])
                if selector := getattr(bridge.workflow_control, "select", None):
                    selector(binding)
                bridge.handoffs.agent_preflight(principal, binding["agent"], binding["cwd"])

            check("agent_workflow", "owned_waiting_session", waiting_agent)
    elif operation in {"terminal.execute", "admin.execute", "agent.execute"}:
        if operation in {"terminal.execute", "admin.execute"}:
            executable = args["argv"][0]
            check(
                "executable",
                executable,
                lambda: check_executable(
                    executable,
                    policy.executables,
                    policy.allow_any_executable,
                    bridge.terminal.environment["PATH"],
                ),
            )
        else:

            def agent():
                if args["agent"] not in policy.agents:
                    raise BridgeError("agent_denied", "Agent identity not granted")
                configured = bridge.config.agents.get(args["agent"])
                if configured is None or configured.kind not in bridge.agents.adapters:
                    raise BridgeError("agent_unavailable", "Agent adapter is not configured")
                if configured.kind != "grok_api":
                    if not configured.executable:
                        raise BridgeError("agent_config", "Agent executable is not configured")
                    check_executable(configured.executable, [configured.executable])

            check("agent", args["agent"], agent)
        cwd_scope = (
            PathScope(policy.terminal_roots or policy.roots)
            if operation != "agent.execute"
            else scope
        )
        check("cwd", args["cwd"], lambda: _directory(cwd_scope, args["cwd"]))
    return {
        "ready": all(c["ok"] for c in checks),
        "checks": compact_checks(checks),
        "operation": operation,
        "operation_properties": OPERATIONS[operation].describe(),
        "permission_decision": permission,
        "runtime": runtime_ref(bridge.runtime),
    }
