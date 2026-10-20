"""Fixed operator project mapping for optional owned CLI stop control."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

from kirabridge.bridge_core.models import BridgeError, digest


def package_fingerprint(root):
    """Bounded source observation, before importing an optional package."""
    manifest, total, examined = {}, 0, 0
    started = time.monotonic()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in dirs + files:
            examined += 1
            path = Path(directory) / name
            if examined > 4096 or path.is_symlink() or time.monotonic() - started > 2:
                raise ValueError("source inspection unavailable")
            if path.suffix != ".py" or not path.is_file():
                continue
            if path.stat().st_size > 524288:
                raise ValueError("source file limit")
            with path.open("rb") as stream:
                raw = stream.read(524289)
            total += len(raw)
            if len(raw) > 524288 or total > 8388608:
                raise ValueError("source byte limit")
            manifest[str(path.relative_to(root))] = hashlib.sha256(raw).hexdigest()
    if not manifest:
        raise ValueError("source package unavailable")
    return digest(manifest)


class ConfiguredWorkflowControl:
    def __init__(self, bridge):
        self.bridge = bridge
        self.settings = bridge.config.workflow_control
        self.error = None
        self.adapters, self.roots = {}, []
        self.source = {}
        try:
            self.initialize()
        except Exception:
            # An unavailable optional assembly blocks controlled work, not health,
            # historical reads or the entire operator service. No exception text.
            self.error = "workflow_control_unavailable"

    def initialize(self):
        from kirabridge.workflow_control_adapter import WorkflowControlAdapter

        if (
            not self.settings.projects
            or not self.settings.source_commit
            or not self.settings.source_package_sha256
        ):
            raise ValueError("explicit project registry and source pin required")
        spec = importlib.util.find_spec("tollgate")
        if (
            spec is None
            or not spec.submodule_search_locations
            or len(spec.submodule_search_locations) != 1
        ):
            raise ValueError("installed source package required")
        self.package_root = Path(next(iter(spec.submodule_search_locations))).resolve(strict=True)
        if package_fingerprint(self.package_root) != self.settings.source_package_sha256:
            raise ValueError("installed source differs from approved package")
        from tollgate import workflow_control as module

        if Path(module.__file__).resolve().parent != self.package_root or not hasattr(
            module.WorkflowControl, "control_identity"
        ):
            raise ValueError("stable journal identity required")
        roots = {}
        for project, paths in self.settings.projects.items():
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", project) or not 1 <= len(paths) <= 128:
                raise ValueError("invalid project registry")
            for value in paths:
                path = Path(value)
                if not path.is_absolute() or (path.exists() and not path.is_dir()):
                    raise ValueError("project root unavailable")
                # Retired/renamed worktrees must not disable other projects or
                # the stored journal scope needed to stop their existing runs.
                # New turns still require the actual CWD/root identity below.
                root = path.resolve(strict=False)
                if root in {Path(root.anchor), Path.home()}:
                    raise ValueError("project root too broad")
                if root in roots and roots[root] != project:
                    raise ValueError("ambiguous project root")
                roots[root] = project
        state_root = (
            Path(self.settings.state_root).expanduser()
            if self.settings.state_root
            else self.bridge.config.state_path / "workflow-control"
        )
        if not state_root.is_absolute():
            raise ValueError("absolute control state required")
        self.state_root = state_root
        control = module.WorkflowControl(
            root=state_root,
            registered_process_actors={self.settings.actor_id: self.settings.consumer_id},
        )
        self.adapters = {
            project: WorkflowControlAdapter(
                self.bridge,
                control,
                project_id=project,
                actor_id=self.settings.actor_id,
                consumer_id=self.settings.consumer_id,
            )
            for project in self.settings.projects
        }
        self.roots = sorted(roots.items(), key=lambda item: len(item[0].parts), reverse=True)
        # This fingerprint observes loaded module bytes. The configured Git pin is
        # an operator claim, not independent source/remote identity attestation.
        self.source = {
            "configured_source_commit": self.settings.source_commit,
            "workflow_module_sha256": hashlib.sha256(
                Path(module.__file__).read_bytes()
            ).hexdigest(),
            "source_authenticated": False,
            "source_package_sha256": self.settings.source_package_sha256,
        }

    def check_configuration(self):
        if self.error:
            raise BridgeError(self.error, "Pinned TollGate/project assembly unavailable")
        try:
            if package_fingerprint(self.package_root) != self.settings.source_package_sha256:
                raise ValueError("source drift")
            parent = self.state_root
            while not parent.exists():
                if parent.is_symlink():
                    raise ValueError("unsafe state root")
                parent = parent.parent
            if (
                parent.is_symlink()
                or not parent.is_dir()
                or not os.access(parent, os.W_OK | os.X_OK)
            ):
                raise ValueError("state permissions unavailable")
        except (OSError, ValueError):
            raise BridgeError(
                "workflow_control_unavailable", "Source/state prerequisites unavailable"
            ) from None

    def assembly_identity(self, project, metadata):
        adapter = self.adapters[project]
        identity = adapter.control.control_identity(adapter.scope(metadata))
        return digest(
            {
                "project_id": project,
                "journal_id": identity["journal_id"],
                "state_root_ref": digest(str(self.state_root.resolve())),
                "actor_id": self.settings.actor_id,
                "consumer_id": self.settings.consumer_id,
                "source_package_sha256": self.settings.source_package_sha256,
                "mode": self.settings.mode,
            }
        ), identity["journal_id"]

    def bound_project(self, metadata):
        self.check_configuration()
        if previous := metadata.get("control_project_id"):
            if previous not in self.adapters:
                raise BridgeError("workflow_project_changed", "Bound project is not configured")
            return previous
        return self.select(metadata)

    def select(self, metadata):
        self.check_configuration()
        try:
            cwd = Path(metadata["cwd"]).resolve(strict=True)
        except (OSError, KeyError, ValueError):
            raise BridgeError("workflow_project_unavailable", "Owned project unavailable") from None
        selected = next((project for root, project in self.roots if cwd.is_relative_to(root)), None)
        if selected is None:
            raise BridgeError(
                "workflow_project_unconfigured", "Project has no configured control scope"
            )
        previous = metadata.get("control_project_id")
        if previous is not None and previous != selected:
            raise BridgeError(
                "workflow_project_changed", "Previously controlled project mapping changed"
            )
        return selected

    @asynccontextmanager
    async def bind_turn(self, task, metadata):
        from kirabridge.workflow_control_adapter import _finish_thread, stop_observation

        stored = self.bridge.handoffs.get(
            task["principal"], metadata["handoff_id"], metadata["revision"]
        )
        if stop_observation(self.bridge.store, stored).get("control_mode") in {
            "stop_only",
            "abort_only",
        }:
            raise BridgeError("workflow_stopped", "An owned stop intent blocks further turns")
        project = self.select(stored)
        cwd = Path(stored["cwd"]).resolve(strict=True)
        root = next(
            root for root, owner in self.roots if owner == project and cwd.is_relative_to(root)
        )
        cwd_info, root_info = cwd.stat(), root.stat()
        location = digest(
            [
                str(cwd),
                cwd_info.st_dev,
                cwd_info.st_ino,
                str(root),
                root_info.st_dev,
                root_info.st_ino,
            ]
        )
        if (
            stored.get("control_project_id") is not None
            and stored.get("control_cwd_ref") != location
        ):
            raise BridgeError(
                "workflow_project_changed", "Previously bound project directory changed"
            )
        metadata["control_cwd_ref"] = location
        if metadata.get("control_project_id") not in {None, project}:
            raise BridgeError("workflow_project_changed", "Turn has a different project scope")
        metadata["control_project_id"] = project
        assembly, journal_id = await _finish_thread(self.assembly_identity, project, stored)
        self.bridge.handoffs.ensure_not_stopped(
            task["principal"], metadata["handoff_id"], metadata["revision"]
        )
        if stored.get("control_assembly_ref") not in {None, assembly}:
            raise BridgeError(
                "workflow_assembly_changed", "Previously bound journal or assembly changed"
            )
        if stored.get("control_project_id") is not None and not stored.get("control_assembly_ref"):
            raise BridgeError(
                "workflow_assembly_unknown", "Previously bound journal identity is unknown"
            )
        metadata["control_assembly_ref"] = assembly
        metadata["control_journal_id"] = journal_id
        metadata["control_source"] = self.source
        with self.adapters[project].bind_turn(task, metadata):
            yield

    async def stop(self, principal, handoff_id, revision, stop_id, *, task_id=None):
        from kirabridge.workflow_control_adapter import (
            _finish_thread,
            owned_stop,
            record_owned_stop_request,
            validate_owned_stop,
        )

        metadata = validate_owned_stop(
            self.bridge, principal, handoff_id, revision, stop_id, task_id=task_id
        )
        record_owned_stop_request(self.bridge, metadata, stop_id, task_id=task_id)
        try:
            project = self.bound_project(metadata)
            assembly, journal_id = await _finish_thread(self.assembly_identity, project, metadata)
            if metadata.get("control_assembly_ref") not in {None, assembly}:
                raise BridgeError(
                    "workflow_assembly_changed", "Previously bound journal or assembly changed"
                )
            if metadata.get("control_project_id") is not None and not metadata.get(
                "control_assembly_ref"
            ):
                raise BridgeError(
                    "workflow_assembly_unknown", "Previously bound journal identity is unknown"
                )
            with self.bridge.store.transaction():
                current = self.bridge.handoffs.get(principal, handoff_id, revision)
                if current.get("control_assembly_ref") not in {None, assembly}:
                    raise BridgeError("workflow_assembly_changed", "Stop journal binding changed")
                current.update(
                    control_project_id=project,
                    control_assembly_ref=assembly,
                    control_journal_id=journal_id,
                )
                self.bridge.handoffs.save(current, task_id=task_id, event="handoff.control_scope")
        except Exception:
            return await owned_stop(
                self.bridge,
                principal,
                handoff_id,
                revision,
                stop_id,
                task_id=task_id,
                barrier={
                    "status": "UNKNOWN",
                    "further_dispatch_blocked": False,
                    "abort_confirmed": False,
                },
                control_error="workflow_control_unavailable",
            )
        # Do not rewrite old standalone runs as previously gated. The actual stop
        # audit records the new barrier; the old turn's provenance stays intact.
        return await self.adapters[project].stop(
            principal, handoff_id, revision, stop_id, task_id=task_id
        )


def configured_workflow_control(bridge):
    if not bridge.config.workflow_control.enabled:
        return None
    return ConfiguredWorkflowControl(bridge)
