"""Bounded views of existing owned audit records; no Store, queue or runtime writes."""

from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import stat
import time
from datetime import datetime, timezone

from kirabridge.bridge_core.models import BridgeError, canonical, digest

EVENT_SCHEMA = "agent-authority-workflow-event-v1"
MAX_TASKS, MAX_ROWS, MAX_RECORD_BYTES, MAX_PAGE_BYTES = 16, 500, 4096, 65536
MAX_METADATA_BYTES = 16384
MAX_RESPONSE_BYTES = 262144
REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")
TASK_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
BINDINGS = (
    "project_id",
    "workflow_id",
    "thread_id",
    "handoff_id",
    "original_task_id",
    "bridge_task_id",
    "run_id",
    "attempt_id",
    "return_id",
    "recipient_id",
    "session_id",
    "principal_ref",
    "operator_scope",
    "binding_event_id",
    "control_ref",
    "consumer_id",
)
REVISIONS = ("handoff_revision", "source_revision", "task_revision")
STATES = {
    "accepted": "task.accepted",
    "running": "task.running",
    "completed": "task.completed",
    "failed": "task.failed",
    "unknown": "task.unknown",
    "cancelled": "task.cancelled",
}
HANDOFF_TYPES = {
    "handoff.bound": "handoff.bound",
    "handoff.agent_started": "task.started",
    "handoff.question": "task.question",
    "handoff.turn_ended": "task.completed",
    "handoff.delivered": "return.received",
    "handoff.decided": "return.reviewed",
}


def _error(code):
    return BridgeError(code, "Observation export unavailable; inspect bounded prerequisite codes")


def _ref(value):
    return type(value) is str and REF.fullmatch(value) is not None


def _hash(value):
    return type(value) is str and HASH.fullmatch(value) is not None


def _integer(value):
    return type(value) is int and 0 <= value < 2**63


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate metadata")
        result[key] = value
    return result


def _json(text):
    value = json.loads(text, object_pairs_hook=_unique)
    if type(value) is not dict:
        raise ValueError("invalid metadata")
    return value


def _private_db(config):
    directory = config.state_path
    path = directory / "bridge.sqlite3"
    try:
        for part in (path, *path.parents):
            if part.is_symlink():
                raise _error("unsafe_state")
        parent, info = directory.stat(), path.stat()
        if not stat.S_ISDIR(parent.st_mode) or not stat.S_ISREG(info.st_mode):
            raise _error("unsafe_state")
        if os.name != "nt" and (
            parent.st_uid != os.getuid()
            or info.st_uid != os.getuid()
            or parent.st_mode & 0o077
            or info.st_mode & 0o077
        ):
            raise _error("unsafe_state")
        for suffix in ("-wal", "-shm"):
            side = path.with_name(path.name + suffix)
            if side.is_symlink():
                raise _error("unsafe_state")
            if side.exists():
                side_info = side.stat()
                if not stat.S_ISREG(side_info.st_mode) or (
                    os.name != "nt"
                    and (side_info.st_uid != os.getuid() or side_info.st_mode & 0o077)
                ):
                    raise _error("unsafe_state")
    except OSError:
        raise _error("observation_state_unavailable") from None
    return path, (info.st_dev, info.st_ino)


def _runtime(row):
    preflight, seq = row["preflight"], row["preflight_seq"]
    if preflight is None:
        return {"basis": "unknown_no_prior_task_preflight"}
    try:
        record = _json(preflight)
        original = {
            "at": row["preflight_at"],
            "kind": "task.preflight",
            "principal": row["principal"],
            "task_id": row["task_id"],
            "metadata": record,
            "previous": row["preflight_previous"],
        }
        if not _hash(row["preflight_hash"]) or digest(original) != row["preflight_hash"]:
            return {"basis": "unknown_invalid_task_preflight"}
        runtime = record.get("runtime")
        if type(runtime) is not dict:
            return {"basis": "unknown_invalid_task_preflight"}
        result = {
            key: runtime[key]
            for key in ("config_sha256", "effective_config_sha256", "source_tree_sha256")
            if _hash(runtime.get(key))
        }
        for key in ("instance_id", "version"):
            if _ref(runtime.get(key)):
                result[key] = runtime[key]
        return {
            "basis": "existing_task_preflight_at_or_before_event",
            "audit_seq": seq,
            "fingerprints": result,
            "identity_authenticated": False,
        }
    except (ValueError, TypeError, RecursionError):
        return {"basis": "unknown_invalid_task_preflight"}


def _project(row, principal, source_id):
    if len(row["metadata"].encode()) > MAX_METADATA_BYTES:
        raise ValueError("audit_metadata_limit")
    metadata = _json(row["metadata"])
    if not _hash(row["hash"]) or not _hash(row["previous"]):
        raise ValueError("audit_hash_invalid")
    original = {key: row[key] for key in ("at", "kind", "principal", "task_id", "previous")}
    original["metadata"] = metadata
    if digest(original) != row["hash"]:
        raise ValueError("audit_hash_conflict")
    kind = row["kind"]
    event_type = HANDOFF_TYPES.get(kind)
    if kind == "task.accepted":
        event_type = "task.accepted"
    elif kind == "task.transition":
        event_type = STATES.get(metadata.get("to"))
    elif kind == "workflow.stop":
        # Only the actual scope barrier can establish EFFECTIVE; an owned abort
        # with missing assembly remains a request with unknown broader effect.
        event_type = {
            "EFFECTIVE": "control.stop_effective",
            "PENDING": "control.stop_pending",
            "UNKNOWN": "control.stop_requested",
        }.get(metadata.get("status"))
        if (
            metadata.get("status") == "EFFECTIVE"
            and metadata.get("further_dispatch_blocked") is not True
        ):
            event_type = "control.stop_requested"
    if event_type is None:
        return None, metadata
    at = row["at"]
    if type(at) not in (int, float) or not math.isfinite(at):
        raise ValueError("audit_timestamp_invalid")
    record = {
        "schema_version": EVENT_SCHEMA,
        "source_tool": "kirabridge",
        "source_id": source_id,
        "event_id": f"audit-{row['seq']}-{row['hash']}",
        "ordinal": row["seq"],
        "event_type": event_type,
        "timestamp": datetime.fromtimestamp(at, timezone.utc).isoformat(),
        "event_hash": row["hash"],
        "previous_event_hash": row["previous"],
        "task_id": row["task_id"],
        "bridge_task_id": row["task_id"],
        "principal_ref": digest(principal),
    }
    for key in BINDINGS:
        if _ref(metadata.get(key)):
            record[key] = metadata[key]
    for key in REVISIONS:
        if _integer(metadata.get(key)):
            record[key] = metadata[key]
    if kind == "workflow.stop":
        record["stop_state"] = {
            "control.stop_effective": "effective",
            "control.stop_pending": "pending",
        }.get(event_type, "unknown")
        record["cost_kind"] = "unknown"
        if _integer(metadata.get("barrier_seq")):
            record["barrier_seq"] = metadata["barrier_seq"]
    for key in ("source_hash", "request_hash"):
        if _hash(metadata.get(key)):
            record[key] = metadata[key]
    if kind.startswith("handoff."):
        # Never substitute the current step's Bridge request hash for the
        # workflow/consent request hash. Historical audit may not have that field.
        if _ref(record.get("original_task_id")):
            record["task_id"] = record["original_task_id"]
    elif _hash(row["task_request_hash"]):
        record["request_hash"] = row["task_request_hash"]
    status = {
        "return.received": "delivered_unverified",
        "task.question": "waiting_question",
        "return.reviewed": "checked",
    }.get(event_type)
    if event_type == "task.completed" and (
        kind == "handoff.turn_ended" or row["task_operation"] == "agent.execute"
    ):
        status = "turn_completed"
    if status:
        record["reported_status"] = status
    if len((canonical(record) + "\n").encode()) > MAX_RECORD_BYTES:
        raise ValueError("event_byte_limit")
    return record, metadata


def export_workflow_observations(
    bridge, principal, *, task_ids, cursor=0, limit=100, through_seq=None
):
    """Authenticated facade for later MCP wiring; creates no task or audit event."""
    if type(principal) is not str:
        raise _error("forbidden")
    bridge.security.principal(principal, "task.read")
    return export_configured_observations(
        bridge.config,
        principal,
        task_ids=task_ids,
        cursor=cursor,
        limit=limit,
        through_seq=through_seq,
    )


def export_configured_observations(
    config, principal, *, task_ids, cursor=0, limit=100, through_seq=None
):
    """Trusted local operator reader. Identity comes from configured policy, not payload flags."""
    if type(principal) is not str:
        raise _error("forbidden")
    policy = config.principals.get(principal)
    if policy is None or "task.read" not in policy.capabilities:
        raise _error("forbidden")
    if (
        type(task_ids) not in (list, tuple)
        or not 1 <= len(task_ids) <= MAX_TASKS
        or any(type(t) is not str or TASK_ID.fullmatch(t) is None for t in task_ids)
        or len(set(task_ids)) != len(task_ids)
        or not _integer(cursor)
        or type(limit) is not int
        or not 1 <= limit <= MAX_ROWS
        or through_seq is not None
        and (not _integer(through_seq) or through_seq < cursor)
    ):
        raise _error("invalid_observation_request")
    path, signature = _private_db(config)
    source_id = "kb-audit-" + digest(["existing_bridge_audit", str(path), principal])[:32]
    started = time.monotonic()
    try:
        db = sqlite3.connect(
            path.as_uri() + "?mode=ro", uri=True, timeout=0.2, isolation_level=None
        )
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            db.set_progress_handler(lambda: int(time.monotonic() - started > 2), 1000)
            db.execute("BEGIN")
            info = path.stat()
            if (info.st_dev, info.st_ino) != signature:
                raise _error("unsafe_state")
            marks = ",".join("?" for _ in task_ids)
            owned = db.execute(
                f"SELECT id FROM tasks WHERE principal=? AND id IN ({marks})",
                (principal, *task_ids),
            ).fetchall()
            if len(owned) != len(task_ids):
                raise _error("not_found")
            maximum = (
                db.execute(
                    f"SELECT max(seq) FROM audit WHERE principal=? AND task_id IN ({marks})",
                    (principal, *task_ids),
                ).fetchone()[0]
                or 0
            )
            through = maximum if through_seq is None else through_seq
            if through > maximum or cursor > through:
                raise _error("invalid_observation_cursor")
            rows = db.execute(
                "SELECT a.seq,a.at,a.kind,a.principal,a.task_id,a.hash,a.previous,"
                "CAST(substr(CAST(a.metadata AS BLOB),1,?) AS TEXT) metadata,"
                "t.request_hash task_request_hash,t.operation task_operation,"
                "CAST(substr(CAST(p.metadata AS BLOB),1,?) AS TEXT) preflight,"
                "p.seq preflight_seq,p.at preflight_at,p.hash preflight_hash,"
                "p.previous preflight_previous "
                "FROM audit a JOIN tasks t ON t.id=a.task_id AND t.principal=a.principal "
                "LEFT JOIN audit p ON p.seq=(SELECT q.seq FROM audit q "
                "WHERE q.principal=a.principal AND q.task_id=a.task_id "
                "AND q.kind='task.preflight' AND q.seq<=a.seq ORDER BY q.seq DESC LIMIT 1) "
                f"WHERE a.principal=? AND a.task_id IN ({marks}) AND a.seq>? AND a.seq<=? "
                "ORDER BY a.seq LIMIT ?",
                (
                    MAX_METADATA_BYTES + 1,
                    MAX_METADATA_BYTES + 1,
                    principal,
                    *task_ids,
                    cursor,
                    through,
                    limit + 1,
                ),
            ).fetchall()
            return _page(db, rows, principal, source_id, task_ids, cursor, through, limit)
        finally:
            db.close()
    except (sqlite3.Error, OSError):
        raise _error("observation_state_unavailable") from None


def _page(db, rows, principal, source_id, task_ids, cursor, through, limit):
    events, provenance, diagnostics, refs = [], [], [], set()
    checkpoints = []
    next_cursor, page_bytes, scanned, skipped, invalid = cursor, 0, 0, 0, 0
    gaps = False
    for row in rows[:limit]:
        checkpoint = (next_cursor, page_bytes, scanned, skipped, invalid, gaps, len(diagnostics))
        try:
            event, metadata = _project(row, principal, source_id)
        except (ValueError, TypeError, OverflowError, OSError, RecursionError):
            event, metadata = None, {}
            invalid += 1
            if len(diagnostics) < 64:
                diagnostics.append({"code": "audit_record_unprojectable", "audit_seq": row["seq"]})
        if event is not None:
            size = len((canonical(event) + "\n").encode())
            if page_bytes + size > MAX_PAGE_BYTES:
                break
            page_bytes += size
            checkpoints.append(checkpoint)
            events.append(event)
            proof = {
                "event_id": event["event_id"],
                "audit_seq": row["seq"],
                "audit_hash": row["hash"],
                "audit_kind": row["kind"],
                "basis": "existing_selected_audit_record",
                "execution_runtime": _runtime(row),
                "historical_runtime_authenticated": False,
            }
            if _ref(metadata.get("binding_ref")):
                proof["correlation_ref"] = metadata["binding_ref"]
            provenance.append(proof)
        else:
            skipped += 1
        if _ref(metadata.get("binding_ref")) and len(refs) < MAX_TASKS:
            refs.add(metadata["binding_ref"])
        gaps |= row["seq"] != next_cursor + 1
        next_cursor, scanned = row["seq"], scanned + 1
    correlations = _correlations(db, principal, task_ids, refs)
    response = {
        "event_schema": EVENT_SCHEMA,
        "role": "observer_only",
        "source_tool": "kirabridge",
        "source_id": source_id,
        "events": events,
        "provenance": provenance,
        "cursor": cursor,
        "next_cursor": next_cursor,
        "through_seq": through,
        "has_more": scanned < len(rows),
        "audit_rows_examined": scanned,
        "audit_rows_without_workflow_projection": skipped,
        "page_event_bytes": page_bytes,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "diagnostics": diagnostics,
        "diagnostics_omitted": max(0, invalid - len(diagnostics)),
        "current_correlations": correlations,
        "coverage": {
            "basis": "selected_owned_tasks_existing_audit_only",
            "filtered_or_missing_sequence": gaps or skipped > 0 or cursor > 0,
            "all_activity": "unknown",
            "runtime_outside_recorded_preflight": "unknown",
            "external_tunnel": "unknown",
            "business_project_scope": "unknown_unless_recorded",
        },
        "source_authenticated": False,
        "rights_granted": False,
        "budget_released": False,
        "stop_enforced": False,
        "project_completion_verified": False,
    }
    while len((canonical(response) + "\n").encode()) > MAX_RESPONSE_BYTES:
        if not checkpoints:
            raise _error("observation_response_budget")
        next_cursor, page_bytes, scanned, skipped, invalid, gaps, diagnostic_count = (
            checkpoints.pop()
        )
        # Revisit the omitted event and every later row on the next page. Current
        # correlations remain explicitly current, never historical event evidence.
        del events[len(checkpoints) :]
        del provenance[len(checkpoints) :]
        del diagnostics[diagnostic_count:]
        response.update(
            next_cursor=next_cursor,
            has_more=True,
            audit_rows_examined=scanned,
            audit_rows_without_workflow_projection=skipped,
            page_event_bytes=page_bytes,
            diagnostics_omitted=max(0, invalid - len(diagnostics)),
        )
        response["coverage"]["filtered_or_missing_sequence"] = gaps or skipped > 0 or cursor > 0
        if next_cursor == cursor:
            # A configured budget too small for the first event must fail, rather
            # than promise an empty continuation which can never make progress.
            raise _error("observation_response_budget")
    return response


def _correlations(db, principal, task_ids, refs):
    exists = db.execute("SELECT type FROM sqlite_master WHERE name='handoff_bindings'").fetchone()
    if exists is None or exists[0] != "table":
        return {
            "basis": "current_persistent_correlation_not_historical_evidence",
            "items": [],
            "coverage": "unknown",
        }
    task_marks = ",".join("?" for _ in task_ids)
    refs = sorted(refs)
    ref_marks = ",".join("?" for _ in refs) or "NULL"
    rows = db.execute(
        "SELECT h.id,h.operator_ref,h.handoff_id,h.revision,h.first_task_id,h.request_hash "
        "FROM handoff_bindings h JOIN tasks t ON t.id=h.first_task_id AND t.principal=h.principal "
        f"WHERE h.principal=? AND (h.first_task_id IN ({task_marks}) OR h.id IN ({ref_marks})) "
        "ORDER BY h.id LIMIT ?",
        (principal, *task_ids, *refs, MAX_TASKS + 1),
    ).fetchall()
    items = []
    for row in rows[:MAX_TASKS]:
        value = {
            key: row[key]
            for key in ("operator_ref", "handoff_id", "first_task_id")
            if _ref(row[key])
        }
        if _ref(row["id"]):
            value["correlation_ref"] = row["id"]
        if _integer(row["revision"]):
            value["handoff_revision"] = row["revision"]
        if _hash(row["request_hash"]):
            value["binding_request_hash"] = row["request_hash"]
        items.append(value)
    return {
        "basis": "current_persistent_correlation_not_historical_evidence",
        "items": items,
        "truncated": len(rows) > MAX_TASKS,
        "identity_authenticated": False,
    }
