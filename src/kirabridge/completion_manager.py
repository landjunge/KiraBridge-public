"""Durable owner-scoped completion outbox; client receipt is not assistant wake-up."""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid

from kirabridge.bridge_core.models import BridgeError, canonical, digest

TERMINAL = {"completed", "failed", "cancelled", "unknown", "blocked"}
SCHEMA = (
    "CREATE TABLE IF NOT EXISTS message_completion_routes ("
    "message_id TEXT PRIMARY KEY REFERENCES messages(id), target TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS completion_routes ("
    "task_id TEXT PRIMARY KEY REFERENCES tasks(id), target TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS completion_notices ("
    "seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, "
    "principal TEXT NOT NULL, target TEXT NOT NULL, source TEXT NOT NULL, source_id TEXT NOT NULL, "
    "event_seq INTEGER NOT NULL, payload TEXT NOT NULL, created REAL NOT NULL, "
    "receipt TEXT, delivered REAL, acknowledged REAL, UNIQUE(source,event_seq))",
    "CREATE INDEX IF NOT EXISTS completion_inbox ON "
    "completion_notices(principal,target,acknowledged,seq)",
)


def valid_target(target):
    if not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", target):
        raise BridgeError("invalid_completion_target", "Use a stable opaque completion target")
    return target


def find_evidence(value, key, depth=0):
    if isinstance(value, str) and len(value) <= 65536:
        try:
            value = json.loads(value)
        except ValueError:
            return None
    if depth > 8 or not isinstance(value, dict):
        return None
    if key in value and value[key] is not None:
        return value[key]
    for nested in ("evidence", "last_observation", "result", "agent_result"):
        found = find_evidence(value.get(nested), key, depth + 1)
        if found is not None:
            return found
    return None


def completion_payload(task, event_seq, *, source="task"):
    evidence = {"result": task.get("result"), "evidence": task.get("evidence", {})}
    state = task["state"]
    code = (task.get("error") or {}).get("code")
    timed_out = find_evidence(evidence, "timed_out") is True or code == "agent_timeout"
    terminated = find_evidence(evidence, "terminated") is True
    provider = find_evidence(evidence, "provider_error")
    # Only the adapter's explicit structured code is evidence. Never inspect text
    # for words such as quota, credit, 429, billing, limit or payment.
    provider_category = provider.get("category") if isinstance(provider, dict) else None
    outcome = {
        "completed": "success",
        "cancelled": "cancelled",
        "unknown": "unknown",
        "failed": "error",
        "blocked": "blocked",
    }[state]
    if state != "completed":
        if timed_out:
            outcome = "timeout"
        elif terminated:
            outcome = "cancelled"
        elif provider_category in {"quota_exhausted", "rate_limit", "authentication", "provider"}:
            outcome = "provider_error"
    result = task.get("result") or {}
    text = result.get("final_message") or result.get("text") or result.get("stdout") or ""
    preview = " ".join(text.split())[:320] if isinstance(text, str) else ""
    exit_code = find_evidence(evidence, "exit_code")
    return {
        "task_id": task["id"],
        "parent_id": task.get("parent_id"),
        "session_id": find_evidence(evidence, "session_id"),
        "agent": task.get("agent"),
        "process_id": find_evidence(evidence, "pid"),
        "attempt": task.get("attempt"),
        "completion_basis": (task.get("evidence") or {}).get("source", "recorded_execution_event"),
        "source": source,
        "state": state,
        "outcome": outcome,
        "execution_outcome_unknown": state == "unknown",
        "error_code": code,
        "provider_error": provider,
        "quota_diagnosis": "evidenced"
        if provider_category == "quota_exhausted"
        else "not_established",
        "exit_code": exit_code,
        "summary": f"{task['operation']}: {outcome}"
        + (f" (exit {exit_code})" if exit_code is not None else "")
        + (f". {preview}" if preview else ""),
        "observed_at": task["updated"],
        "finished_at": task.get("finished"),
        "event_seq": event_seq,
        "evidence_refs": {"task_get": task["id"], "task_events_after": event_seq - 1}
        if source == "task"
        else {"message_get": task["message_id"]},
    }


def record_notice(store, principal, target, source, source_id, event_seq, payload):
    """Caller owns transaction: outcome and notice commit together or neither does."""
    notice_id = f"completion-{source}-{event_seq}"
    store.db.execute(
        "INSERT INTO completion_notices"
        "(id,principal,target,source,source_id,event_seq,payload,created) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (
            notice_id,
            principal,
            target,
            source,
            source_id,
            event_seq,
            canonical(payload),
            time.time(),
        ),
    )
    store.audit(
        "completion.recorded",
        principal,
        source_id if source == "task" else None,
        {"notice_id": notice_id, "source": source, "content_sha256": digest(payload)},
    )


def record_task_completion(store, task_id, event_seq):
    task = store.get(task_id, resolve_output=False)
    route = store.db.execute(
        "SELECT target FROM completion_routes WHERE task_id=?", (task_id,)
    ).fetchone()
    payload = completion_payload(task, event_seq)
    previous = store.db.execute(
        "SELECT id,payload FROM completion_notices WHERE source='task' AND source_id=? "
        "ORDER BY seq DESC LIMIT 1",
        (task_id,),
    ).fetchone()
    if previous:
        prior = json.loads(previous["payload"])
        payload["supersedes"] = previous["id"]
        payload["session_id"] = payload["session_id"] or prior.get("session_id")
    record_notice(
        store,
        task["principal"],
        route[0] if route else "default",
        "task",
        task_id,
        event_seq,
        payload,
    )


class CompletionManager:
    def __init__(self, store, security):
        self.store, self.security = store, security

    def _policy(self, principal, source):
        self.security.principal(principal, "task.read" if source == "task" else "message.read")

    def receive(self, principal, target="default", limit=20):
        valid_target(target)
        if not 1 <= limit <= 50:
            raise BridgeError("invalid_limit", "Use limit 1..50")
        policy = self.security.principal(principal)
        sources = [
            source
            for source, cap in [("task", "task.read"), ("message", "message.read")]
            if cap in policy.capabilities
        ]
        if not sources:
            raise BridgeError("capability_denied", "Own task.read or message.read required")
        with self.store.transaction():
            rows = self.store.db.execute(
                "SELECT * FROM completion_notices WHERE principal=? AND target=? "
                "AND acknowledged IS NULL AND source IN (?,?) ORDER BY seq LIMIT ?",
                (
                    principal,
                    target,
                    "task" if "task" in sources else "-",
                    "message" if "message" in sources else "-",
                    limit,
                ),
            ).fetchall()
            notices = []
            for row in rows:
                receipt, delivered = row["receipt"], row["delivered"]
                if receipt is None:
                    receipt, delivered = str(uuid.uuid4()), time.time()
                    self.store.db.execute(
                        "UPDATE completion_notices SET receipt=?,delivered=? WHERE id=?",
                        (receipt, delivered, row["id"]),
                    )
                    self.store.audit(
                        "completion.returned_to_client", principal, None, {"notice_id": row["id"]}
                    )
                notices.append(
                    {
                        "id": row["id"],
                        "seq": row["seq"],
                        "target": target,
                        "receipt": receipt,
                        "returned_at": delivered,
                        "payload": json.loads(row["payload"]),
                    }
                )
        return {
            "notices": notices,
            "delivery_scope": "tool_response_to_client",
            "assistant_awakened": False,
            "chatgpt_chat_delivery": "unverified",
        }

    async def wait(self, principal, target="default", limit=20, wait_seconds=20):
        if not 0 <= wait_seconds <= 20:
            raise BridgeError("invalid_wait", "Completion wait is bounded to 20 seconds per call")
        deadline = asyncio.get_running_loop().time() + wait_seconds
        while True:
            value = self.receive(principal, target, limit)
            remaining = deadline - asyncio.get_running_loop().time()
            if value["notices"] or remaining <= 0:
                return value
            # Also observes commits by another process; no task-status requests.
            await asyncio.sleep(min(0.1, remaining))

    def ack(self, principal, notice_id, receipt):
        with self.store.transaction():
            row = self.store.db.execute(
                "SELECT * FROM completion_notices WHERE id=? AND principal=?",
                (notice_id, principal),
            ).fetchone()
            if row is None:
                raise BridgeError("not_found", "Completion not found")
            self._policy(principal, row["source"])
            if not row["receipt"] or receipt != row["receipt"]:
                raise BridgeError("receipt_conflict", "Matching completion receipt required")
            acknowledged = row["acknowledged"]
            if acknowledged is None:
                acknowledged = time.time()
                self.store.db.execute(
                    "UPDATE completion_notices SET acknowledged=? WHERE id=?",
                    (acknowledged, notice_id),
                )
                self.store.audit(
                    "completion.consumer_acknowledged", principal, None, {"notice_id": notice_id}
                )
        return {
            "id": notice_id,
            "acknowledged": acknowledged,
            "ack_scope": "consumer_processed",
            "chatgpt_chat_delivery": "unverified",
        }
