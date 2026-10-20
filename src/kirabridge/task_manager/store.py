from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from kirabridge.bridge_core.config import private_directory
from kirabridge.bridge_core.models import TRANSITIONS, BridgeError, State, canonical, digest
from kirabridge.operations import RESERVED_READ_OPERATIONS, STOP_OPERATIONS, lane_operations

SCHEMA_VERSION = 2
DRAIN_CONTROL = STOP_OPERATIONS

MESSAGE_SCHEMA = """
CREATE TABLE conversations (
 id TEXT PRIMARY KEY, party_a TEXT NOT NULL, party_b TEXT NOT NULL, created REAL NOT NULL
);
CREATE TABLE messages (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
 conversation_id TEXT NOT NULL REFERENCES conversations(id), position INTEGER NOT NULL,
 sender TEXT NOT NULL, recipient TEXT NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL,
 idem TEXT NOT NULL, request_hash TEXT NOT NULL, reply_to TEXT REFERENCES messages(id),
 task_id TEXT REFERENCES tasks(id), depth INTEGER NOT NULL, request_reply INTEGER NOT NULL,
 created REAL NOT NULL, delivered REAL, receipt TEXT, acknowledged REAL,
 UNIQUE(sender,idem), UNIQUE(conversation_id,position)
);
CREATE INDEX message_inbox ON messages(recipient,acknowledged,seq);
CREATE TABLE message_jobs (
 message_id TEXT PRIMARY KEY REFERENCES messages(id), state TEXT NOT NULL,
 run_id TEXT UNIQUE, claimed REAL, started REAL, finished REAL,
 reply_id TEXT REFERENCES messages(id), evidence TEXT NOT NULL DEFAULT '{}', error TEXT
);
CREATE INDEX message_queue ON message_jobs(state);
CREATE TABLE message_events (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT NOT NULL REFERENCES messages(id),
 at REAL NOT NULL, kind TEXT NOT NULL, evidence TEXT NOT NULL
);
PRAGMA user_version=2;
"""

SCHEMA = """
CREATE TABLE tasks (
 id TEXT PRIMARY KEY, principal TEXT NOT NULL, idem TEXT NOT NULL,
 request_hash TEXT NOT NULL, operation TEXT NOT NULL, args TEXT NOT NULL,
 agent TEXT, parent_id TEXT REFERENCES tasks(id), state TEXT NOT NULL,
 created REAL NOT NULL, updated REAL NOT NULL, accepted REAL, started REAL, finished REAL,
 receipt TEXT, evidence TEXT NOT NULL DEFAULT '{}', result TEXT, error TEXT,
 lease_owner TEXT, lease_until REAL, attempt INTEGER NOT NULL DEFAULT 1,
 UNIQUE(principal, idem)
);
CREATE INDEX queue_idx ON tasks(state, created);
CREATE TABLE events (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(id),
 at REAL NOT NULL, state TEXT NOT NULL, evidence TEXT NOT NULL
);
CREATE TABLE approvals (
 token_hash TEXT PRIMARY KEY, principal TEXT NOT NULL, task_id TEXT NOT NULL,
 request_hash TEXT NOT NULL, expires REAL NOT NULL, used REAL
);
CREATE TABLE audit (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, kind TEXT NOT NULL,
 principal TEXT NOT NULL, task_id TEXT, metadata TEXT NOT NULL,
 previous TEXT NOT NULL, hash TEXT NOT NULL
);
PRAGMA user_version=1;
"""


class Store:
    """Short synchronous WAL transactions; no network or await inside a transaction."""

    def __init__(self, path: Path):
        self.result_codec = None
        private_directory(path.parent)
        if path.is_symlink():
            raise BridgeError("unsafe_state", "Database must not be a symlink")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise BridgeError("unsafe_state", "Database must be owner-only")
        self.db = sqlite3.connect(path, isolation_level=None, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        try:
            # Re-read under the write lock: concurrent daemon/client starts must not migrate twice.
            with self.transaction():
                version = self.db.execute("PRAGMA user_version").fetchone()[0]
                scripts = []
                if version == 0:
                    scripts.append(SCHEMA)
                    version = 1
                if version == 1:
                    scripts.append(MESSAGE_SCHEMA)
                elif version != SCHEMA_VERSION:
                    raise BridgeError("schema_version", "Unsupported database schema")
                for script in scripts:
                    for statement in script.split(";"):
                        if statement.strip():
                            self.db.execute(statement)
                from kirabridge.completion_manager import SCHEMA as COMPLETION_SCHEMA

                for statement in COMPLETION_SCHEMA:
                    self.db.execute(statement)
                self.db.execute(
                    "CREATE TABLE IF NOT EXISTS handoff_bindings ("
                    "id TEXT PRIMARY KEY, principal TEXT NOT NULL, operator_ref TEXT NOT NULL, "
                    "handoff_id TEXT NOT NULL, revision INTEGER NOT NULL, "
                    "first_task_id TEXT NOT NULL REFERENCES tasks(id), "
                    "request_hash TEXT NOT NULL, metadata TEXT NOT NULL, "
                    "UNIQUE(principal,operator_ref,handoff_id,revision))"
                )
                self.db.execute(
                    "CREATE INDEX IF NOT EXISTS audit_kind_at ON audit(kind COLLATE NOCASE,at)"
                )
                self.db.execute(
                    "CREATE INDEX IF NOT EXISTS audit_task_kind "
                    "ON audit(principal,task_id,kind,seq)"
                )
                self.db.execute(
                    "CREATE TABLE IF NOT EXISTS session_input_buffers ("
                    "task_id TEXT PRIMARY KEY REFERENCES tasks(id), "
                    "state TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, "
                    "released REAL, release_source TEXT, dispatch_started REAL)"
                )
                self.db.execute(
                    "CREATE INDEX IF NOT EXISTS session_input_expiry "
                    "ON session_input_buffers(state,expires)"
                )
                self.db.execute(
                    "CREATE TABLE IF NOT EXISTS activation_runs ("
                    "id TEXT PRIMARY KEY,state TEXT NOT NULL,created REAL NOT NULL,"
                    "updated REAL NOT NULL,plan TEXT NOT NULL,error TEXT)"
                )
                self.db.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS activation_single_active "
                    "ON activation_runs((1)) WHERE state IN "
                    "('draining','activating','verifying','recovering','failed_blocked')"
                )
                from kirabridge.voice_channel import SCHEMA as VOICE_SCHEMA

                for statement in VOICE_SCHEMA:
                    self.db.execute(statement)
        except BaseException:
            self.db.close()
            raise

    @contextmanager
    def transaction(self):
        savepoint = "nested_" + uuid.uuid4().hex if self.db.in_transaction else None
        self.db.execute(f"SAVEPOINT {savepoint}" if savepoint else "BEGIN IMMEDIATE")
        try:
            yield self.db
            self.db.execute(f"RELEASE {savepoint}" if savepoint else "COMMIT")
        except BaseException:
            if savepoint:
                self.db.execute(f"ROLLBACK TO {savepoint}")
                self.db.execute(f"RELEASE {savepoint}")
            else:
                self.db.execute("ROLLBACK")
            raise

    def maintenance_state(self):
        row = self.db.execute(
            "SELECT id,state,created,updated,error FROM activation_runs WHERE state IN "
            "('draining','activating','verifying','recovering','failed_blocked')"
        ).fetchone()
        return dict(row) if row else None

    def team_reservation(self, identifier, principal, request_hash, cutoff):
        if not self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='team_work'"
        ).fetchone():
            return False
        return bool(
            self.db.execute(
                "SELECT 1 FROM team_work WHERE core_task_id=? AND assignee=? "
                "AND core_request_hash=? AND created<=? "
                "AND state IN ('dispatching','queued','accepted','running')",
                (identifier, principal, request_hash, cutoff),
            ).fetchone()
        )

    def can_claim(self, created, *, task_id=None, operation=None):
        state = self.maintenance_state()
        if not state:
            return True
        if state["state"] != "draining":
            return False
        if operation in DRAIN_CONTROL:
            return True
        if created <= state["created"]:
            return True
        task = (
            self.db.execute(
                "SELECT principal,request_hash FROM tasks WHERE id=?", (task_id,)
            ).fetchone()
            if task_id
            else None
        )
        return bool(
            task
            and self.team_reservation(
                task_id, task["principal"], task["request_hash"], state["created"]
            )
        )

    def assert_accepting(
        self,
        *,
        continuation_id=None,
        principal=None,
        request_hash=None,
        owned_execution=False,
        operation=None,
    ):
        state = self.maintenance_state()
        if not state:
            return
        if state["state"] == "draining" and operation in DRAIN_CONTROL:
            return
        if state["state"] == "draining" and continuation_id:
            task = self.db.execute(
                "SELECT created FROM tasks WHERE id=? AND state IN ('accepted','running')",
                (continuation_id,),
            ).fetchone()
            existing = self.db.execute(
                "SELECT 1 FROM message_jobs j JOIN messages m ON m.id=j.message_id "
                "WHERE j.run_id=? AND m.created<=? AND j.state='running'",
                (continuation_id, state["created"]),
            ).fetchone()
            if owned_execution and (
                existing or task and self.can_claim(task["created"], task_id=continuation_id)
            ):
                return
            if (
                principal
                and request_hash
                and self.team_reservation(
                    continuation_id, principal, request_hash, state["created"]
                )
            ):
                return
        raise BridgeError(
            "service_maintenance",
            "KiraBridge aktiviert Einstellungen. Neue Aufträge sind vorübergehend gesperrt; "
            "laufende Arbeit und Antworten bleiben erhalten.",
        )

    def audit(self, kind: str, principal: str, task_id: str | None, metadata: dict) -> None:
        # Call inside the transaction that performs the audited action.
        previous = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        record = {
            "at": time.time(),
            "kind": kind,
            "principal": principal,
            "task_id": task_id,
            "metadata": metadata,
            "previous": previous[0] if previous else "0" * 64,
        }
        self.db.execute(
            "INSERT INTO audit(at,kind,principal,task_id,metadata,previous,hash) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                record["at"],
                kind,
                principal,
                task_id,
                canonical(metadata),
                record["previous"],
                digest(record),
            ),
        )

    def get(
        self, task_id: str, principal: str | None = None, *, resolve_output=True
    ) -> dict[str, Any]:
        row = self.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if row is None or (principal is not None and row["principal"] != principal):
            raise BridgeError("not_found", "Task not found")
        result = dict(row)
        for key in ("args", "evidence", "result", "error"):
            result[key] = json.loads(result[key]) if result[key] is not None else None
        result.pop("request_hash")
        if resolve_output and self.result_codec:
            result["result"] = self.result_codec.resolve_result(
                result["principal"], result["result"]
            )
        buffer = self.db.execute(
            "SELECT * FROM session_input_buffers WHERE task_id=?", (task_id,)
        ).fetchone()
        if buffer:
            result["input_buffer"] = dict(buffer)
        return result

    def transition(
        self,
        task_id: str,
        state: State,
        evidence: dict,
        *,
        result: dict | None = None,
        error: dict | None = None,
        owner: str | None = None,
        expected_hash: str | None = None,
        expected_states: set[State] | None = None,
    ) -> None:
        with self.transaction():
            row = self.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if row is None:
                raise BridgeError("not_found", "Task not found")
            if expected_hash is not None and expected_hash != row["request_hash"]:
                raise BridgeError("review_conflict", "The reviewed request does not match")
            if expected_states is not None and row["state"] not in expected_states:
                raise BridgeError("state_conflict", "Task is no longer awaiting this decision")
            if state not in TRANSITIONS[State(row["state"])]:
                raise BridgeError("state_conflict", "Invalid task state transition")
            if owner and row["lease_owner"] != owner:
                raise BridgeError("lease_lost", "Worker no longer owns this task")
            if not evidence:
                raise BridgeError("missing_evidence", "A state transition requires evidence")
            now = time.time()
            if self.result_codec:
                result = self.result_codec.persist_task_result(row, result)
            finished = now if state in {State.COMPLETED, State.FAILED, State.CANCELLED} else None
            self.db.execute(
                "UPDATE tasks SET state=?,updated=?,started=COALESCE(started,?),finished=?,"
                "evidence=?,result=?,error=? WHERE id=?",
                (
                    state,
                    now,
                    now if state == State.RUNNING else None,
                    finished,
                    canonical(evidence),
                    canonical(result) if result is not None else None,
                    canonical(error) if error else None,
                    task_id,
                ),
            )
            event = self.db.execute(
                "INSERT INTO events(task_id,at,state,evidence) VALUES(?,?,?,?)",
                (task_id, now, state, canonical(evidence)),
            )
            from kirabridge.completion_manager import TERMINAL, record_task_completion

            if state in TERMINAL:
                if state == State.CANCELLED:
                    self.db.execute(
                        "UPDATE session_input_buffers SET state='cancelled' WHERE task_id=? "
                        "AND state IN ('waiting','released')",
                        (task_id,),
                    )
                record_task_completion(self, task_id, event.lastrowid)
            self.audit(
                "task.transition",
                row["principal"],
                task_id,
                {"from": row["state"], "to": state, "evidence_hash": digest(evidence)},
            )

    @staticmethod
    def lane_selection(lane):
        lane = "control" if lane is True else "normal" if lane is False else lane
        if lane not in {"normal", "control", "read", "stop"}:
            raise ValueError("Unknown execution lane")
        names = sorted(
            RESERVED_READ_OPERATIONS | STOP_OPERATIONS
            if lane == "normal"
            else lane_operations(lane)
        )
        comparison = "NOT IN" if lane == "normal" else "IN"
        return "operation " + comparison + " (" + ",".join("?" for _ in names) + ")", names

    def queued_count(self, lane):
        selection, names = self.lane_selection(lane)
        return self.db.execute(
            "SELECT COUNT(*) FROM tasks WHERE state IN ('created','queued') AND " + selection,
            names,
        ).fetchone()[0]

    def operator_listing(self):
        rows = self.db.execute(
            "SELECT id,principal,operation,agent,state,created,updated FROM tasks "
            "ORDER BY CASE state WHEN 'created' THEN 0 WHEN 'queued' THEN 1 "
            "WHEN 'accepted' THEN 2 WHEN 'running' THEN 3 WHEN 'unknown' THEN 4 ELSE 5 END, "
            "updated DESC LIMIT 100"
        ).fetchall()
        count = self.db.execute("SELECT count(*) FROM tasks WHERE state='created'").fetchone()[0]
        return {"tasks": [dict(row) for row in rows], "pending": count}

    def operator_detail(self, task_id):
        task = self.get(task_id)
        request_hash = self.db.execute(
            "SELECT request_hash FROM tasks WHERE id=?", (task_id,)
        ).fetchone()[0]
        return {"task": task, "request_hash": request_hash}

    def activation_work_count(self, *, active_only=False, context=None):
        db = context.db if context is not None else self.db
        states = ("accepted", "running") if active_only else ("queued", "accepted", "running")
        return db.execute(
            "SELECT count(*) FROM tasks WHERE state IN (" + ",".join("?" for _ in states) + ")",
            states,
        ).fetchone()[0]

    def operator_work_count(self):
        return self.db.execute(
            "SELECT count(*) FROM tasks WHERE state IN ('queued','accepted','running')"
        ).fetchone()[0]

    def operator_pending(self, limit=20):
        return [
            dict(row)
            for row in self.db.execute(
                "SELECT id,principal,operation FROM tasks WHERE state='created' "
                "ORDER BY created LIMIT ?",
                (min(100, max(1, limit)),),
            )
        ]

    def operator_snapshot_at(self, task_id, at):
        """Historical presentation, without turning later results into earlier evidence."""
        row = self.db.execute(
            "SELECT principal,operation,state,args,result,error,evidence,finished "
            "FROM tasks WHERE id=?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        result = {
            key: json.loads(row[key])
            if key in {"args", "result", "error", "evidence"} and row[key]
            else row[key]
            for key in row.keys()
        }
        observed = self.db.execute(
            "SELECT state,evidence FROM events WHERE task_id=? AND at<=? ORDER BY seq DESC LIMIT 1",
            (task_id, at),
        ).fetchone()
        if observed is None:
            return None  # The task had not yet been observed at this event's time.
        result["state"] = observed["state"]
        result["evidence"] = json.loads(observed["evidence"])
        if row["finished"] is None or row["finished"] > at:
            result["result"] = None
            result["error"] = None
            result["finished"] = None
        elif self.result_codec:
            result["result"] = self.result_codec.resolve_result(row["principal"], result["result"])
        result.pop("principal", None)
        return result

    def claim(self, owner: str, lease_seconds: float, control: bool | str = False) -> dict | None:
        with self.transaction():
            selection, names = self.lane_selection(control)
            row = self.db.execute(
                "SELECT id,principal,created,operation FROM tasks WHERE state='queued' "
                "AND " + selection + " ORDER BY created,id LIMIT 1",
                names,
            ).fetchone()
            if row is None:
                return None
            if not self.can_claim(row["created"], task_id=row["id"], operation=row["operation"]):
                return None
            now, receipt = time.time(), str(uuid.uuid4())
            evidence = {"receiver": "kirabridge.dispatcher", "receipt_id": receipt, "worker": owner}
            self.db.execute(
                "UPDATE tasks SET state='accepted',accepted=?,updated=?,receipt=?,evidence=?,"
                "lease_owner=?,lease_until=? WHERE id=? AND state='queued'",
                (now, now, receipt, canonical(evidence), owner, now + lease_seconds, row["id"]),
            )
            self.db.execute(
                "INSERT INTO events(task_id,at,state,evidence) VALUES(?,?,?,?)",
                (row["id"], now, "accepted", canonical(evidence)),
            )
            self.audit("task.accepted", row["principal"], row["id"], {"receipt_id": receipt})
        return self.get(row["id"])

    def recover(self) -> int:
        # Runtime exclusive lock proves the previous dispatcher no longer owns this DB.
        rows = self.db.execute(
            "SELECT id FROM tasks WHERE state IN ('accepted','running')"
        ).fetchall()
        for row in rows:
            previous = self.get(row[0])["evidence"]
            self.transition(
                row[0],
                State.UNKNOWN,
                {"reason": "dispatcher_restart", "last_observation": previous},
            )
        return len(rows)

    def close(self) -> None:
        self.db.close()
