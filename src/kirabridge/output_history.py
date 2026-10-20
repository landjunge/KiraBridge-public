"""Bounded raw terminal captures. Permanent audit and tasks retain references.

Content hashes identify bytes, never a process, an author or successful execution.
Only already-authorized session/task readers and the trusted local operator use
this internal repository. No public arbitrary-reference lookup is exposed.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid

from kirabridge.bridge_core.models import BridgeError, canonical


class OutputHistory:
    def __init__(self, config, store):
        self.config, self.store = config, store
        with store.transaction():
            store.db.execute(
                "CREATE TABLE IF NOT EXISTS output_snapshots ("
                "id TEXT PRIMARY KEY,principal TEXT NOT NULL,kind TEXT NOT NULL,"
                "source_key TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,"
                "sha256 TEXT NOT NULL,payload BLOB NOT NULL,bytes INTEGER NOT NULL,"
                "original_bytes INTEGER NOT NULL,truncated INTEGER NOT NULL)"
            )
            store.db.execute(
                "CREATE INDEX IF NOT EXISTS output_snapshot_lookup "
                "ON output_snapshots(principal,kind,source_key,sha256)"
            )
            store.db.execute(
                "CREATE INDEX IF NOT EXISTS output_snapshot_expiry ON output_snapshots(expires)"
            )

    def _bounded(self, payload, *, tail=False):
        payload = dict(payload)
        raw = canonical(payload).encode()
        original_bytes = len(raw)
        budget = min(self.config.max_item_bytes, self.config.max_bytes)
        while len(raw) > budget:
            key = max(payload, key=lambda k: len(payload[k].encode()))
            value = payload[key].encode()
            room = max(0, len(value) - max(len(raw) - budget, len(value) // 8, 1))
            value = value[-room:] if tail and room else value[:room]
            payload[key] = value.decode("utf-8", "ignore")
            raw = canonical(payload).encode()
        return raw, original_bytes

    @staticmethod
    def reference(row):
        return {
            "id": row["id"],
            "sha256": row["sha256"],
            "bytes": row["bytes"],
            "original_bytes": row["original_bytes"],
            "expires": row["expires"],
            "truncated": bool(row["truncated"]),
            "format": "canonical_json_utf8_v1",
        }

    def prune(self):
        with self.store.transaction():
            now = time.time()
            self.store.db.execute(
                "DELETE FROM output_snapshots WHERE expires<=? OR created<=?",
                (now, now - self.config.retention_seconds),
            )
            count, size = self.store.db.execute(
                "SELECT count(*),COALESCE(sum(bytes),0) FROM output_snapshots"
            ).fetchone()
            while count > self.config.max_entries or size > self.config.max_bytes:
                row = self.store.db.execute(
                    "SELECT id,bytes FROM output_snapshots ORDER BY created,rowid LIMIT 1"
                ).fetchone()
                self.store.db.execute("DELETE FROM output_snapshots WHERE id=?", (row["id"],))
                count, size = count - 1, size - row["bytes"]

    def capture(self, principal, kind, source_key, payload, metadata, *, task_id=None):
        raw, original_bytes = self._bounded(payload, tail=kind == "session_capture")
        fingerprint = hashlib.sha256(raw).hexdigest()
        with self.store.transaction():
            self.prune()
            row = self.store.db.execute(
                "SELECT * FROM output_snapshots WHERE principal=? AND kind=? "
                "AND source_key=? AND sha256=? AND expires>?",
                (principal, kind, source_key, fingerprint, time.time()),
            ).fetchone()
            if row is None:
                identifier, now = uuid.uuid4().hex, time.time()
                self.store.db.execute(
                    "INSERT INTO output_snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        identifier,
                        principal,
                        kind,
                        source_key,
                        now,
                        now + self.config.retention_seconds,
                        fingerprint,
                        raw,
                        len(raw),
                        original_bytes,
                        int(len(raw) != original_bytes),
                    ),
                )
                row = self.store.db.execute(
                    "SELECT * FROM output_snapshots WHERE id=?", (identifier,)
                ).fetchone()
                reference = self.reference(row)
                self.store.audit(
                    "terminal.output",
                    principal,
                    task_id,
                    {
                        **metadata,
                        "output_ref": reference,
                        "content_sha256": fingerprint,
                        "fingerprint_scope": "canonical capture bytes, not identity or execution",
                    },
                )
                self.prune()
            return self.reference(row)

    def read(self, principal, reference):
        row = self.store.db.execute(
            "SELECT * FROM output_snapshots WHERE id=? AND principal=?",
            (reference.get("id"), principal),
        ).fetchone()
        if row is None:
            return None, "unavailable_or_evicted"
        if row["expires"] <= time.time() or row["created"] <= (
            time.time() - self.config.retention_seconds
        ):
            return None, "expired"
        raw = bytes(row["payload"])
        if (
            reference.get("sha256") != row["sha256"]
            or hashlib.sha256(raw).hexdigest() != row["sha256"]
        ):
            return None, "integrity_mismatch"
        return json.loads(raw), "available"

    def observe_terminal(self, principal, result):
        reference = self.capture(
            principal,
            "session_capture",
            f"{result['pane_id']}:{result['expected_pid']}",
            {"text": result["text"]},
            {"pane_id": result["pane_id"], "expected_pid": result["expected_pid"]},
        )
        return self.resolve_result(
            principal,
            {
                **result,
                "output_ref": reference,
                "output_fields": ["text"],
                "output_codec": 1,
            },
        )

    def persist_task_result(self, task, result):
        if result is None:
            return None
        operation = task["operation"]
        if operation == "session.read" and isinstance(result.get("text"), str):
            payload = {"text": result["text"]}
            source_key = f"{result.get('pane_id')}:{result.get('expected_pid')}"
            provided = result.get("output_ref") or {}
            stored, status = self.read(task["principal"], provided)
            row = self.store.db.execute(
                "SELECT * FROM output_snapshots WHERE id=? AND principal=? "
                "AND kind='session_capture' AND source_key=?",
                (provided.get("id"), task["principal"], source_key),
            ).fetchone()
            if status == "available" and stored == payload and row is not None:
                reference = self.reference(row)
            else:
                reference = self.capture(
                    task["principal"],
                    "session_capture",
                    source_key,
                    payload,
                    {"pane_id": result.get("pane_id"), "expected_pid": result.get("expected_pid")},
                    task_id=task["id"],
                )
        elif operation in {"terminal.execute", "admin.execute", "agent.execute"}:
            payload = {
                key: result[key] for key in ("stdout", "stderr") if isinstance(result.get(key), str)
            }
            if not payload:
                return result
            reference = self.capture(
                task["principal"],
                "execution_output",
                task["id"],
                payload,
                {"operation": operation, "streams": list(payload)},
                task_id=task["id"],
            )
        else:
            return result
        return {
            **{key: value for key, value in result.items() if key not in payload},
            "output_ref": reference,
            "output_fields": list(payload),
            "output_codec": 1,
        }

    def resolve_result(self, principal, result):
        if not isinstance(result, dict) or result.get("output_codec") != 1:
            return result  # Historical results and business answers remain unchanged.
        payload, status = self.read(principal, result.get("output_ref") or {})
        fields = result.get("output_fields", [])
        return {
            **result,
            **{field: (payload or {}).get(field, "") for field in fields},
            "output_status": status,
            "output_available": payload is not None,
            "output_truncated": bool(
                (result.get("output_ref") or {}).get("truncated") or result.get("output_truncated")
            ),
        }

    def status(self):
        count, size = self.store.db.execute(
            "SELECT count(*),COALESCE(sum(bytes),0) FROM output_snapshots"
        ).fetchone()
        return {
            "entries": count,
            "payload_bytes": size,
            **self.config.model_dump(),
            "scope": "new raw capture payloads; historical audit and business records preserved",
        }

    def prepare_legacy_results(self):
        """Explicit local rollback preparation, never automatic or publicly exposed.

        Keep every state/event/receipt/audit record. Only new referenced task result
        JSON receives a compatible view before deliberately rolling back the code.
        No DB backup is restored and no execution is repeated.
        """
        with self.store.transaction():
            if self.store.maintenance_state() is None:
                raise BridgeError("rollback_maintenance_required", "Pause new work before rollback")
            updates, size = [], 0
            for row in self.store.db.execute(
                "SELECT id,principal,result FROM tasks "
                "WHERE json_extract(result,'$.output_codec')=1"
            ):
                result = self.resolve_result(row["principal"], json.loads(row["result"]))
                fields = result.get("output_fields", [])
                size += sum(len(result.get(field, "").encode()) for field in fields)
                if size > self.config.max_bytes:
                    raise BridgeError(
                        "rollback_capacity", "Use a compatible release; export is too large"
                    )
                result["legacy_output_ref"] = result.pop("output_ref")
                result.pop("output_codec")
                updates.append((canonical(result), row["id"]))
            self.store.db.executemany("UPDATE tasks SET result=? WHERE id=?", updates)
            self.store.audit(
                "control.output_history.rollback_prepared",
                "local",
                None,
                {"tasks": len(updates), "raw_bytes": size, "execution_repeated": False},
            )
        return {"tasks": len(updates), "raw_bytes": size}
