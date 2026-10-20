from __future__ import annotations

import json
from typing import TYPE_CHECKING

from kirabridge.bridge_core.models import digest

if TYPE_CHECKING:
    from kirabridge.task_manager.store import Store


class AuditWriter:
    """Atomic events for callers which own no other database mutation."""

    def __init__(self, store):
        self.store = store

    def record(self, kind, metadata, principal="local", task_id=None):
        with self.store.transaction():
            self.store.audit(kind, principal, task_id, metadata)


class AuditReader:
    """Audit-table reads for the authenticated local operator application."""

    def __init__(self, store):
        self.store = store

    def protocol_page(self, after=0, before=0):
        condition, parameter = (
            ("seq>?", after) if after else ("seq<?", before) if before else ("seq>?", 0)
        )
        order = "ASC" if after else "DESC"
        rows = self.store.db.execute(
            f"SELECT * FROM audit WHERE {condition} AND ("
            "kind LIKE 'message.%' OR kind LIKE 'task.%' OR kind LIKE 'control.%' "
            "OR kind LIKE 'session.input.%' OR kind LIKE 'console.%' "
            "OR kind='connection.checked' OR kind='terminal.output' "
            "OR json_extract(metadata,'$.error_code') IS NOT NULL) "
            f"ORDER BY seq {order} LIMIT 100",
            (parameter,),
        ).fetchall()
        if not after:
            rows = list(reversed(rows))
        return [{**dict(row), "metadata": json.loads(row["metadata"])} for row in rows]

    def recent_connection_checks(self):
        rows = self.store.db.execute(
            "SELECT at,principal,metadata FROM audit WHERE kind='connection.checked' "
            "ORDER BY seq DESC LIMIT 50"
        )
        return [
            {"at": row["at"], "principal": row["principal"], **json.loads(row["metadata"])}
            for row in rows
        ]


def verify(store: Store) -> dict:
    previous, count = "0" * 64, 0
    for row in store.db.execute("SELECT * FROM audit ORDER BY seq"):
        record = {k: row[k] for k in ("at", "kind", "principal", "task_id", "previous")}
        record["metadata"] = json.loads(row["metadata"])
        if row["previous"] != previous or digest(record) != row["hash"]:
            return {"valid": False, "failed_sequence": row["seq"]}
        previous, count = row["hash"], count + 1
    return {"valid": True, "records": count, "head": previous}
