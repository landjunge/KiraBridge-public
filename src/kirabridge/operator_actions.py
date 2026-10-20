"""Durable local operator actions, separate from HTTP and platform execution."""

from __future__ import annotations

import asyncio
import json
import re
import time

from kirabridge.bridge_core.models import BridgeError, State, canonical, digest


def action_identity(value):
    identity = value.get("action_id", "")
    if not isinstance(identity, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", identity):
        raise BridgeError("invalid_request", "Eine Aktionskennung fehlt")
    return identity


class ControlActionRepository:
    """Owns control_actions. Reservation and its audit record commit together."""

    def __init__(self, store):
        self.store = store
        store.db.execute(
            "CREATE TABLE IF NOT EXISTS control_actions ("
            "id TEXT PRIMARY KEY,request_hash TEXT NOT NULL,state TEXT NOT NULL,"
            "created REAL NOT NULL,result TEXT)"
        )

    def reserve(self, value):
        identity, hashed = action_identity(value), digest(value)
        # The lookup must be INSIDE BEGIN IMMEDIATE, including across console
        # processes. No process/network call or await holds this transaction.
        with self.store.transaction():
            row = self.store.db.execute(
                "SELECT * FROM control_actions WHERE id=?", (identity,)
            ).fetchone()
            if row:
                if row["request_hash"] != hashed:
                    raise BridgeError(
                        "idempotency_conflict", "Die Aktionskennung wurde bereits verwendet"
                    )
                return (
                    False,
                    json.loads(row["result"])
                    if row["result"]
                    else {"state": row["state"], "message": "Aktion bereits angefordert"},
                )
            self.store.db.execute(
                "INSERT INTO control_actions VALUES(?,?,?,?,NULL)",
                (identity, hashed, "requested", time.time()),
            )
            self.store.audit(
                "control.requested",
                "local",
                None,
                {
                    "action_id": identity,
                    "service": value.get("service"),
                    "action": value.get("action"),
                },
            )
        return True, None

    def finish(self, value, result):
        identity = action_identity(value)
        with self.store.transaction():
            changed = self.store.db.execute(
                "UPDATE control_actions SET state=?,result=? "
                "WHERE id=? AND request_hash=? AND result IS NULL",
                (result.get("state", "unknown"), canonical(result), identity, digest(value)),
            ).rowcount
            if changed != 1:
                raise BridgeError("action_state_conflict", "Der Aktionsabschluss ist verändert")
            self.store.audit(
                "control.result",
                "local",
                None,
                {"action_id": identity, "service": value.get("service"), "result": result},
            )


class ControlActions:
    def __init__(self, repository):
        self.repository = repository

    async def execute(self, value, dispatch):
        identity = action_identity(value)
        reserved, previous = self.repository.reserve(value)
        if not reserved:
            return previous
        try:
            result = await dispatch(value.get("service"), value.get("action"), identity)
        except BridgeError as exc:
            result = {"state": "failed", "error": {"code": exc.code, "message": str(exc)}}
        except asyncio.CancelledError:
            # A lost HTTP client may already have triggered the OS action.
            # Preserve uncertainty and forbid automatic retry of this ID.
            self.repository.finish(
                value,
                {
                    "state": "unknown",
                    "error": {
                        "code": "action_outcome_unknown",
                        "message": "Bedienung unterbrochen. Zustand prüfen; nicht wiederholen.",
                    },
                },
            )
            raise
        except Exception as exc:
            result = {
                "state": "unknown",
                "error": {
                    "code": "action_outcome_unknown",
                    "message": "Der Ausgang ist unklar. Zustand neu prüfen: " + str(exc)[:200],
                },
            }
        self.repository.finish(value, result)
        return result


class OperatorTaskDecisions:
    """Trusted local review using the task owner's existing atomic decisions."""

    def __init__(self, tasks, store, config):
        self.tasks, self.store, self.config = tasks, store, config

    def listing(self):
        return {
            **self.store.operator_listing(),
            "approval_modes": {
                name: policy.approval_mode for name, policy in self.config().principals.items()
            },
        }

    def detail(self, task_id):
        return self.store.operator_detail(task_id)

    def decide(self, task_id, decision, request_hash):
        if decision == "approve":
            self.tasks.approve(task_id, expected_hash=request_hash, source="local_console")
        elif decision == "deny":
            self.store.transition(
                task_id,
                State.CANCELLED,
                {"source": "local_console_rejection"},
                expected_hash=request_hash,
                expected_states={State.CREATED, State.QUEUED},
            )
        else:
            raise BridgeError("invalid_request", "Unknown decision")
        return {"task": self.store.get(task_id)}
