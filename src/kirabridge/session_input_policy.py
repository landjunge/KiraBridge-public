"""Durable, two-step terminal input; shares task/approval transactions."""

from __future__ import annotations

import time

from kirabridge.bridge_core.models import BridgeError, canonical

SUFFIX = "go-go-go"


def marked(text):
    return text.rstrip().endswith(SUFFIX)


class SessionInputPolicy:
    def __init__(self, config, store, security):
        self.config, self.store, self.security = config, store, security

    def applies(self, request, principal):
        from kirabridge.permissions import decision

        return decision(self.config, principal, request.operation)["buffer_enabled"]

    def stage(self, request, principal):
        """Inside enqueue's transaction, after the immutable task has been stored."""
        now = time.time()
        immediate = marked(request.arguments["text"])
        if immediate and not request.arguments["text"].rstrip()[: -len(SUFFIX)].strip():
            raise BridgeError("invalid_arguments", "Input is empty after removing go-go-go")
        self.store.db.execute(
            "INSERT INTO session_input_buffers"
            "(task_id,state,created,expires,released,release_source) "
            "VALUES(?,?,?,?,?,?)",
            (
                request.task_id,
                "released" if immediate else "waiting",
                now,
                now + self.config.session_input_policy.timeout_seconds,
                now if immediate else None,
                "suffix" if immediate else None,
            ),
        )
        self.store.audit(
            "session.input.buffered",
            principal,
            request.task_id,
            {
                "release_source": "suffix" if immediate else None,
                "timeout_seconds": self.config.session_input_policy.timeout_seconds,
            },
        )

    def waiting(self, task_id):
        row = self.store.db.execute(
            "SELECT * FROM session_input_buffers WHERE task_id=?", (task_id,)
        ).fetchone()
        return row if row and row["state"] == "waiting" else None

    def release(self, principal, request, token, *, source="daniel_token"):
        """Consume a separate local-operator-issued token within the queue transaction."""
        row = self.waiting(request.task_id)
        task = self.store.get(request.task_id, principal)
        if not row or row["expires"] <= time.time() or task["state"] != "created":
            raise BridgeError(
                "input_buffer_expired", "Input buffer is expired or no longer waiting"
            )
        self.security.consume(principal, request, token)
        self.store.db.execute(
            "UPDATE session_input_buffers SET state='released',released=?,release_source=? "
            "WHERE task_id=?",
            (time.time(), source, request.task_id),
        )
        self.store.audit("session.input.released", principal, request.task_id, {"source": source})

    def expire(self):
        """Persist expiry, also on daemon restart and before any late approval."""
        now = time.time()
        with self.store.transaction():
            rows = self.store.db.execute(
                "SELECT b.task_id,t.principal,t.state FROM session_input_buffers b "
                "JOIN tasks t ON t.id=b.task_id WHERE b.state='waiting' AND b.expires<=?",
                (now,),
            ).fetchall()
            for row in rows:
                self.store.db.execute(
                    "UPDATE session_input_buffers SET state='expired' WHERE task_id=?",
                    (row["task_id"],),
                )
                if row["state"] == "created":
                    evidence = canonical({"reason": "input_buffer_expired"})
                    self.store.db.execute(
                        "UPDATE tasks SET state='cancelled',updated=?,finished=?,evidence=? "
                        "WHERE id=?",
                        (now, now, evidence, row["task_id"]),
                    )
                    event = self.store.db.execute(
                        "INSERT INTO events(task_id,at,state,evidence) VALUES(?,?,'cancelled',?)",
                        (row["task_id"], now, evidence),
                    )
                    from kirabridge.completion_manager import record_task_completion

                    record_task_completion(self.store, row["task_id"], event.lastrowid)
                self.store.audit(
                    "session.input.expired",
                    row["principal"],
                    row["task_id"],
                    {"input_handed_to_transport": False},
                )

    def dispatch(self, principal, args, task_id):
        """Last guard at the transport boundary; direct sends cannot bypass the buffer."""
        from kirabridge.permissions import decision

        if not decision(self.config, principal, "session.input")["buffer_enabled"]:
            # Persisted buffers remain binding even if the policy was subsequently disabled.
            if (
                not task_id
                or not self.store.db.execute(
                    "SELECT 1 FROM session_input_buffers WHERE task_id=?", (task_id,)
                ).fetchone()
            ):
                return args
        if not task_id:
            raise BridgeError("input_buffer_required", "Submit session.input as a buffered task")
        with self.store.transaction():
            task = self.store.get(task_id, principal)
            buffer = task.get("input_buffer")
            if (
                task["operation"] != "session.input"
                or task["state"] != "running"
                or not buffer
                or buffer["state"] != "released"
                or type(args).model_validate(task["args"]).model_dump() != args.model_dump()
            ):
                raise BridgeError("input_buffer_required", "This exact input has not been released")
            self.store.db.execute(
                "UPDATE session_input_buffers SET state='dispatching',dispatch_started=? "
                "WHERE task_id=?",
                (time.time(), task_id),
            )
            self.store.audit(
                "session.input.dispatching",
                principal,
                task_id,
                {"release_source": buffer["release_source"]},
            )
        text = args.text.rstrip()[: -len(SUFFIX)].rstrip() if marked(args.text) else args.text
        return args.model_copy(update={"text": text})

    def sent(self, principal, task_id):
        if not task_id:
            return
        with self.store.transaction():
            changed = self.store.db.execute(
                "UPDATE session_input_buffers SET state='sent' "
                "WHERE task_id=? AND state='dispatching'",
                (task_id,),
            ).rowcount
            if changed:
                self.store.audit(
                    "session.input.sent",
                    principal,
                    task_id,
                    {"input_handed_to_transport": True, "agent_processed": False},
                )
