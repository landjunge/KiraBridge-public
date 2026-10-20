"""Durable, addressed agent messages. Payloads are data, never shell commands."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Literal

from pydantic import Field

from kirabridge.bridge_core.models import BridgeError, Input, canonical, digest


class MessageSend(Input):
    recipient: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_-]*$")
    conversation_id: str = Field(min_length=1, max_length=128, pattern=r"^[\w-]+$")
    idempotency_key: str = Field(min_length=1, max_length=128)
    body: str = Field(min_length=1, max_length=65536)
    kind: Literal["question", "answer", "work", "result", "note"] = "question"
    message_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[\w-]+$")
    reply_to: str | None = Field(default=None, min_length=1, max_length=128)
    task_id: str | None = Field(default=None, min_length=1, max_length=128)
    request_reply: bool | None = None
    dispatch: bool | None = None


class MessageManager:
    interface_version = "1"

    def activation_work_count(self, *, active_only=False, context=None):
        db = context.db if context is not None else self.store.db
        states = ("running",) if active_only else ("queued", "running")
        return db.execute(
            "SELECT count(*) FROM message_jobs WHERE state IN ("
            + ",".join("?" for _ in states)
            + ")",
            states,
        ).fetchone()[0]

    def operator_work_count(self):
        return self.store.db.execute(
            "SELECT count(*) FROM message_jobs WHERE state IN ('queued','running')"
        ).fetchone()[0]

    def operator_protocol_snapshot(self, message_id, at):
        row = self.store.db.execute(
            "SELECT sender,recipient,body,delivered,acknowledged,created FROM messages WHERE id=?",
            (message_id,),
        ).fetchone()
        if row is None or row["created"] > at:
            return None
        result = {key: row[key] for key in row.keys() if key != "created"}
        for key in ("delivered", "acknowledged"):
            if result[key] is not None and result[key] > at:
                result[key] = None
        return result

    def __init__(self, config, store, security):
        self.config, self.store, self.security = config, store, security
        self.wake = asyncio.Event()
        from kirabridge.voice_channel import VoiceChannel
        from kirabridge.voice_message_policy import VoiceMessagePolicy

        self.voice_channel = VoiceChannel(config, store)
        self.voice_policy = VoiceMessagePolicy(self)

    def _identity(self, principal, capability):
        return self.security.principal(principal, capability)

    def _row(self, principal, message_id):
        row = self.store.db.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
        if row is None:
            raise BridgeError("not_found", "Message not found")
        members = self.voice_channel.check(principal, row["conversation_id"])
        if not members and principal not in {row["sender"], row["recipient"]}:
            raise BridgeError("not_found", "Message not found")
        return row

    def _event(self, message_id, kind, principal, evidence):
        self.store.db.execute(
            "INSERT INTO message_events(message_id,at,kind,evidence) VALUES(?,?,?,?)",
            (message_id, time.time(), kind, canonical(evidence)),
        )
        self.store.audit(kind, principal, None, {"message_id": message_id, **evidence})

    def get(self, principal, message_id):
        self._identity(principal, "message.read")
        pending = self.voice_policy.get(principal, message_id)
        if pending and (
            pending.get("transport") == "team" or pending["message_buffer"]["state"] != "released"
        ):
            return pending
        result = dict(self._row(principal, message_id))
        result.pop("idem")
        result.pop("request_hash")
        job = self.store.db.execute(
            "SELECT * FROM message_jobs WHERE message_id=?", (message_id,)
        ).fetchone()
        result["processing"] = dict(job) if job else None
        visible = (
            job
            and self.store.db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='visible_handoffs'"
            ).fetchone()
            and self.store.db.execute(
                "SELECT 1 FROM visible_handoffs WHERE id=?", (job["run_id"],)
            ).fetchone()
        )
        result["processing_route"] = (
            "existing_visible_terminal"
            if visible
            else "managed_receiver"
            if job
            else "external_client_inbox"
        )
        if job:
            result["processing"]["evidence"] = json.loads(job["evidence"])
            scope = result["processing"]["evidence"].get("session_scope")
            if scope == "existing_visible_terminal":
                result["processing_route"] = scope
            elif job["state"] == "queued":
                result["processing_route"] = (
                    "pending_visible_terminal"
                    if self.config.visible_handoffs.enabled
                    else "pending_managed_receiver"
                )
        result["request_reply"] = bool(result["request_reply"])
        return {"api_version": "1", **result}

    def send(self, principal, message: MessageSend, *, completion_target=None):
        self._identity(principal, "message.send")
        message = self.voice_channel.route(principal, message)
        return self.voice_policy.send(principal, message, completion_target)

    def _send(
        self,
        principal,
        message,
        *,
        completion_target=None,
        validate_only=False,
        visible_internal=False,
    ):
        from kirabridge.completion_manager import valid_target

        if completion_target is not None:
            valid_target(completion_target)
        policy = self._identity(principal, "message.send")
        if policy.permission_level is None and policy.approval_mode != "automatic":
            raise BridgeError(
                "approval_required", "Messaging requires local automatic authorization"
            )
        target = self.config.principals.get(message.recipient)
        self_reply = (
            principal == message.recipient
            and message.kind in {"answer", "result"}
            and message.reply_to
            and self.store.db.execute(
                "SELECT 1 FROM visible_handoffs WHERE message_id=? AND principal=? AND target=?",
                (message.reply_to, principal, principal),
            ).fetchone()
        )
        bound_self = principal == message.recipient and (visible_internal or self_reply)
        if (
            (principal == message.recipient and not bound_self)
            or (message.recipient not in policy.message_peers and not bound_self)
            or not target
            or (principal not in target.message_peers and not bound_self)
            or "message.read" not in target.capabilities
        ):
            raise BridgeError("message_peer_denied", "Recipient is not an authorized peer")
        limits = self.config.messaging
        dispatch = message.dispatch
        if (
            self.config.visible_handoffs.enabled
            and not visible_internal
            and message.recipient in self.config.agents
            and message.kind in {"work", "question"}
        ):
            dispatch = True  # A caller's dispatch=false cannot select an invisible work route.
        if dispatch is None:
            dispatch = (
                message.kind not in {"answer", "result"} and message.recipient in limits.receivers
            )
        if dispatch and message.recipient in {"chatgpt", "grok_app", "local"}:
            if message.recipient not in limits.receivers:
                dispatch = False
        if len(message.body.encode()) > limits.max_body_bytes:
            raise BridgeError("payload_limit", "Message exceeds configured byte limit")
        wants_reply = message.request_reply
        if wants_reply is None:
            wants_reply = message.kind in {"question", "work"}
        if wants_reply and message.kind not in {"question", "work"}:
            raise BridgeError(
                "reply_loop", "Answers, results and notes cannot request auto replies"
            )
        recorded = self.store.db.execute(
            "SELECT m.id,EXISTS(SELECT 1 FROM message_jobs j "
            "WHERE j.message_id=m.id) AS dispatched "
            "FROM messages m WHERE m.sender=? AND m.idem=?",
            (principal, message.idempotency_key),
        ).fetchone()
        if recorded and (
            message.dispatch is None
            or (self.config.visible_handoffs.enabled and message.dispatch is False)
        ):
            dispatch = bool(recorded["dispatched"])
        if dispatch and not recorded:
            from kirabridge.permissions import decision

            receiver = limits.receivers.get(message.recipient)
            if not receiver:
                raise BridgeError("receiver_unavailable", "No automatic receiver for this identity")
            if not decision(self.config, message.recipient, "agent.execute")["automatic"]:
                raise BridgeError(
                    "approval_required", "Dieser Agentenauftrag benötigt deine Erlaubnis"
                )
            if (
                message.recipient not in self.config.agents
                or message.recipient not in target.agents
            ):
                raise BridgeError(
                    "agent_denied", "Receiver agent is not configured for this identity"
                )
        if validate_only:
            return None
        hashed = digest({**message.model_dump(), "dispatch": dispatch})
        message_id = message.message_id or str(uuid.uuid4())
        with self.store.transaction():
            previous = self.store.db.execute(
                "SELECT id,request_hash FROM messages WHERE sender=? AND idem=?",
                (principal, message.idempotency_key),
            ).fetchone()
            if previous:
                previous_hash = hashed
                if message.dispatch is None or (
                    self.config.visible_handoffs.enabled and message.dispatch is False
                ):
                    # Preserve the recorded dispatch decision on retries across
                    # upgrades, including old answers sent to managed receivers.
                    recorded_dispatch = bool(
                        self.store.db.execute(
                            "SELECT 1 FROM message_jobs WHERE message_id=?", (previous["id"],)
                        ).fetchone()
                    )
                    previous_hash = digest({**message.model_dump(), "dispatch": recorded_dispatch})
                if previous["request_hash"] != previous_hash:
                    raise BridgeError("idempotency_conflict", "Key belongs to a different message")
                route = self.store.db.execute(
                    "SELECT target FROM message_completion_routes WHERE message_id=?",
                    (previous["id"],),
                ).fetchone()
                if completion_target is not None and completion_target != (
                    route[0] if route else "default"
                ):
                    raise BridgeError(
                        "completion_route_conflict", "Original return target is fixed"
                    )
                return self.get(principal, previous["id"])
            if dispatch:
                self.store.assert_accepting()
            conversation = self.store.db.execute(
                "SELECT * FROM conversations WHERE id=?", (message.conversation_id,)
            ).fetchone()
            parties = {principal, message.recipient}
            members = self.voice_channel.check(principal, message.conversation_id)
            if members and message.recipient not in members:
                raise BridgeError("message_peer_denied", "Recipient is not a conversation member")
            if (
                conversation
                and not members
                and {conversation["party_a"], conversation["party_b"]} != parties
            ):
                raise BridgeError("not_found", "Conversation not found")
            parent = self._row(principal, message.reply_to) if message.reply_to else None
            depth, task_id = 0, message.task_id
            if parent:
                if (
                    parent["conversation_id"] != message.conversation_id
                    or parent["recipient"] != principal
                    or parent["sender"] != message.recipient
                ):
                    raise BridgeError("reply_conflict", "Reply must reverse the addressed message")
                depth = parent["depth"] + 1
                if task_id is not None and task_id != parent["task_id"]:
                    raise BridgeError("reply_conflict", "Reply must preserve the task reference")
                task_id = parent["task_id"]
            elif task_id:
                self.store.get(task_id, principal)
            if depth > limits.max_reply_depth and not members:
                raise BridgeError("reply_loop", "Conversation reply depth limit reached")
            position = (
                self.store.db.execute(
                    "SELECT count(*) FROM messages WHERE conversation_id=?",
                    (message.conversation_id,),
                ).fetchone()[0]
                + 1
            )
            if position > limits.max_conversation_messages and not members:
                # An accepted request must remain answerable, including legacy
                # conversations already at the limit. Only its first final reply
                # gets this bounded allowance; new work/notes cannot extend it.
                final_reply = (
                    parent
                    and parent["request_reply"]
                    and parent["kind"] in {"question", "work"}
                    and message.kind in {"answer", "result"}
                    and not wants_reply
                    and not self.store.db.execute(
                        "SELECT 1 FROM messages WHERE reply_to=? "
                        "AND sender=? AND recipient=? AND kind IN ('answer','result') LIMIT 1",
                        (parent["id"], principal, message.recipient),
                    ).fetchone()
                )
                if not final_reply:
                    raise BridgeError("conversation_full", "Conversation message limit reached")
            if (
                self.store.db.execute("SELECT count(*) FROM messages").fetchone()[0]
                >= limits.max_total
            ):
                raise BridgeError("message_store_full", "Message archive capacity reached")
            pending = self.store.db.execute(
                "SELECT count(*) FROM messages WHERE recipient=? AND acknowledged IS NULL",
                (message.recipient,),
            ).fetchone()[0]
            if pending >= limits.max_pending_per_recipient:
                raise BridgeError("message_queue_full", "Recipient queue is full")
            if self.store.db.execute("SELECT 1 FROM messages WHERE id=?", (message_id,)).fetchone():
                raise BridgeError("message_id_conflict", "Message ID is already reserved")
            now = time.time()
            if not conversation:
                self.store.db.execute(
                    "INSERT INTO conversations VALUES(?,?,?,?)",
                    (
                        message.conversation_id,
                        *(sorted(parties) if len(parties) == 2 else (principal, principal)),
                        now,
                    ),
                )
            self.store.db.execute(
                "INSERT INTO messages(id,conversation_id,position,sender,recipient,kind,body,idem,"
                "request_hash,reply_to,task_id,depth,request_reply,created) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    message_id,
                    message.conversation_id,
                    position,
                    principal,
                    message.recipient,
                    message.kind,
                    message.body,
                    message.idempotency_key,
                    hashed,
                    message.reply_to,
                    task_id,
                    depth,
                    int(wants_reply),
                    now,
                ),
            )
            if dispatch:
                self.store.db.execute(
                    "INSERT INTO message_completion_routes(message_id,target) VALUES(?,?)",
                    (message_id, completion_target or "default"),
                )
                self.store.db.execute(
                    "INSERT INTO message_jobs(message_id,state) VALUES(?,'queued')", (message_id,)
                )
            self._event(
                message_id,
                "message.queued",
                principal,
                {
                    "recipient": message.recipient,
                    "conversation_id": message.conversation_id,
                    "position": position,
                    "content_sha256": digest(message.body),
                    "automatic_dispatch": dispatch,
                },
            )
        self.wake.set()
        return self.get(principal, message_id)

    def receive(self, principal, after=0, limit=20, conversation_id=None):
        self._identity(principal, "message.read")
        if conversation_id:
            self.voice_channel.check(principal, conversation_id)
        if after < 0 or not 1 <= limit <= 50:
            raise BridgeError("invalid_cursor", "Use nonnegative cursor and limit 1..50")
        with self.store.transaction():
            rows = self.store.db.execute(
                "SELECT id,seq,delivered FROM messages WHERE recipient=? AND seq>? "
                "AND acknowledged IS NULL AND (? IS NULL OR conversation_id=?) "
                "ORDER BY seq LIMIT ?",
                (principal, after, conversation_id, conversation_id, limit),
            ).fetchall()
            for row in rows:
                if row["delivered"] is None:
                    receipt = str(uuid.uuid4())
                    self.store.db.execute(
                        "UPDATE messages SET delivered=?,receipt=? WHERE id=?",
                        (time.time(), receipt, row["id"]),
                    )
                    self._event(row["id"], "message.delivered", principal, {"receipt": receipt})
        return {
            "messages": [self.get(principal, row["id"]) for row in rows],
            "next_cursor": rows[-1]["seq"] if rows else after,
            "redelivery": "Unacknowledged messages remain available with the same ID and receipt.",
        }

    async def wait(self, principal, after=0, limit=20, conversation_id=None, wait_seconds=0):
        if not 0 <= wait_seconds <= 20:
            raise BridgeError("invalid_wait", "Long poll is bounded to 20 seconds")
        deadline = asyncio.get_running_loop().time() + wait_seconds
        while True:
            self.wake.clear()
            result = self.receive(principal, after, limit, conversation_id)
            remaining = deadline - asyncio.get_running_loop().time()
            if result["messages"] or remaining <= 0:
                return result
            try:
                await asyncio.wait_for(self.wake.wait(), min(remaining, 2))
            except TimeoutError:
                pass

    def ack(self, principal, message_id, receipt):
        self._identity(principal, "message.ack")
        with self.store.transaction():
            row = self._row(principal, message_id)
            if row["recipient"] != principal:
                raise BridgeError("not_found", "Incoming message not found")
            if not row["receipt"] or receipt != row["receipt"]:
                raise BridgeError("receipt_conflict", "A matching delivery receipt is required")
            if row["acknowledged"] is None:
                self.store.db.execute(
                    "UPDATE messages SET acknowledged=? WHERE id=?", (time.time(), message_id)
                )
                self._event(message_id, "message.acknowledged", principal, {"receipt": receipt})
        return self.get(principal, message_id)

    def conversation(self, principal, conversation_id, after=0, limit=50):
        self._identity(principal, "message.read")
        if after < 0 or not 1 <= limit <= 50:
            raise BridgeError("invalid_cursor", "Use nonnegative cursor and limit 1..50")
        row = self.store.db.execute(
            "SELECT * FROM conversations WHERE id=?", (conversation_id,)
        ).fetchone()
        members = self.voice_channel.check(principal, conversation_id)
        if row is None or (not members and principal not in {row["party_a"], row["party_b"]}):
            raise BridgeError("not_found", "Conversation not found")
        rows = self.store.db.execute(
            "SELECT id,seq FROM messages WHERE conversation_id=? AND seq>? ORDER BY seq LIMIT ?",
            (conversation_id, after, limit),
        ).fetchall()
        return {
            "conversation_id": conversation_id,
            "participants": members or [row["party_a"], row["party_b"]],
            "append_only": bool(members),
            "messages": [self.get(principal, r["id"]) for r in rows],
            "next_cursor": rows[-1]["seq"] if rows else after,
        }

    def events(self, principal, message_id, after=0):
        self.get(principal, message_id)
        if after < 0:
            raise BridgeError("invalid_cursor", "Cursor must be nonnegative")
        return {
            "events": [
                {**dict(row), "evidence": json.loads(row["evidence"])}
                for row in self.store.db.execute(
                    "SELECT * FROM message_events WHERE message_id=? AND seq>? "
                    "ORDER BY seq LIMIT 100",
                    (message_id, after),
                )
            ]
        }
