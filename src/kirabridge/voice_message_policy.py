"""Immediate normal messages; immutable retry behavior for historical voice buffers."""

import json
import time

from kirabridge.bridge_core.models import BridgeError, digest
from kirabridge.session_input_policy import SUFFIX
from kirabridge.voice_channel import VOICE_PRINCIPALS


class VoiceMessagePolicy:
    def __init__(self, channel):
        self.channel, self.store = channel, channel.store
        self.teams = None

    def _deliver(self, principal, message, target, transport, message_id=None, validate_only=False):
        if transport == "team":
            result = self.teams._send(
                principal, message, message_id=message_id, validate_only=validate_only
            )
            return (
                {**result, "transport": "team"}
                if result and principal in VOICE_PRINCIPALS
                else result
            )
        return self.channel._send(
            principal, message, completion_target=target, validate_only=validate_only
        )

    def _released(self, principal, row):
        request = json.loads(row["request"])
        if request.get("_transport") == "team":
            self.teams._team(principal, request["team_id"])
            return {**self.teams._message(request["team_id"], row["id"]), "transport": "team"}
        return self.channel.get(principal, row["id"])

    def expire(self):
        with self.store.transaction():
            rows = self.store.db.execute(
                "SELECT id,sender FROM voice_message_buffers WHERE state='waiting' AND expires<=?",
                (time.time(),),
            ).fetchall()
            for row in rows:
                self.store.db.execute(
                    "UPDATE voice_message_buffers SET state='expired' WHERE id=?", (row["id"],)
                )
                self.store.audit("message.expired", row["sender"], None, {"message_id": row["id"]})

    def get(self, principal, message_id):
        self.expire()
        row = self.store.db.execute(
            "SELECT * FROM voice_message_buffers WHERE id=? AND sender=?", (message_id, principal)
        ).fetchone()
        if not row:
            return None
        request = json.loads(row["request"])
        if row["state"] == "released" and request.get("_transport") == "team":
            return self._released(principal, row)
        return {
            "api_version": "1",
            "id": row["id"],
            "sender": principal,
            "recipient": request["recipient"],
            "conversation_id": request.get("conversation_id"),
            "transport": request.get("_transport", "message"),
            "body": request["body"],
            "kind": request["kind"],
            "request_reply": request.get("request_reply", False),
            "created": row["created"],
            "message_buffer": {
                "state": row["state"],
                "expires": row["expires"],
                "released": row["released"],
            },
            "delivered": None,
            "acknowledged": None,
            "processing": None,
        }

    def send(self, principal, message, completion_target, *, transport="message"):
        """New user requests are immediate; historical buffers never auto-release."""
        self.expire()
        key = (
            message.idempotency_key
            if transport == "message"
            else "team-" + digest({"team_id": message.team_id, "key": message.idempotency_key})
        )
        row = self.store.db.execute(
            "SELECT * FROM voice_message_buffers WHERE sender=? AND idem=?", (principal, key)
        ).fetchone()
        if row:
            hashed = digest({"transport": transport, **message.model_dump()})
            if row["request_hash"] != hashed:
                raise BridgeError("idempotency_conflict", "Key belongs to a different message")
            if row["completion_target"] != completion_target:
                raise BridgeError("completion_route_conflict", "Original return target is fixed")
            if row["state"] == "released":
                return self._released(principal, row)
            return self.get(principal, row["id"])
        self.channel.security.principal(
            principal, "message.send" if transport == "message" else "team.write"
        )
        return self._deliver(principal, message, completion_target, transport)

    def release(self, principal, message_id, token):
        from kirabridge.message_manager import MessageSend

        self.channel.security.principal(principal)
        self.expire()
        if token != SUFFIX:
            raise BridgeError("invalid_release_token", "The exact go-go-go token is required")
        with self.store.transaction():
            row = self.store.db.execute(
                "SELECT * FROM voice_message_buffers WHERE id=? AND sender=?",
                (message_id, principal),
            ).fetchone()
            if not row:
                raise BridgeError("not_found", "Voice message buffer not found")
            if row["state"] == "expired" or (
                row["state"] == "waiting" and row["expires"] <= time.time()
            ):
                raise BridgeError("message_buffer_expired", "Voice message buffer expired")
            if row["state"] == "released":
                return self._released(principal, row)
            payload = json.loads(row["request"])
            transport = payload.pop("_transport", "message")
            if transport == "team":
                from kirabridge.team_manager.models import TeamMessageSend

                request = TeamMessageSend.model_validate(payload)
            else:
                request = MessageSend.model_validate(payload)
            self.store.db.execute(
                "UPDATE voice_message_buffers SET state='released',released=? WHERE id=?",
                (time.time(), message_id),
            )
            result = self._deliver(
                principal, request, row["completion_target"], transport, message_id=message_id
            )
            self.store.audit("message.released", principal, None, {"message_id": message_id})
        return result
