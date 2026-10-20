"""Participant-based voice conversations and immutable shared message archives."""

from kirabridge.bridge_core.models import BridgeError

IDENTITIES = {
    "grok_app": {"name": "Eve", "model": "Grok", "role": "voice", "dictation_only": True},
    "grok": {"name": "Grok Build", "model": "Grok", "role": "terminal"},
    "chatgpt": {"name": "Kira", "model": "ChatGPT", "role": "voice"},
    "codex": {"name": "Codex", "model": "ChatGPT", "role": "terminal"},
    "local": {"name": "Daniel", "role": "human"},
}
VOICE_PRINCIPALS = frozenset({"grok_app", "chatgpt"})
MEMBERS = {"grok_app": "voice", "chatgpt": "voice", "local": "human"}

SCHEMA = [
    "CREATE TABLE IF NOT EXISTS conversation_members ("
    "conversation_id TEXT NOT NULL REFERENCES conversations(id), principal TEXT NOT NULL, "
    "role TEXT NOT NULL, PRIMARY KEY(conversation_id,principal))",
    "CREATE TABLE IF NOT EXISTS voice_message_buffers ("
    "id TEXT PRIMARY KEY, sender TEXT NOT NULL, idem TEXT NOT NULL, request_hash TEXT NOT NULL, "
    "request TEXT NOT NULL, completion_target TEXT, state TEXT NOT NULL, "
    "created REAL NOT NULL, expires REAL NOT NULL, released REAL, "
    "UNIQUE(sender,idem))",
    "CREATE INDEX IF NOT EXISTS voice_message_expiry ON voice_message_buffers(state,expires)",
    "CREATE TRIGGER IF NOT EXISTS shared_message_no_delete BEFORE DELETE ON messages "
    "WHEN EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id=OLD.conversation_id) "
    "BEGIN SELECT RAISE(ABORT,'Shared conversation is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS shared_message_no_edit BEFORE UPDATE OF "
    "id,seq,conversation_id,position,sender,recipient,kind,body,created,reply_to,task_id,"
    "depth,request_reply,idem,request_hash ON messages "
    "WHEN EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id=OLD.conversation_id) "
    "BEGIN SELECT RAISE(ABORT,'Shared conversation is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS shared_member_no_delete BEFORE DELETE ON conversation_members "
    "BEGIN SELECT RAISE(ABORT,'Shared membership is permanent'); END",
    "CREATE TRIGGER IF NOT EXISTS shared_member_no_edit BEFORE UPDATE ON conversation_members "
    "BEGIN SELECT RAISE(ABORT,'Shared membership is permanent'); END",
]


class VoiceChannel:
    def __init__(self, config, store):
        self.config, self.store = config, store
        self.ensure()

    def ensure(self):
        config, store = self.config, self.store
        settings = config.voice_channel
        if settings.enabled and VOICE_PRINCIPALS <= config.principals.keys():
            import time

            with store.transaction():
                row = store.db.execute(
                    "SELECT party_a,party_b FROM conversations WHERE id=?",
                    (settings.conversation_id,),
                ).fetchone()
                if row and set(row) != VOICE_PRINCIPALS:
                    raise BridgeError("conversation_conflict", "Shared channel ID is already used")
                store.db.execute(
                    "INSERT OR IGNORE INTO conversations VALUES(?,?,?,?)",
                    (settings.conversation_id, *sorted(VOICE_PRINCIPALS), time.time()),
                )
                for name, role in MEMBERS.items():
                    store.db.execute(
                        "INSERT OR IGNORE INTO conversation_members VALUES(?,?,?)",
                        (settings.conversation_id, name, role),
                    )

    def members(self, conversation_id):
        return [
            row[0]
            for row in self.store.db.execute(
                "SELECT principal FROM conversation_members WHERE conversation_id=? "
                "ORDER BY principal",
                (conversation_id,),
            )
        ]

    def check(self, principal, conversation_id):
        members = self.members(conversation_id)
        if members and principal not in members:
            raise BridgeError("not_found", "Conversation not found")
        return members

    def route(self, principal, message):
        settings = self.config.voice_channel
        if settings.enabled and {principal, message.recipient} == VOICE_PRINCIPALS:
            if not self.members(settings.conversation_id):
                self.ensure()
            message = message.model_copy(
                update={
                    "conversation_id": settings.conversation_id,
                    "dispatch": False,
                }
            )
        members = self.check(principal, message.conversation_id)
        if members:
            if message.recipient not in members or message.dispatch or message.task_id:
                raise BridgeError("message_peer_denied", "Shared voice channel is participant-only")
            message = message.model_copy(update={"dispatch": False})
        elif message.conversation_id == settings.conversation_id:
            raise BridgeError("not_found", "Shared voice channel is unavailable")
        return message

    def profile(self, principal):
        return {
            "identity": IDENTITIES.get(principal, {"name": principal, "role": "other"}),
            "voice_message_gate": False,
            "shared_conversation_id": self.config.voice_channel.conversation_id
            if principal in MEMBERS and self.config.voice_channel.enabled
            else None,
            "eve_instructions": "Eve übermittelt ausschließlich Daniels Diktat unverändert. "
            "Explizite Nutzeraufträge ohne zusätzliches Sondertoken weitergeben; "
            "normale Berechtigungen bleiben erforderlich.",
        }
