"""Durable, permission-scoped teams; team content never becomes executable code."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import time
import uuid
from pathlib import Path

from kirabridge.bridge_core.models import BridgeError, TaskRequest, canonical, digest
from kirabridge.team_manager.models import (
    TeamCreate,
    TeamMessageSend,
    TeamRoleSet,
    TeamWorkClaim,
    TeamWorkComplete,
    TeamWorkCreate,
    TeamWorkReprocess,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS teams (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL,
 coordinator TEXT NOT NULL, revision INTEGER NOT NULL, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS team_members (
 team_id TEXT NOT NULL REFERENCES teams(id), principal TEXT NOT NULL,
 role TEXT NOT NULL, active INTEGER NOT NULL, PRIMARY KEY(team_id,principal)
);
CREATE TABLE IF NOT EXISTS team_operations (
 team_id TEXT NOT NULL REFERENCES teams(id), principal TEXT NOT NULL, operation TEXT NOT NULL,
 idem TEXT NOT NULL, request_hash TEXT NOT NULL, object_id TEXT NOT NULL,
 PRIMARY KEY(team_id,principal,operation,idem)
);
CREATE TABLE IF NOT EXISTS team_messages (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
 team_id TEXT NOT NULL REFERENCES teams(id), sender TEXT NOT NULL, recipient TEXT NOT NULL,
 kind TEXT NOT NULL, body TEXT NOT NULL, reply_to TEXT REFERENCES team_messages(id),
 created REAL NOT NULL, acknowledged REAL
);
CREATE INDEX IF NOT EXISTS team_message_order ON team_messages(team_id,seq);
CREATE INDEX IF NOT EXISTS team_message_inbox ON team_messages(recipient,acknowledged);
CREATE TABLE IF NOT EXISTS team_work (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
 team_id TEXT NOT NULL REFERENCES teams(id), assigned_by TEXT NOT NULL, assignee TEXT NOT NULL,
 title TEXT NOT NULL, body TEXT NOT NULL, parent_id TEXT REFERENCES team_work(id),
 root_id TEXT NOT NULL, depth INTEGER NOT NULL, state TEXT NOT NULL,
 core_task_id TEXT UNIQUE, core_request_hash TEXT, result TEXT,
 evidence TEXT NOT NULL DEFAULT '{}', error TEXT,
 created REAL NOT NULL, claimed REAL, started REAL, finished REAL
);
CREATE INDEX IF NOT EXISTS team_work_order ON team_work(team_id,seq);
CREATE INDEX IF NOT EXISTS team_work_roots ON team_work(root_id);
CREATE INDEX IF NOT EXISTS team_work_queue ON team_work(state,seq);
CREATE TABLE IF NOT EXISTS team_events (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, team_id TEXT NOT NULL REFERENCES teams(id),
 at REAL NOT NULL, kind TEXT NOT NULL, principal TEXT NOT NULL,
 object_id TEXT, metadata TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS team_work_reprocess_history (
 id TEXT PRIMARY KEY, work_id TEXT UNIQUE NOT NULL REFERENCES team_work(id),
 team_id TEXT NOT NULL REFERENCES teams(id), principal TEXT NOT NULL,
 core_task_id TEXT NOT NULL, at REAL NOT NULL, native_result_sha256 TEXT NOT NULL,
 previous_state TEXT NOT NULL, previous_result TEXT, previous_evidence TEXT NOT NULL,
 previous_error TEXT, previous_started REAL, previous_finished REAL
);
"""

TERMINAL = {"completed", "failed", "unknown", "cancelled", "blocked"}
WRITERS = {"coordinator", "worker", "reviewer"}
ROLES = WRITERS | {"observer"}
NAME = re.compile(r"^[a-z][a-z0-9_-]{0,79}$")
ERROR = re.compile(r"^[a-z][a-z0-9_]{0,79}$")


def _bounded_text(text, limit):
    if not isinstance(text, str):
        return ""
    return text.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def _safe_evidence(value, depth=0):
    """Internal evidence contains identifiers/codes, never credentials or raw provider errors."""
    if depth > 5:
        return None
    if isinstance(value, dict):
        return {
            str(key)[:80]: _safe_evidence(item, depth + 1)
            for key, item in list(value.items())[:48]
            if not re.search(
                r"token|secret|password|authorization|api.?key|raw|body|prompt", str(key), re.I
            )
        }
    if isinstance(value, list):
        return [_safe_evidence(item, depth + 1) for item in value[:32]]
    if isinstance(value, str):
        return _bounded_text(value, 512)
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value is None or isinstance(value, bool | int | float):
        return value
    return None


def _native_evidence(value):
    """Only transport/turn facts belong in the shared view of an underlying private task."""
    if not isinstance(value, dict):
        return {}
    allowed = {
        "kind",
        "event",
        "session_id",
        "thread_id",
        "sessionId",
        "pid",
        "exit_code",
        "state",
        "scope",
        "completion_scope",
        "execution_mode",
        "project_completion_verified",
        "provider_error_category",
        "core_result_sha256",
        "timed_out",
        "terminated",
        "agent_running",
    }
    return _safe_evidence({key: item for key, item in value.items() if key in allowed})


class TeamManager:
    interface_version = "1"

    def activation_work_count(self, *, active_only=False, context=None):
        db = context.db if context is not None else self.store.db
        states = (
            ("accepted", "running", "processing_result")
            if active_only
            else ("queued", "dispatching", "created", "accepted", "running", "processing_result")
        )
        return db.execute(
            "SELECT count(*) FROM team_work WHERE state IN (" + ",".join("?" for _ in states) + ")",
            states,
        ).fetchone()[0]

    def operator_work_count(self):
        return self.store.db.execute(
            "SELECT count(*) FROM team_work WHERE state IN "
            "('queued','dispatching','created','accepted','running','processing_result')"
        ).fetchone()[0]

    def __init__(self, bridge):
        self.bridge = bridge
        self.config, self.store, self.security = bridge.config, bridge.store, bridge.security
        self.wake = asyncio.Event()
        with self.store.transaction():
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    self.store.db.execute(statement)
            columns = {row["name"] for row in self.store.db.execute("PRAGMA table_info(team_work)")}
            if "core_request_hash" not in columns:
                self.store.db.execute("ALTER TABLE team_work ADD COLUMN core_request_hash TEXT")

    def _principal(self, principal, capability):
        if not self.config.team.enabled:
            raise BridgeError("team_disabled", "Team collaboration is disabled")
        if principal not in self.config.team.workers:
            raise BridgeError("not_found", "Team not found")
        return self.security.principal(principal, capability)

    def _team(self, principal, team_id, capability="team.read", write=False, manage=False):
        self._principal(principal, capability)
        row = self.store.db.execute(
            "SELECT t.*,m.role,m.active FROM teams t JOIN team_members m ON m.team_id=t.id "
            "WHERE t.id=? AND m.principal=?",
            (team_id, principal),
        ).fetchone()
        if row is None or not row["active"] or principal not in self.config.team.workers:
            raise BridgeError("not_found", "Team not found")
        if manage and principal not in {row["owner"], row["coordinator"]}:
            raise BridgeError("team_role_denied", "Only the owner or coordinator may manage roles")
        if write and row["role"] not in WRITERS:
            raise BridgeError("team_role_denied", "Observers may only read shared team data")
        return row

    def _member(self, team_id, principal, *, writable=False):
        row = self.store.db.execute(
            "SELECT * FROM team_members WHERE team_id=? AND principal=? AND active=1",
            (team_id, principal),
        ).fetchone()
        if row is None or principal not in self.config.team.workers:
            raise BridgeError("team_member_denied", "Recipient is not an active authorized member")
        if writable and row["role"] not in WRITERS:
            raise BridgeError("team_role_denied", "Observers cannot receive work or messages")
        if principal not in self.config.principals:
            raise BridgeError("team_member_denied", "Member identity is not configured")
        return row

    def _size(self, text, limit):
        if len(text.encode("utf-8")) > limit:
            raise BridgeError("payload_limit", "Team payload exceeds the configured byte limit")

    def _automatic(self, principal, capability="team.write"):
        policy = self._principal(principal, capability)
        if policy.approval_mode != "automatic":
            raise BridgeError(
                "approval_required", "Team writes require local automatic authorization"
            )

    def _page(self, after, limit):
        if isinstance(after, bool) or not isinstance(after, int) or not 0 <= after < 2**63:
            raise BridgeError("invalid_cursor", "Use a nonnegative integer cursor")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise BridgeError("invalid_cursor", "Use a page limit between 1 and 100")

    def _previous(self, principal, team_id, operation, request):
        row = self.store.db.execute(
            "SELECT request_hash,object_id FROM team_operations "
            "WHERE team_id=? AND principal=? AND operation=? AND idem=?",
            (team_id, principal, operation, request.idempotency_key),
        ).fetchone()
        if row and row["request_hash"] != digest(request.model_dump()):
            raise BridgeError("idempotency_conflict", "Key belongs to a different team operation")
        return row["object_id"] if row else None

    def _remember(self, principal, team_id, operation, request, object_id):
        self.store.db.execute(
            "INSERT INTO team_operations VALUES(?,?,?,?,?,?)",
            (
                team_id,
                principal,
                operation,
                request.idempotency_key,
                digest(request.model_dump()),
                object_id,
            ),
        )

    def _event(self, team_id, principal, kind, object_id=None, **metadata):
        self.store.db.execute(
            "INSERT INTO team_events(team_id,at,kind,principal,object_id,metadata) "
            "VALUES(?,?,?,?,?,?)",
            (team_id, time.time(), kind, principal, object_id, canonical(metadata)),
        )
        self.store.audit(
            kind, principal, None, {"team_id": team_id, "object_id": object_id, **metadata}
        )

    def _view_team(self, team_id):
        result = dict(
            self.store.db.execute("SELECT * FROM teams WHERE id=?", (team_id,)).fetchone()
        )
        result["api_version"] = "1"
        result["members"] = {
            row["principal"]: {
                "role": row["role"],
                "active": bool(row["active"]),
                "execution": "automatic"
                if self.config.team.workers.get(row["principal"])
                and self.config.team.workers[row["principal"]].agent
                else "manual",
            }
            for row in self.store.db.execute(
                "SELECT * FROM team_members WHERE team_id=? ORDER BY principal", (team_id,)
            )
        }
        return result

    def create(self, principal, request: TeamCreate):
        self._automatic(principal, "team.manage")
        members = dict(request.members)
        members.setdefault(principal, "worker")
        if len(members) > 16 or any(
            not NAME.fullmatch(member)
            or member not in self.config.team.workers
            or member not in self.config.principals
            for member in members
        ):
            raise BridgeError(
                "team_member_denied", "Members must belong to the operator participation roster"
            )
        if request.coordinator not in members:
            raise BridgeError("team_role_denied", "The coordinator must be a team member")
        if any(
            role == "coordinator" and member != request.coordinator
            for member, role in members.items()
        ):
            raise BridgeError("team_role_denied", "Select exactly one coordinator")
        members[request.coordinator] = "coordinator"
        self._size(request.name, 256)
        with self.store.transaction():
            prior = self._previous(principal, request.team_id, "create", request)
            if prior:
                self._team(principal, prior)
                return self._view_team(prior)
            if self.store.db.execute(
                "SELECT 1 FROM teams WHERE id=?", (request.team_id,)
            ).fetchone():
                raise BridgeError("team_id_conflict", "Team ID is already reserved")
            if (
                self.store.db.execute("SELECT count(*) FROM teams").fetchone()[0]
                >= self.config.team.max_teams
            ):
                raise BridgeError("team_store_full", "The team archive is full")
            self.store.db.execute(
                "INSERT INTO teams VALUES(?,?,?,?,1,?)",
                (request.team_id, request.name, principal, request.coordinator, time.time()),
            )
            self.store.db.executemany(
                "INSERT INTO team_members VALUES(?,?,?,1)",
                [(request.team_id, member, role) for member, role in members.items()],
            )
            self._remember(principal, request.team_id, "create", request, request.team_id)
            self._event(request.team_id, principal, "team.created", coordinator=request.coordinator)
        return self.get(principal, request.team_id)

    def list(self, principal):
        self._principal(principal, "team.read")
        rows = self.store.db.execute(
            "SELECT t.id FROM teams t JOIN team_members m ON m.team_id=t.id "
            "WHERE m.principal=? AND m.active=1 ORDER BY t.created,t.id",
            (principal,),
        ).fetchall()
        return {"teams": [self._view_team(row["id"]) for row in rows]}

    def get(self, principal, team_id):
        self._team(principal, team_id)
        return self._view_team(team_id)

    def set_role(self, principal, request: TeamRoleSet):
        self._automatic(principal)
        with self.store.transaction():
            team = self._team(principal, request.team_id, "team.write", manage=True)
            prior = self._previous(principal, request.team_id, "role", request)
            if prior:
                return self._view_team(request.team_id)
            if team["revision"] != request.expected_revision:
                raise BridgeError(
                    "team_revision_conflict", "Team roles changed; read the current revision"
                )
            if (
                request.member not in self.config.team.workers
                or request.member not in self.config.principals
            ):
                raise BridgeError(
                    "team_member_denied", "Member is outside the operator participation roster"
                )
            if request.member == team["owner"] and not request.active:
                raise BridgeError("team_owner_protected", "The immutable owner must remain active")
            if request.member == team["coordinator"] and (
                request.role != "coordinator" or not request.active
            ):
                raise BridgeError(
                    "team_coordinator_required", "Select a different coordinator first"
                )
            if request.role == "coordinator" and not request.active:
                raise BridgeError("team_coordinator_required", "The coordinator must be active")
            exists = self.store.db.execute(
                "SELECT 1 FROM team_members WHERE team_id=? AND principal=?",
                (request.team_id, request.member),
            ).fetchone()
            if (
                not exists
                and self.store.db.execute(
                    "SELECT count(*) FROM team_members WHERE team_id=?", (request.team_id,)
                ).fetchone()[0]
                >= 16
            ):
                raise BridgeError("team_member_limit", "A team supports at most 16 identities")
            if request.role == "coordinator":
                self.store.db.execute(
                    "UPDATE team_members SET role='worker' WHERE team_id=? AND role='coordinator'",
                    (request.team_id,),
                )
                self.store.db.execute(
                    "UPDATE teams SET coordinator=? WHERE id=?", (request.member, request.team_id)
                )
            self.store.db.execute(
                "INSERT INTO team_members VALUES(?,?,?,?) ON CONFLICT(team_id,principal) "
                "DO UPDATE SET role=excluded.role,active=excluded.active",
                (request.team_id, request.member, request.role, int(request.active)),
            )
            self.store.db.execute(
                "UPDATE teams SET revision=revision+1 WHERE id=?", (request.team_id,)
            )
            self._remember(principal, request.team_id, "role", request, request.team_id)
            self._event(
                request.team_id,
                principal,
                "team.role_changed",
                member=request.member,
                role=request.role,
                active=request.active,
            )
        self.wake.set()
        return self.get(principal, request.team_id)

    def _message(self, team_id, message_id):
        row = self.store.db.execute(
            "SELECT * FROM team_messages WHERE id=? AND team_id=?", (message_id, team_id)
        ).fetchone()
        if row is None:
            raise BridgeError("not_found", "Team message not found")
        return dict(row)

    def send(self, principal, request: TeamMessageSend):
        from kirabridge.message_manager import MessageSend
        from kirabridge.voice_channel import VOICE_PRINCIPALS

        self._team(principal, request.team_id, "team.write", write=True)
        self._member(request.team_id, request.recipient, writable=True)
        if {principal, request.recipient} == VOICE_PRINCIPALS:
            return self.bridge.messages.send(
                principal,
                MessageSend(
                    recipient=request.recipient,
                    conversation_id=self.config.voice_channel.conversation_id,
                    idempotency_key="voice-team-"
                    + digest(
                        {
                            "team_id": request.team_id,
                            "key": request.idempotency_key,
                        }
                    ),
                    body=request.body,
                    kind=request.kind,
                    reply_to=request.reply_to,
                ),
            )
        return self.bridge.messages.voice_policy.send(principal, request, None, transport="team")

    def _send(self, principal, request, *, message_id=None, validate_only=False):
        self._automatic(principal)
        self._size(request.body, self.config.team.max_body_bytes)
        with self.store.transaction():
            self._team(principal, request.team_id, "team.write", write=True)
            self._member(request.team_id, request.recipient, writable=True)
            if validate_only:
                return None
            prior = self._previous(principal, request.team_id, "message", request)
            if prior:
                return self._message(request.team_id, prior)
            if request.reply_to:
                parent = self._message(request.team_id, request.reply_to)
                if parent["recipient"] != principal or parent["sender"] != request.recipient:
                    raise BridgeError("reply_conflict", "Reply must reverse the addressed message")
            if (
                self.store.db.execute("SELECT count(*) FROM team_messages").fetchone()[0]
                >= self.config.team.max_messages
            ):
                raise BridgeError("message_store_full", "Team message archive capacity reached")
            count = self.store.db.execute(
                "SELECT count(*) FROM team_messages WHERE recipient=? AND acknowledged IS NULL",
                (request.recipient,),
            ).fetchone()[0]
            if count >= self.config.team.max_pending_per_member:
                raise BridgeError("message_queue_full", "Member message inbox is full")
            message_id = message_id or "tm-" + uuid.uuid4().hex
            self.store.db.execute(
                "INSERT INTO team_messages(id,team_id,sender,recipient,kind,body,reply_to,created) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    message_id,
                    request.team_id,
                    principal,
                    request.recipient,
                    request.kind,
                    request.body,
                    request.reply_to,
                    time.time(),
                ),
            )
            self._remember(principal, request.team_id, "message", request, message_id)
            self._event(
                request.team_id,
                principal,
                "team.message_queued",
                message_id,
                recipient=request.recipient,
                content_sha256=digest(request.body),
            )
        self.wake.set()
        return self._message(request.team_id, message_id)

    def messages(self, principal, team_id, after=0, limit=50):
        self._team(principal, team_id)
        self._page(after, limit)
        rows = self.store.db.execute(
            "SELECT * FROM team_messages WHERE team_id=? AND seq>? ORDER BY seq LIMIT ?",
            (team_id, after, limit),
        ).fetchall()
        return {
            "messages": [dict(row) for row in rows],
            "next_cursor": rows[-1]["seq"] if rows else after,
        }

    def ack(self, principal, team_id, message_id):
        with self.store.transaction():
            self._team(principal, team_id, "team.write", write=True)
            message = self._message(team_id, message_id)
            if message["recipient"] != principal:
                raise BridgeError("not_found", "Incoming team message not found")
            if message["acknowledged"] is None:
                self.store.db.execute(
                    "UPDATE team_messages SET acknowledged=? WHERE id=?", (time.time(), message_id)
                )
                self._event(team_id, principal, "team.message_acknowledged", message_id)
        return self._message(team_id, message_id)

    def _work(self, work_id):
        row = self.store.db.execute("SELECT * FROM team_work WHERE id=?", (work_id,)).fetchone()
        if row is None:
            raise BridgeError("not_found", "Team work not found")
        result = dict(row)
        result["evidence"] = json.loads(result["evidence"])
        result.pop("core_request_hash")
        return result

    def delegate(self, principal, request: TeamWorkCreate):
        self._automatic(principal)
        self._size(request.body, self.config.team.max_body_bytes)
        self._size(request.title, 256)
        with self.store.transaction():
            self._team(principal, request.team_id, "team.write", write=True)
            self._member(request.team_id, request.assignee, writable=True)
            prior = self._previous(principal, request.team_id, "work", request)
            if prior:
                return self._work(prior)
            self.store.assert_accepting()
            work_id = "tw-" + uuid.uuid4().hex
            root_id, depth = work_id, 0
            if request.parent_id:
                parent = self._work(request.parent_id)
                if parent["team_id"] != request.team_id:
                    raise BridgeError("not_found", "Parent team work not found")
                if parent["assignee"] != principal:
                    raise BridgeError(
                        "team_parent_denied", "Only the actual assignee may extend a work chain"
                    )
                root_id, depth = parent["root_id"], parent["depth"] + 1
            if depth > self.config.team.max_hops:
                raise BridgeError("team_hop_limit", "Delegation depth limit reached")
            if (
                self.store.db.execute(
                    "SELECT count(*) FROM team_work WHERE root_id=?", (root_id,)
                ).fetchone()[0]
                >= self.config.team.max_work_per_root
            ):
                raise BridgeError("team_work_limit", "Root work delegation budget reached")
            if (
                self.store.db.execute("SELECT count(*) FROM team_work").fetchone()[0]
                >= self.config.team.max_total_work
            ):
                raise BridgeError("team_store_full", "Team work archive capacity reached")
            pending = self.store.db.execute(
                "SELECT count(*) FROM team_work WHERE assignee=? AND state NOT IN "
                "('completed','failed','unknown','cancelled','blocked')",
                (request.assignee,),
            ).fetchone()[0]
            if pending >= self.config.team.max_pending_per_member:
                raise BridgeError("team_queue_full", "Member work queue is full")
            state = (
                "queued" if self.config.team.workers[request.assignee].agent else "queued_manual"
            )
            self.store.db.execute(
                "INSERT INTO team_work(id,team_id,assigned_by,assignee,title,body,parent_id,"
                "root_id,depth,state,created) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    work_id,
                    request.team_id,
                    principal,
                    request.assignee,
                    request.title,
                    request.body,
                    request.parent_id,
                    root_id,
                    depth,
                    state,
                    time.time(),
                ),
            )
            self._remember(principal, request.team_id, "work", request, work_id)
            self._event(
                request.team_id,
                principal,
                "team.work_created",
                work_id,
                assignee=request.assignee,
                parent_id=request.parent_id,
                root_id=root_id,
                depth=depth,
                content_sha256=digest(request.body),
            )
        self.wake.set()
        return self._work(work_id)

    def work_get(self, principal, team_id, work_id):
        self._team(principal, team_id)
        result = self._work(work_id)
        if result["team_id"] != team_id:
            raise BridgeError("not_found", "Team work not found")
        return result

    def work_list(self, principal, team_id, after=0, limit=50):
        self._team(principal, team_id)
        self._page(after, limit)
        rows = self.store.db.execute(
            "SELECT id,seq FROM team_work WHERE team_id=? AND seq>? ORDER BY seq LIMIT ?",
            (team_id, after, limit),
        ).fetchall()
        return {
            "work": [self._work(row["id"]) for row in rows],
            "next_cursor": rows[-1]["seq"] if rows else after,
        }

    def context(self, principal, team_id):
        """Recent shared work and the recipient's oldest pending messages, within 32 KiB.

        Reading context does not acknowledge receipt. An authenticated receiver
        may acknowledge its own included messages after reading the response.
        Existing paginated APIs retain their chronological ordering.
        """
        self._team(principal, team_id)
        team = self._view_team(team_id)
        work = [
            dict(row)
            for row in self.store.db.execute(
                "SELECT id,seq,assigned_by,assignee,title,state,parent_id,root_id,depth,"
                "result,created,finished FROM team_work WHERE team_id=? ORDER BY seq DESC LIMIT 16",
                (team_id,),
            )
        ]
        pending = self.store.db.execute(
            "SELECT * FROM team_messages WHERE team_id=? AND recipient=? "
            "AND acknowledged IS NULL ORDER BY seq LIMIT 16",
            (team_id, principal),
        ).fetchall()
        latest = self.store.db.execute(
            "SELECT * FROM team_messages WHERE team_id=? ORDER BY seq DESC LIMIT 16",
            (team_id,),
        ).fetchall()
        messages, seen = [], set()
        for row in [*pending, *latest]:
            if row["id"] not in seen:
                seen.add(row["id"])
                messages.append(dict(row))

        def snapshot(text_bytes):
            def excerpt(value):
                if not isinstance(value, str):
                    return value, False
                text = _bounded_text(value, text_bytes)
                return text, text != value

            team_view = dict(team)
            team_view["name"], team_view["name_truncated"] = excerpt(team["name"])
            result_work = []
            for source in work:
                item = dict(source)
                item["title"], item["title_truncated"] = excerpt(source["title"])
                item["result"], item["result_truncated"] = excerpt(source["result"])
                result_work.append(item)
            result_messages = []
            for source in messages:
                item = dict(source)
                item["body"], item["body_truncated"] = excerpt(source["body"])
                result_messages.append(item)
            truncated = (
                team_view["name_truncated"]
                or any(item["title_truncated"] or item["result_truncated"] for item in result_work)
                or any(item["body_truncated"] for item in result_messages)
            )
            return {
                "api_version": "1",
                "team": team_view,
                "work": result_work,
                "messages": result_messages,
                "truncated": truncated,
                "max_bytes": 32768,
                "selection": {
                    "work": "newest_16_first",
                    "messages": "oldest_16_own_unacknowledged_then_newest_16_shared_deduplicated",
                },
            }

        result = snapshot(2048)
        if len(canonical(result).encode("utf-8")) <= 32768:
            return result
        # Shrink text evenly instead of dropping recent work or pending message
        # identities behind a large body. Include JSON escaping in the budget.
        low, high = 0, 2048
        result = snapshot(0)
        if len(canonical(result).encode("utf-8")) > 32768:
            raise BridgeError("team_context_limit", "Team metadata exceeds the context byte limit")
        while low < high:
            middle = (low + high + 1) // 2
            candidate = snapshot(middle)
            if len(canonical(candidate).encode("utf-8")) <= 32768:
                low, result = middle, candidate
            else:
                high = middle - 1
        return result

    def work_claim(self, principal, request: TeamWorkClaim):
        with self.store.transaction():
            self._team(principal, request.team_id, "team.write", write=True)
            work = self.work_get(principal, request.team_id, request.work_id)
            if work["assignee"] != principal or self.config.team.workers[principal].agent:
                raise BridgeError(
                    "team_assignee_denied", "Only the manual assignee may acknowledge work"
                )
            prior = self._previous(principal, request.team_id, "work_claim", request)
            if prior:
                return work
            if not self.store.can_claim(work["created"]):
                self.store.assert_accepting()
            if work["state"] != "queued_manual":
                raise BridgeError("state_conflict", "Manual work is no longer awaiting receipt")
            self.store.db.execute(
                "UPDATE team_work SET state='accepted_manual',claimed=?,evidence=? WHERE id=?",
                (
                    time.time(),
                    canonical({"kind": "assignee_receipt", "principal": principal}),
                    request.work_id,
                ),
            )
            self._remember(principal, request.team_id, "work_claim", request, request.work_id)
            self._event(request.team_id, principal, "team.work_received", request.work_id)
        return self._work(request.work_id)

    def work_complete(self, principal, request: TeamWorkComplete):
        self._size(request.result, self.config.team.max_result_bytes)
        with self.store.transaction():
            self._team(principal, request.team_id, "team.write", write=True)
            work = self.work_get(principal, request.team_id, request.work_id)
            if work["assignee"] != principal or self.config.team.workers[principal].agent:
                raise BridgeError(
                    "team_assignee_denied", "Only the external assignee may report completion"
                )
            prior = self._previous(principal, request.team_id, "work_complete", request)
            if prior:
                return work
            if work["state"] not in {"queued_manual", "accepted_manual"}:
                raise BridgeError("state_conflict", "Manual work already has a terminal outcome")
            state = "completed" if request.success else "failed"
            evidence = {
                "kind": "assignee_report",
                "principal": principal,
                "project_completion_verified": False,
                "result_sha256": digest(request.result),
            }
            self.store.db.execute(
                "UPDATE team_work SET state=?,result=?,evidence=?,finished=? WHERE id=?",
                (state, request.result, canonical(evidence), time.time(), request.work_id),
            )
            self._remember(principal, request.team_id, "work_complete", request, request.work_id)
            self._event(
                request.team_id,
                principal,
                "team.work_" + state,
                request.work_id,
                result_sha256=digest(request.result),
                evidence="assignee_report",
            )
        return self._work(request.work_id)

    def work_reprocess(self, principal, request: TeamWorkReprocess):
        """Review the already proven native result again, without submitting a model turn.

        Only an explicit owner/coordinator request can reopen a zero-action
        result. The original core task is immutable; its exact request seal and
        UTF-8 result hash must match. An append-only snapshot preserves the old
        shared result/evidence while the existing dispatcher applies actions.
        """
        self._automatic(principal)
        with self.store.transaction():
            self._team(principal, request.team_id, "team.write", manage=True)
            work = self.work_get(principal, request.team_id, request.work_id)
            prior = self._previous(principal, request.team_id, "work_reprocess", request)
            if prior:
                return work
            if work["state"] != "completed":
                raise BridgeError("state_conflict", "Only completed team work can be reprocessed")
            if work["core_task_id"] is None or request.core_task_id != work["core_task_id"]:
                raise BridgeError("team_task_conflict", "The original linked core task is required")
            actions = work["evidence"].get("actions")
            if not isinstance(actions, list) or actions:
                raise BridgeError(
                    "team_reprocess_denied",
                    "Reprocessing requires explicit evidence of zero prior actions",
                )
            if self.store.db.execute(
                "SELECT 1 FROM team_work_reprocess_history WHERE work_id=?", (work["id"],)
            ).fetchone():
                raise BridgeError(
                    "team_reprocess_conflict",
                    "Reuse the existing result-reprocessing idempotency key",
                )
            self._member(request.team_id, work["assignee"], writable=True)
            self._automatic(work["assignee"])
            worker = self.config.team.workers[work["assignee"]]
            core = self.store.get(request.core_task_id)
            if (
                core["principal"] != work["assignee"]
                or core["operation"] != "agent.execute"
                or not worker.agent
                or core["args"].get("agent") != worker.agent
            ):
                raise BridgeError(
                    "team_task_conflict", "The original agent identity no longer matches"
                )
            self._check_sealed(work)
            native = core["result"]
            if (
                core["state"] != "completed"
                or not isinstance(native, dict)
                or native.get("success") is not True
            ):
                raise BridgeError(
                    "team_reprocess_denied",
                    "The original core task must prove successful completion",
                )
            text = native.get("text", native.get("final_message"))
            if not isinstance(text, str) or not text:
                raise BridgeError(
                    "team_reprocess_denied", "The original native result has no final text"
                )
            self._size(text, self.config.team.max_result_bytes)
            text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if text_hash != request.expected_result_sha256:
                raise BridgeError(
                    "team_result_conflict", "The expected native result SHA256 does not match"
                )
            snapshot_id = "tr-" + uuid.uuid4().hex
            self.store.db.execute(
                "INSERT INTO team_work_reprocess_history VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    snapshot_id,
                    work["id"],
                    request.team_id,
                    principal,
                    request.core_task_id,
                    time.time(),
                    text_hash,
                    work["state"],
                    work["result"],
                    canonical(work["evidence"]),
                    work["error"],
                    work["started"],
                    work["finished"],
                ),
            )
            retained_evidence = {**work["evidence"], "core_result_sha256": text_hash}
            self.store.db.execute(
                "UPDATE team_work SET state='processing_result',finished=NULL,evidence=? "
                "WHERE id=?",
                (canonical(retained_evidence), work["id"]),
            )
            self._remember(principal, request.team_id, "work_reprocess", request, work["id"])
            self._event(
                request.team_id,
                principal,
                "team.work_reprocessing_requested",
                work["id"],
                snapshot_id=snapshot_id,
                previous_state=work["state"],
                core_task_id=request.core_task_id,
                native_result_sha256=text_hash,
                previous_result_sha256=hashlib.sha256(
                    (work["result"] or "").encode("utf-8")
                ).hexdigest(),
                previous_evidence_sha256=digest(work["evidence"]),
                automatic_retry=False,
                execution_scope="existing_result_only",
            )
        self.wake.set()
        return self._work(request.work_id)

    def events(self, principal, team_id, after=0, limit=50):
        self._team(principal, team_id)
        self._page(after, limit)
        rows = self.store.db.execute(
            "SELECT * FROM team_events WHERE team_id=? AND seq>? ORDER BY seq LIMIT ?",
            (team_id, after, limit),
        ).fetchall()
        result = []
        for row in rows:
            event = dict(row)
            event["metadata"] = json.loads(event["metadata"])
            result.append(event)
        return {"events": result, "next_cursor": rows[-1]["seq"] if rows else after}

    def pending(self, limit=16):
        if not self.config.team.enabled:
            return []
        self._page(0, limit)
        rows = self.store.db.execute(
            "SELECT id FROM team_work WHERE state='queued' AND core_task_id IS NULL "
            "ORDER BY seq LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._work(row["id"]) for row in rows]

    def _execution_allowed(self, work):
        self._automatic(work["assigned_by"])
        self._team(work["assigned_by"], work["team_id"], "team.write", write=True)
        self._member(work["team_id"], work["assignee"], writable=True)
        worker = self.config.team.workers.get(work["assignee"])
        if not worker or not worker.agent or not worker.cwd:
            raise BridgeError("team_worker_unavailable", "No automatic worker is configured")
        policy = self.security.principal(work["assignee"], "agent.execute")
        if policy.approval_mode != "automatic" or worker.agent not in policy.agents:
            raise BridgeError("team_worker_denied", "Worker execution is not authorized")
        if worker.agent not in self.config.agents:
            raise BridgeError("agent_unavailable", "Worker adapter is not configured")
        return worker

    def claim(self, work_id):
        with self.store.transaction():
            work = self._work(work_id)
            if not self.store.can_claim(work["created"]):
                return None
            if work["state"] != "queued" or work["core_task_id"] is not None:
                return None
            try:
                self._execution_allowed(work)
            except BridgeError as exc:
                self._fail(work, "blocked", exc.code, {"reason": "execution_not_authorized"})
                return None
            count = self.store.db.execute(
                "SELECT count(*) FROM team_work WHERE core_task_id IS NOT NULL AND claimed>?",
                (time.time() - 3600,),
            ).fetchone()[0]
            if count >= self.config.team.max_runs_per_hour:
                self._fail(work, "blocked", "team_rate_limit", {"reason": "hourly_turn_limit"})
                return None
            core_id = "team-" + work["id"]
            self.store.db.execute(
                "UPDATE team_work SET state='dispatching',core_task_id=?,claimed=? WHERE id=?",
                (core_id, time.time(), work_id),
            )
            self._event(
                work["team_id"],
                work["assignee"],
                "team.work_dispatching",
                work_id,
                core_task_id=core_id,
                session_scope="existing_visible_terminal"
                if self.config.visible_handoffs.enabled
                else "separate_managed_session",
            )
        return self._work(work_id)

    def inflight(self, limit=32):
        self._page(0, limit)
        rows = self.store.db.execute(
            "SELECT id FROM team_work WHERE core_task_id IS NOT NULL "
            "AND state NOT IN ('completed','failed','unknown','cancelled','blocked') "
            "ORDER BY seq LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._work(row["id"]) for row in rows]

    def authorize_execution(self, core_task):
        row = self.store.db.execute(
            "SELECT id FROM team_work WHERE core_task_id=?", (core_task.get("id"),)
        ).fetchone()
        if row is None:
            policy = self.config.principals.get(core_task.get("principal"))
            if policy and policy.team_only_execution:
                raise BridgeError(
                    "team_task_required", "This worker may only execute sealed team tasks"
                )
            return
        work = self._work(row["id"])
        worker = self._execution_allowed(work)
        args = core_task.get("args", {})
        if (
            core_task.get("principal") != work["assignee"]
            or core_task.get("operation") != "agent.execute"
            or args.get("agent") != worker.agent
            or args.get("local_tools", False)
            or Path(args.get("cwd", "")).expanduser().absolute()
            != Path(worker.cwd).expanduser().absolute()
            or not isinstance(args.get("timeout"), int | float)
            or args["timeout"] > worker.timeout
        ):
            raise BridgeError(
                "team_task_conflict", "Linked task does not match the fixed worker scope"
            )
        self._check_sealed(work)

    def seal_request(self, work_id, request: TaskRequest):
        """Bind a dispatcher-created request before submission; cannot be changed after a crash."""
        with self.store.transaction():
            work = self._work(work_id)
            if request.task_id != work["core_task_id"] or request.operation != "agent.execute":
                raise BridgeError(
                    "team_task_conflict", "Request does not match the reserved team task"
                )
            request_hash = digest(request.model_dump())
            previous = self.store.db.execute(
                "SELECT core_request_hash FROM team_work WHERE id=?", (work_id,)
            ).fetchone()[0]
            if previous == request_hash:
                return
            if previous is not None or work["state"] != "dispatching":
                raise BridgeError(
                    "team_task_conflict", "The team request is already sealed or not dispatching"
                )
            self.store.db.execute(
                "UPDATE team_work SET core_request_hash=? WHERE id=?", (request_hash, work_id)
            )
            self._event(
                work["team_id"],
                work["assignee"],
                "team.request_sealed",
                work_id,
                request_sha256=request_hash,
            )

    def _check_sealed(self, work):
        row = self.store.db.execute(
            "SELECT w.core_request_hash,t.request_hash FROM team_work w LEFT JOIN tasks t "
            "ON t.id=w.core_task_id WHERE w.id=?",
            (work["id"],),
        ).fetchone()
        if not row["core_request_hash"] or row["core_request_hash"] != row["request_hash"]:
            raise BridgeError(
                "team_task_conflict", "The underlying task does not match its sealed request"
            )

    def bind_task(self, work_id, core_task):
        with self.store.transaction():
            work = self._work(work_id)
            worker = self.config.team.workers.get(work["assignee"])
            if (
                core_task.get("id") != work["core_task_id"]
                or core_task.get("principal") != work["assignee"]
                or core_task.get("operation") != "agent.execute"
                or not worker
                or core_task.get("args", {}).get("agent") != worker.agent
            ):
                raise BridgeError(
                    "team_task_conflict", "Linked task identity does not match team work"
                )
            self._check_sealed(work)
            if work["state"] in TERMINAL:
                return work
            state = core_task.get("state")
            if state not in {"created", "queued", "accepted", "running", *TERMINAL}:
                raise BridgeError("team_task_conflict", "Unsupported linked task state")
            shared_state = "processing_result" if state == "completed" else state
            evidence = {
                "kind": "core_task_observation",
                "core_task_id": core_task["id"],
                "core_state": state,
                "native_evidence": _native_evidence(core_task.get("evidence", {})),
                "project_completion_verified": False,
            }
            result = None
            if state == "completed":
                native = core_task.get("result") or {}
                if isinstance(native, dict):
                    result = native.get("text", native.get("final_message", ""))
                    if native.get("success") is True and isinstance(result, str):
                        evidence["core_result_sha256"] = hashlib.sha256(
                            result.encode("utf-8")
                        ).hexdigest()
                result = _bounded_text(result, self.config.team.max_result_bytes)
            error = None
            if isinstance(core_task.get("error"), dict):
                candidate = core_task["error"].get("code", "agent_failed")
                error = (
                    candidate
                    if isinstance(candidate, str) and ERROR.fullmatch(candidate)
                    else "agent_failed"
                )
            finished = core_task.get("finished") if state in TERMINAL - {"completed"} else None
            values = (
                shared_state,
                result,
                canonical(evidence),
                error,
                core_task.get("started"),
                finished,
            )
            previous = (
                work["state"],
                work["result"],
                canonical(work["evidence"]),
                work["error"],
                work["started"],
                work["finished"],
            )
            if values != previous:
                self.store.db.execute(
                    "UPDATE team_work SET state=?,result=?,evidence=?,error=?,started=?,finished=? "
                    "WHERE id=?",
                    (*values, work_id),
                )
                self._event(
                    work["team_id"],
                    work["assignee"],
                    "team.work_observed",
                    work_id,
                    state=shared_state,
                    core_task_id=core_task["id"],
                    evidence_sha256=digest(evidence),
                )
        return self._work(work_id)

    def finish(self, work_id, result, evidence):
        self._size(result, self.config.team.max_result_bytes)
        with self.store.transaction():
            work = self._work(work_id)
            if work["state"] == "completed" and work["result"] == result:
                return work
            if work["state"] != "processing_result":
                raise BridgeError(
                    "state_conflict", "Only a proven completed core turn may be finalized"
                )
            sanitized = _safe_evidence(evidence)
            sanitized["completion_scope"] = "agent_turn"
            sanitized["project_completion_verified"] = False
            core_result_hash = work["evidence"].get("core_result_sha256")
            if isinstance(core_result_hash, str) and re.fullmatch(
                r"[a-f0-9]{64}", core_result_hash
            ):
                sanitized["core_result_sha256"] = core_result_hash
            self._size(canonical(sanitized), self.config.team.max_result_bytes)
            self.store.db.execute(
                "UPDATE team_work SET state='completed',result=?,evidence=?,finished=? WHERE id=?",
                (result, canonical(sanitized), time.time(), work_id),
            )
            self._event(
                work["team_id"],
                work["assignee"],
                "team.work_completed",
                work_id,
                result_sha256=digest(result),
                evidence_sha256=digest(sanitized),
            )
        return self._work(work_id)

    def _fail(self, work, state, error_code, evidence):
        if state not in {"blocked", "failed", "unknown", "cancelled"}:
            raise BridgeError("state_conflict", "Unsupported terminal team state")
        code = (
            error_code
            if isinstance(error_code, str) and ERROR.fullmatch(error_code)
            else "team_failed"
        )
        sanitized = _safe_evidence(evidence)
        if work["state"] in TERMINAL:
            return
        self.store.db.execute(
            "UPDATE team_work SET state=?,error=?,evidence=?,finished=? WHERE id=?",
            (state, code, canonical(sanitized), time.time(), work["id"]),
        )
        self._event(
            work["team_id"],
            work["assignee"],
            "team.work_" + state,
            work["id"],
            error_code=code,
            evidence_sha256=digest(sanitized),
        )

    def fail(self, work_id, state, error_code, evidence):
        with self.store.transaction():
            self._fail(self._work(work_id), state, error_code, evidence)
        return self._work(work_id)
