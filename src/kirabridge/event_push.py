"""Optional host-subscribed webhooks over the immutable completion archive.

No callback is invented. A verified subscription must be bound before submission.
Webhook acknowledgement and payload receipt do not attest a specific chat UI turn.
This module is SDK-independent so the isolated MCP-2 adapter can reuse it.
"""

from __future__ import annotations

import asyncio
import base64
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from httpcore._backends.auto import AutoBackend

EVENT_NAME = "kirabridge.task.completed"


class EventError(Exception):
    def __init__(self, reason, code=-32602):
        super().__init__(reason)
        self.reason, self.code = reason, code


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def signing_key(secret):
    try:
        if not isinstance(secret, str) or not secret.startswith("whsec_"):
            raise ValueError()
        key = base64.b64decode(secret[6:], validate=True)
        if not 24 <= len(key) <= 64:
            raise ValueError()
        return key
    except (ValueError, TypeError):
        raise EventError("invalid_signing_secret") from None


def signed_headers(subscription, event_id, body, *, timestamp=None):
    timestamp = str(int(time.time() if timestamp is None else timestamp))
    message = event_id.encode() + b"." + timestamp.encode() + b"." + body
    keys = [subscription["secret"]]
    if subscription.get("old_secret") and subscription.get("old_until", 0) > time.time():
        keys.append(subscription["old_secret"])
    signatures = [
        "v1," + base64.b64encode(hmac.digest(signing_key(key), message, "sha256")).decode()
        for key in keys
    ]
    return {
        "Content-Type": "application/json",
        "webhook-id": event_id,
        "webhook-timestamp": timestamp,
        "webhook-signature": " ".join(signatures),
        "X-MCP-Subscription-Id": subscription["id"],
    }


def callback_host(url, allowed_hosts):
    try:
        if not isinstance(url, str):
            raise EventError("invalid_callback_url")
        parsed = urlsplit(url)
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower()
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username
            or parsed.password
            or parsed.fragment
            or parsed.port not in {None, 443}
            or len(url) > 2048
            or any(ord(c) <= 32 or ord(c) == 127 for c in url)
        ):
            raise EventError("invalid_callback_url")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise EventError("literal_callback_address_forbidden")
        if host not in allowed_hosts:
            # Hostname is safe to report; the full URL may contain a routing secret.
            raise EventError("callback_host_not_allowed:" + host, -32015)
        return host
    except (ValueError, UnicodeError):
        raise EventError("invalid_callback_url") from None


class PublicNetwork(AutoBackend):
    """Validate every DNS answer and pin TCP to an IP; TLS retains original hostname."""

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if port != 443:
            raise EventError("callback_port_forbidden", -32015)
        answers = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = {item[4][0] for item in answers}
        if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            raise EventError("callback_address_not_public", -32015)
        return await super().connect_tcp(
            sorted(addresses)[0], port, timeout, local_address, socket_options
        )


class WebhookSender:
    def __init__(self, allowed_hosts):
        self.allowed_hosts = frozenset(allowed_hosts)

    async def post(self, url, body, headers):
        callback_host(url, self.allowed_hosts)
        transport = httpx.AsyncHTTPTransport(retries=0)
        # httpx/httpcore are pinned in the adapter. Pinning only the TCP address
        # leaves httpcore's original TLS server_hostname and certificate checks intact.
        transport._pool._network_backend = PublicNetwork()
        async with (
            asyncio.timeout(10),
            httpx.AsyncClient(
                transport=transport, trust_env=False, follow_redirects=False, timeout=10
            ) as client,
        ):
            async with client.stream("POST", url, content=body, headers=headers) as response:
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > 16384:
                        raise EventError("callback_response_too_large", -32015)
                return response.status_code, bytes(data)


async def wait_backend_ready(call, *, sleep=asyncio.sleep):
    """Bounded startup retries for read-only health; never replay a task call."""
    async with asyncio.timeout(25):
        for attempt in range(6):
            try:
                result = await call("bridge_health", {})
            except (
                httpx.ConnectError,
                httpx.ReadError,
                httpx.RemoteProtocolError,
                httpx.ReadTimeout,
            ):
                if attempt == 5:
                    raise EventError("backend_startup_unavailable") from None
                await sleep(min(0.5 * 2**attempt, 4))
                continue
            data = result.get("structuredContent") or {}
            if result.get("isError") or data.get("error") or not data.get("dispatcher_active"):
                raise EventError("backend_readiness_failed")
            return


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS subscriptions(
 id TEXT PRIMARY KEY,principal TEXT NOT NULL,task_id TEXT NOT NULL,target TEXT NOT NULL,
 url TEXT NOT NULL,secret TEXT NOT NULL,old_secret TEXT,old_until REAL NOT NULL DEFAULT 0,
 expires REAL NOT NULL,verified REAL NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS deliveries(
 event_id TEXT PRIMARY KEY,subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
 notice_id TEXT NOT NULL,body TEXT NOT NULL,receipt_hash TEXT NOT NULL,
 state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_at REAL NOT NULL,
 http_status INTEGER,reason TEXT,assistant_receipt REAL,
 auth_failures INTEGER NOT NULL DEFAULT 0,
 UNIQUE(subscription_id,notice_id));
CREATE TABLE IF NOT EXISTS observations(
 seq INTEGER PRIMARY KEY AUTOINCREMENT,at REAL NOT NULL,kind TEXT NOT NULL,
 subscription_id TEXT,event_id TEXT,reason TEXT);
"""


@contextmanager
def initialization_lock(directory):
    """Serialize first WAL/schema setup across sender and independent frontends."""
    fd = os.open(directory / "initialize.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise EventError("event_journal_initialization_busy") from None
                time.sleep(0.01)
        yield
    finally:
        os.close(fd)


class EventJournal:
    def __init__(self, directory):
        directory = Path(directory)
        if directory.is_symlink():
            raise EventError("unsafe_event_state")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
            raise EventError("private_event_state_required")
        path = directory / "events.sqlite3"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
            raise EventError("private_event_database_required")
        with initialization_lock(directory):
            self.db = sqlite3.connect(path, isolation_level=None, timeout=5)
            self.db.row_factory = sqlite3.Row
            if self.db.execute("PRAGMA journal_mode").fetchone()[0] != "wal":
                self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.executescript(SCHEMA)
            columns = {row[1] for row in self.db.execute("PRAGMA table_info(deliveries)")}
            if "auth_failures" not in columns:
                self.db.execute(
                    "ALTER TABLE deliveries ADD COLUMN auth_failures INTEGER NOT NULL DEFAULT 0"
                )
            with self.transaction():
                self.db.execute(
                    "INSERT OR IGNORE INTO settings VALUES('identity_key',?)",
                    (secrets.token_hex(32),),
                )
            self.key = bytes.fromhex(
                self.db.execute("SELECT value FROM settings WHERE key='identity_key'").fetchone()[0]
            )

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def observe(self, kind, sub=None, event=None, reason=None):
        self.db.execute(
            "INSERT INTO observations(at,kind,subscription_id,event_id,reason) VALUES(?,?,?,?,?)",
            (time.time(), kind, sub, event, reason),
        )

    def subscription(self, principal, sub_id):
        row = self.db.execute(
            "SELECT * FROM subscriptions WHERE id=? AND principal=?", (sub_id, principal)
        ).fetchone()
        if row is None:
            raise EventError("subscription_not_found")
        return dict(row)


class EventPush:
    def __init__(self, journal, source_db, principal, sender, authorize_task):
        self.journal, self.db = journal, journal.db
        self.source_db = Path(source_db)
        self.principal, self.sender, self.authorize_task = principal, sender, authorize_task
        self.lock = asyncio.Lock()

    def status(self):
        return {
            "event": EVENT_NAME,
            "subscription_states": dict(
                self.db.execute(
                    "SELECT state,count(*) FROM subscriptions WHERE principal=? GROUP BY state",
                    (self.principal,),
                ).fetchall()
            ),
            "delivery_states": dict(
                self.db.execute(
                    "SELECT d.state,count(*) FROM deliveries d JOIN subscriptions s "
                    "ON s.id=d.subscription_id WHERE s.principal=? GROUP BY d.state",
                    (self.principal,),
                ).fetchall()
            ),
            "chat_ui_receipt_independently_verified": False,
            "scope": "task_request/task_submit, including agent.run; task-source notices only",
        }

    def event_list(self):
        return {
            "events": [
                {
                    "name": EVENT_NAME,
                    "description": "Optional push for one owned task’s final state. "
                    "Subscribe in the "
                    "requesting chat BEFORE submitting it through task_request/task_submit here.",
                    "delivery": ["webhook"],
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"}
                        },
                        "required": ["task_id"],
                        "additionalProperties": False,
                    },
                    "payloadSchema": {
                        "type": "object",
                        "properties": {
                            "task_id": {"type": "string"},
                            "subscription_id": {"type": "string"},
                            "completion_id": {"type": "string"},
                            "receipt_token": {"type": "string"},
                        },
                        "required": [
                            "task_id",
                            "subscription_id",
                            "completion_id",
                            "receipt_token",
                        ],
                        "additionalProperties": True,
                    },
                }
            ]
        }

    def identity(self, name, arguments, delivery):
        if name != EVENT_NAME or not isinstance(arguments, dict) or set(arguments) != {"task_id"}:
            raise EventError("invalid_event_arguments")
        task_id = arguments["task_id"]
        if not isinstance(task_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", task_id):
            raise EventError("invalid_task_filter")
        if not isinstance(delivery, dict) or delivery.get("mode") != "webhook":
            raise EventError("webhook_delivery_required")
        url = delivery.get("url", "")
        callback_host(url, self.sender.allowed_hosts)
        identity = canonical([self.principal, name, arguments, url])
        sub_id = "sub_" + hmac.digest(self.journal.key, identity.encode(), "sha256").hex()
        return sub_id, task_id, url

    async def subscribe(self, name, arguments, delivery, *, cursor=None, ttl_ms=86400000):
        sub_id, task_id, url = self.identity(name, arguments, delivery)
        if cursor is not None:
            raise EventError("cursor_replay_not_supported")
        if ttl_ms is not None and (type(ttl_ms) is not int or not 60000 <= ttl_ms <= 86400000):
            raise EventError("ttl_out_of_bounds")
        secret = delivery.get("secret")
        signing_key(secret)
        async with self.lock:
            count = self.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0]
            existing = self.db.execute(
                "SELECT * FROM subscriptions WHERE id=?", (sub_id,)
            ).fetchone()
            if count >= 128 and existing is None:
                raise EventError("subscription_capacity_reached")
            now = time.time()
            cached = (
                existing
                and existing["state"] == "active"
                and (existing["secret"] == secret and existing["verified"] > now - 300)
            )
            if not cached:
                challenge = secrets.token_urlsafe(32)
                body = canonical({"type": "verification", "challenge": challenge}).encode()
                verification_id = "verify_" + secrets.token_hex(16)
                headers = signed_headers({"id": sub_id, "secret": secret}, verification_id, body)
                try:
                    status, reply = await self.sender.post(url, body, headers)
                    echoed = json.loads(reply).get("challenge")
                    ok = (
                        200 <= status < 300
                        and isinstance(echoed, str)
                        and hmac.compare_digest(echoed, challenge)
                    )
                except (httpx.HTTPError, TimeoutError):
                    raise EventError("callback_timeout", -32015) from None
                except (ValueError, AttributeError):
                    ok = False
                if not ok:
                    raise EventError("challenge_failed", -32015)
            expires = now + (ttl_ms or 86400000) / 1000
            old = (
                existing["secret"]
                if existing and existing["secret"] != secret
                else (existing["old_secret"] if existing else None)
            )
            old_until = (
                now + 60
                if existing and existing["secret"] != secret
                else (existing["old_until"] if existing else 0)
            )
            with self.journal.transaction():
                self.db.execute(
                    "INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET secret=excluded.secret,"
                    "old_secret=excluded.old_secret,"
                    "old_until=excluded.old_until,expires=excluded.expires,verified=excluded.verified,"
                    "state='active'",
                    (
                        sub_id,
                        self.principal,
                        task_id,
                        "push:" + sub_id,
                        url,
                        secret,
                        old,
                        old_until,
                        expires,
                        now,
                        "active",
                    ),
                )
                self.journal.observe("subscription_verified", sub_id)
            return {
                "id": sub_id,
                "refreshBefore": datetime.fromtimestamp(expires, timezone.utc).isoformat(),
                "cursor": None,
                "truncated": False,
            }

    def unsubscribe(self, name, arguments, delivery):
        sub_id, _, _ = self.identity(name, arguments, delivery)
        with self.journal.transaction():
            self.db.execute(
                "UPDATE subscriptions SET state='stopped' WHERE id=? AND principal=?",
                (sub_id, self.principal),
            )
            self.journal.observe("subscription_stopped", sub_id)
        return {}

    def binding(self, task_id, sub_id=None):
        if not isinstance(sub_id, str) or not sub_id:
            raise EventError("explicit_verified_chat_subscription_required")
        sub = self.journal.subscription(self.principal, sub_id)
        if sub["task_id"] != task_id or sub["state"] != "active" or sub["expires"] <= time.time():
            raise EventError("exact_verified_chat_subscription_required")
        return sub["target"]

    def route_submission(self, arguments):
        """Preserve ordinary task calls; verify only an explicitly requested push route.

        No tool schema is extended. New clients use the existing completion_target.
        The old, unadvertised field is accepted for already-bound historical clients.
        """
        routed = dict(arguments)
        legacy = routed.pop("completion_subscription", None)
        target = routed.get("completion_target")
        subscription = legacy if legacy not in (None, "") else None
        if isinstance(target, str) and target.startswith("push:"):
            if subscription is not None and target != "push:" + str(subscription):
                raise EventError("completion_target_does_not_match_verified_subscription")
            subscription = target[5:]
        if subscription is not None:
            request = routed.get("request")
            task_id = request.get("task_id") if isinstance(request, dict) else None
            verified = self.binding(task_id, subscription)
            if target is not None and target != verified:
                raise EventError("completion_target_does_not_match_verified_subscription")
            routed["completion_target"] = verified
        return routed

    def recover(self):
        # Process-level exclusive lock is required by the sidecar before this.
        self.db.execute(
            "UPDATE deliveries SET state=CASE WHEN attempts<3 THEN 'pending' "
            "ELSE 'unknown' END,reason='sender_restart' WHERE state='sending'"
        )

    def collect(self):
        with sqlite3.connect(f"file:{self.source_db}?mode=ro", uri=True) as source:
            source.row_factory = sqlite3.Row
            subscriptions = self.db.execute(
                "SELECT * FROM subscriptions WHERE principal=? AND state='active' AND expires>?",
                (self.principal, time.time()),
            ).fetchall()
            for sub in subscriptions:
                notices = source.execute(
                    "SELECT * FROM completion_notices WHERE principal=? "
                    "AND source='task' AND source_id=? AND target=? ORDER BY seq",
                    (self.principal, sub["task_id"], sub["target"]),
                ).fetchall()
                for notice in notices:
                    if self.db.execute(
                        "SELECT 1 FROM deliveries WHERE subscription_id=? AND notice_id=?",
                        (sub["id"], notice["id"]),
                    ).fetchone():
                        continue
                    token = secrets.token_urlsafe(32)
                    event_id = (
                        "evt_"
                        + hashlib.sha256((sub["id"] + ":" + notice["id"]).encode()).hexdigest()
                    )
                    data = json.loads(notice["payload"])
                    data.update(
                        subscription_id=sub["id"], completion_id=notice["id"], receipt_token=token
                    )
                    event = {
                        "eventId": event_id,
                        "name": EVENT_NAME,
                        "timestamp": datetime.fromtimestamp(
                            notice["created"], timezone.utc
                        ).isoformat(),
                        "data": data,
                        "cursor": None,
                    }
                    body = canonical(event)
                    if len(body.encode()) > 262144:
                        raise EventError("event_payload_too_large")
                    with self.journal.transaction():
                        self.db.execute(
                            "INSERT INTO deliveries(event_id,subscription_id,notice_id,"
                            "body,receipt_hash,state,next_at) VALUES(?,?,?,?,?,'pending',?)",
                            (
                                event_id,
                                sub["id"],
                                notice["id"],
                                body,
                                hashlib.sha256(token.encode()).hexdigest(),
                                time.time(),
                            ),
                        )
                        self.journal.observe("event_queued", sub["id"], event_id)

    async def deliver_once(self):
        self.db.execute(
            "UPDATE subscriptions SET old_secret=NULL,old_until=0 "
            "WHERE old_secret IS NOT NULL AND old_until<=?",
            (time.time(),),
        )
        self.collect()
        row = self.db.execute(
            "SELECT d.* FROM deliveries d JOIN subscriptions s ON "
            "s.id=d.subscription_id WHERE d.state='pending' AND d.attempts<3 AND d.next_at<=? "
            "AND s.state='active' AND s.expires>? ORDER BY d.rowid LIMIT 1",
            (time.time(), time.time()),
        ).fetchone()
        if row is None:
            return False
        sub = self.journal.subscription(self.principal, row["subscription_id"])
        try:
            authorized = await self.authorize_task(sub["task_id"])
        except (EventError, httpx.HTTPError, TimeoutError):
            failures = row["auth_failures"] + 1
            state = "pending" if failures < 3 else "authorization_unknown"
            self.db.execute(
                "UPDATE deliveries SET auth_failures=?,state=?,next_at=?,reason=? WHERE event_id=?",
                (
                    failures,
                    state,
                    time.time() + 2**failures,
                    "backend_authorization_unconfirmed",
                    row["event_id"],
                ),
            )
            self.journal.observe(state, sub["id"], row["event_id"], "authorization_unconfirmed")
            return True
        if not authorized:
            self.db.execute("UPDATE subscriptions SET state='revoked' WHERE id=?", (sub["id"],))
            self.journal.observe("access_revoked", sub["id"], row["event_id"])
            return True
        sub = self.journal.subscription(self.principal, row["subscription_id"])
        if sub["state"] != "active" or sub["expires"] <= time.time():
            return False
        self.db.execute(
            "UPDATE deliveries SET state='sending',attempts=attempts+1 WHERE event_id=?",
            (row["event_id"],),
        )
        reason, status = None, None
        try:
            headers = signed_headers(sub, row["event_id"], row["body"].encode())
            status, _ = await self.sender.post(sub["url"], row["body"].encode(), headers)
            state = "webhook_accepted" if 200 <= status < 300 else "rejected"
            retry = status == 429 or status >= 500
        except (httpx.HTTPError, TimeoutError):
            state, retry, reason = "unknown", True, "transport_outcome_unknown"
        except EventError as exc:
            state, retry, reason = "rejected", False, exc.reason.split(":", 1)[0]
        attempts = row["attempts"] + 1
        if retry and attempts < 3:
            state = "pending"
        with self.journal.transaction():
            self.db.execute(
                "UPDATE deliveries SET state=?,http_status=?,reason=?,next_at=? WHERE event_id=?",
                (state, status, reason, time.time() + 2**attempts, row["event_id"]),
            )
            if status == 410:
                self.db.execute("UPDATE subscriptions SET state='gone' WHERE id=?", (sub["id"],))
            self.journal.observe(state, sub["id"], row["event_id"], reason)
        return True

    def receipt(self, sub_id, event_id, task_id, token):
        sub = self.journal.subscription(self.principal, sub_id)
        row = self.db.execute(
            "SELECT * FROM deliveries WHERE event_id=? AND subscription_id=?", (event_id, sub_id)
        ).fetchone()
        if (
            not row
            or row["attempts"] < 1
            or sub["task_id"] != task_id
            or not isinstance(token, str)
            or not hmac.compare_digest(
                row["receipt_hash"], hashlib.sha256(token.encode()).hexdigest()
            )
        ):
            raise EventError("receipt_not_bound_to_event")
        with self.journal.transaction():
            self.db.execute(
                "UPDATE deliveries SET assistant_receipt=COALESCE(assistant_receipt,?) "
                "WHERE event_id=?",
                (time.time(), event_id),
            )
            self.journal.observe("authenticated_payload_receipt", sub_id, event_id)
        return {
            "event_id": event_id,
            "receipt_scope": "authenticated_payload_possession",
            "chat_ui_receipt_independently_verified": False,
        }
