"""Owner-only, durable OAuth state. Bearer and refresh credentials are stored as hashes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from kirabridge.bridge_core.config import private_directory
from kirabridge.bridge_core.models import BridgeError, canonical, digest

ACCESS_SECONDS = 3600
REFRESH_SECONDS = 7 * 86400
PENDING_SECONDS = 600
# Mobile browsers pause the consent-page poll while the user switches apps.
# Keep the approved code within the original ten-minute authorization window.
CODE_SECONDS = 600
UNAUTHORIZED_CLIENT_SECONDS = 3600
MAX_REGISTRATIONS_PER_MINUTE = 16
MAX_GENERATIONS = 256
SCOPE = ["kirabridge"]
ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_clients (
 id TEXT PRIMARY KEY, issuer TEXT NOT NULL, principal TEXT NOT NULL, metadata TEXT NOT NULL,
 created REAL NOT NULL, revoked REAL, authorized INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS oauth_requests (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES oauth_clients(id),
 issuer TEXT NOT NULL, resource TEXT NOT NULL, principal TEXT NOT NULL,
 redirect_uri TEXT NOT NULL, state TEXT, challenge TEXT NOT NULL,
 explicit_redirect INTEGER NOT NULL,
 status TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, code TEXT
);
CREATE TABLE IF NOT EXISTS oauth_families (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES oauth_clients(id), issuer TEXT NOT NULL,
 resource TEXT NOT NULL, principal TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
 revoked REAL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
 hash TEXT PRIMARY KEY, request_id TEXT NOT NULL REFERENCES oauth_requests(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL, issuer TEXT NOT NULL, resource TEXT NOT NULL, principal TEXT NOT NULL,
 redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, explicit_redirect INTEGER NOT NULL,
 expires REAL NOT NULL, used REAL, family_id TEXT
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
 hash TEXT PRIMARY KEY, kind TEXT NOT NULL, family_id TEXT NOT NULL REFERENCES oauth_families(id)
 ON DELETE CASCADE, client_id TEXT NOT NULL, issuer TEXT NOT NULL, resource TEXT NOT NULL,
 principal TEXT NOT NULL, expires REAL NOT NULL, used REAL, generation INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_token_family ON oauth_tokens(family_id);
CREATE TABLE IF NOT EXISTS oauth_audit (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, kind TEXT NOT NULL,
 metadata TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_audit_kind_at ON oauth_audit(kind,at);
"""


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class _Transaction:
    """A class context manager preserves the SDK's frozen OAuth exception objects."""

    def __init__(self, store):
        self.store = store

    def __enter__(self):
        self.store.lock.acquire()
        try:
            self.store.db.execute("BEGIN IMMEDIATE")
        except BaseException:
            self.store.lock.release()
            raise
        return self.store.db

    def __exit__(self, kind, value, traceback):
        try:
            self.store.db.execute("ROLLBACK" if kind else "COMMIT")
        finally:
            self.store.lock.release()
        return False


class OAuthStore:
    def __init__(self, path: Path, *, issuer: str, principal="grok_app", redirect_hosts=None):
        parsed = urlsplit(issuer)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
            or "?" in issuer
            or "#" in issuer
            or any(char.isspace() or ord(char) < 32 for char in issuer)
        ):
            raise BridgeError("oauth_issuer", "A canonical HTTPS issuer origin is required")
        try:
            issuer_port = parsed.port
        except ValueError:
            raise BridgeError("oauth_issuer", "Invalid HTTPS issuer origin") from None
        if issuer_port is not None and not 1 <= issuer_port <= 65535:
            raise BridgeError("oauth_issuer", "Invalid HTTPS issuer port")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,40}", principal):
            raise BridgeError("oauth_principal", "An explicit connector principal is required")
        self.issuer, self.principal, self.resource = issuer, principal, issuer + "/mcp"
        self.redirect_hosts = tuple(
            redirect_hosts
            if redirect_hosts is not None
            else ["grok.com", "accounts.x.ai", "console.x.ai"]
        )
        if not self.redirect_hosts or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host)
            for host in self.redirect_hosts
        ):
            raise BridgeError("oauth_redirect_hosts", "Exact HTTPS callback hosts are required")
        path = Path(path)
        private_directory(path.parent)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (
                os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077)
            ):
                raise BridgeError("unsafe_state", "OAuth state must be an owner-only regular file")
        finally:
            os.close(fd)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, isolation_level=None, timeout=5, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            with self.transaction():
                if self.db.execute("PRAGMA user_version").fetchone()[0] not in {0, 1}:
                    raise BridgeError("schema_version", "Unsupported OAuth state schema")
                for statement in SCHEMA.split(";"):
                    if statement.strip():
                        self.db.execute(statement)
                client_columns = {
                    row["name"] for row in self.db.execute("PRAGMA table_info(oauth_clients)")
                }
                if "authorized" not in client_columns:
                    self.db.execute(
                        "ALTER TABLE oauth_clients ADD COLUMN authorized INTEGER NOT NULL DEFAULT 0"
                    )
                    self.db.execute(
                        "UPDATE oauth_clients SET authorized=1 WHERE id IN "
                        "(SELECT client_id FROM oauth_families) OR id IN "
                        "(SELECT client_id FROM oauth_requests "
                        "WHERE status IN ('approved','consumed'))"
                    )
                    self._restore_audited_approvals()
                self.db.execute("PRAGMA user_version=1")
        except BaseException:
            self.db.close()
            raise

    def transaction(self):
        return _Transaction(self)

    def _restore_audited_approvals(self):
        """Keep previously approved clients whose short-lived grants were already cleaned up."""
        clients = {
            token_hash(row["id"]): row["id"]
            for row in self.db.execute("SELECT id FROM oauth_clients")
        }
        pending = {}
        for row in self.db.execute(
            "SELECT at,kind,metadata FROM oauth_audit WHERE kind IN "
            "('oauth.consent_requested','oauth.consent_approved','oauth.consent_denied') "
            "ORDER BY seq"
        ):
            pending = {
                key: value
                for key, value in pending.items()
                if value[1] >= row["at"] - PENDING_SECONDS
            }
            metadata = json.loads(row["metadata"])
            request_id = metadata.get("request_id")
            if row["kind"] == "oauth.consent_requested":
                client_id = clients.get(metadata.get("client_id_sha256"))
                if client_id and isinstance(request_id, str):
                    pending[request_id] = (client_id, row["at"])
            elif request_id in pending:
                client_id, _ = pending.pop(request_id)
                if row["kind"] == "oauth.consent_approved":
                    self.db.execute(
                        "UPDATE oauth_clients SET authorized=1 WHERE id=?", (client_id,)
                    )

    def _audit(self, kind, **metadata):
        previous = self.db.execute(
            "SELECT hash FROM oauth_audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        record = {
            "at": time.time(),
            "kind": kind,
            "metadata": metadata,
            "previous": previous[0] if previous else "0" * 64,
        }
        self.db.execute(
            "INSERT INTO oauth_audit(at,kind,metadata,previous,hash) VALUES(?,?,?,?,?)",
            (record["at"], kind, canonical(metadata), record["previous"], digest(record)),
        )

    def _cleanup(self):
        now = time.time()
        self.db.execute("DELETE FROM oauth_requests WHERE expires<=?", (now,))
        self.db.execute("DELETE FROM oauth_codes WHERE expires<=?", (now,))
        self.db.execute("DELETE FROM oauth_families WHERE expires<=?", (now,))
        # Audit history is immutable. Expired grant material is expendable.
        self.db.execute(
            "DELETE FROM oauth_clients WHERE "
            "(revoked IS NOT NULL OR (authorized=0 AND created<=?)) "
            "AND id NOT IN (SELECT client_id FROM oauth_requests) "
            "AND id NOT IN (SELECT client_id FROM oauth_families)",
            (now - UNAUTHORIZED_CLIENT_SECONDS,),
        )

    def _redirect(self, value):
        uri = str(value)
        parsed = urlsplit(uri)
        try:
            port = parsed.port
        except ValueError:
            raise RegistrationError("invalid_redirect_uri", "Invalid callback URI") from None
        if (
            len(uri.encode("utf-8")) > 2048
            or parsed.scheme != "https"
            or parsed.hostname not in self.redirect_hosts
            or port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or "#" in uri
            or any(char.isspace() or ord(char) < 32 for char in uri)
            or any(
                key in {"code", "state", "iss", "error", "error_description"}
                for key, _ in parse_qsl(parsed.query)
            )
        ):
            raise RegistrationError(
                "invalid_redirect_uri", "Callback must use an operator-approved exact HTTPS host"
            )
        return uri

    def register_client(self, client):
        if not client.client_id or not ID.fullmatch(client.client_id):
            raise RegistrationError("invalid_client_metadata", "Invalid client ID")
        if client.token_endpoint_auth_method not in {
            "none",
            "client_secret_post",
            "client_secret_basic",
        }:
            raise RegistrationError(
                "invalid_client_metadata", "Unsupported client authentication method"
            )
        if (
            "authorization_code" not in client.grant_types
            or not set(client.grant_types) <= {"authorization_code", "refresh_token"}
            or client.response_types != ["code"]
            or client.scope not in {None, "kirabridge"}
            or not client.redirect_uris
            or len(client.redirect_uris) > 8
            or client.client_name is not None
            and len(client.client_name.encode("utf-8")) > 128
        ):
            raise RegistrationError(
                "invalid_client_metadata", "Unsupported client metadata or scope"
            )
        for redirect in client.redirect_uris:
            self._redirect(redirect)
        if client.token_endpoint_auth_method == "none":
            if client.client_secret:
                raise RegistrationError(
                    "invalid_client_metadata", "Public clients must not use a secret"
                )
        elif not client.client_secret or not 32 <= len(client.client_secret) <= 256:
            raise RegistrationError(
                "invalid_client_metadata", "A generated client secret is required"
            )
        client = client.model_copy(update={"scope": "kirabridge", "issuer": self.issuer})
        metadata = client.model_dump_json()
        if len(metadata.encode("utf-8")) > 16384:
            raise RegistrationError(
                "invalid_client_metadata", "Client metadata exceeds its byte limit"
            )
        with self.transaction():
            self._cleanup()
            recent = self.db.execute(
                "SELECT count(*) FROM oauth_audit WHERE kind='oauth.client_registered' AND at>?",
                (time.time() - 60,),
            ).fetchone()[0]
            if recent >= MAX_REGISTRATIONS_PER_MINUTE:
                raise RegistrationError(
                    "invalid_client_metadata", "Registration rate limit reached; try again later"
                )
            if self.db.execute("SELECT count(*) FROM oauth_clients").fetchone()[0] >= 32:
                raise RegistrationError(
                    "invalid_client_metadata", "Client registration capacity reached"
                )
            if self.db.execute(
                "SELECT 1 FROM oauth_clients WHERE id=?", (client.client_id,)
            ).fetchone():
                raise RegistrationError(
                    "invalid_client_metadata", "Client ID is already registered"
                )
            self.db.execute(
                "INSERT INTO oauth_clients(id,issuer,principal,metadata,created,revoked) "
                "VALUES(?,?,?,?,?,NULL)",
                (client.client_id, self.issuer, self.principal, metadata, time.time()),
            )
            self._audit("oauth.client_registered", client_id_sha256=token_hash(client.client_id))

    def get_client(self, client_id):
        if not isinstance(client_id, str) or len(client_id) > 128:
            return None
        with self.lock:
            row = self.db.execute(
                "SELECT metadata FROM oauth_clients WHERE id=? AND issuer=? AND principal=? "
                "AND revoked IS NULL",
                (client_id, self.issuer, self.principal),
            ).fetchone()
            return OAuthClientInformationFull.model_validate_json(row[0]) if row else None

    def request_authorization(self, client, params: AuthorizationParams):
        current = self.get_client(client.client_id)
        if not current:
            raise AuthorizeError("unauthorized_client", "Client is not registered with this issuer")
        if params.resource != self.resource:
            raise AuthorizeError("invalid_request", "Exact MCP resource is required")
        if params.scopes is not None and params.scopes != SCOPE:
            raise AuthorizeError("invalid_scope", "Only the kirabridge scope is supported")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.code_challenge):
            raise AuthorizeError("invalid_request", "A valid S256 PKCE challenge is required")
        if params.state is not None and len(params.state.encode("utf-8")) > 2048:
            raise AuthorizeError("invalid_request", "State exceeds its byte limit")
        try:
            redirect = self._redirect(params.redirect_uri)
        except RegistrationError:
            raise AuthorizeError("invalid_request", "Invalid callback URI") from None
        if redirect not in {str(uri) for uri in current.redirect_uris or []}:
            raise AuthorizeError("invalid_request", "Callback URI is not registered")
        with self.transaction():
            self._cleanup()
            if not self.get_client(client.client_id):
                raise AuthorizeError("unauthorized_client", "Client authorization was revoked")
            if self.db.execute("SELECT count(*) FROM oauth_requests").fetchone()[0] >= 16:
                raise AuthorizeError("temporarily_unavailable", "Authorization queue is full")
            request_id = secrets.token_urlsafe(32)
            self.db.execute(
                "INSERT INTO oauth_requests VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
                (
                    request_id,
                    current.client_id,
                    self.issuer,
                    self.resource,
                    self.principal,
                    redirect,
                    params.state,
                    params.code_challenge,
                    int(params.redirect_uri_provided_explicitly),
                    "pending",
                    time.time(),
                    time.time() + PENDING_SECONDS,
                ),
            )
            self._audit(
                "oauth.consent_requested",
                request_id=request_id,
                client_id_sha256=token_hash(current.client_id),
            )
        return request_id

    def list_pending(self):
        with self.transaction():
            self._cleanup()
            rows = self.db.execute(
                "SELECT r.*,c.metadata FROM oauth_requests r "
                "JOIN oauth_clients c ON c.id=r.client_id "
                "WHERE r.issuer=? AND r.principal=? AND r.status='pending' AND c.revoked IS NULL "
                "ORDER BY r.created",
                (self.issuer, self.principal),
            ).fetchall()
            return [
                {
                    "id": row["id"],
                    "client_name": json.loads(row["metadata"]).get("client_name"),
                    "redirect_uri": row["redirect_uri"],
                    "scopes": SCOPE.copy(),
                    "created": row["created"],
                    "expires_at": row["expires"],
                    "principal": self.principal,
                }
                for row in rows
            ]

    def decide(self, request_id, allow):
        if type(allow) is not bool:
            raise BridgeError("invalid_arguments", "Decision must be an explicit boolean")
        with self.transaction():
            self._cleanup()
            row = self.db.execute(
                "SELECT * FROM oauth_requests WHERE id=? AND issuer=? AND principal=?",
                (request_id, self.issuer, self.principal),
            ).fetchone()
            if row is None:
                raise BridgeError("not_found", "Authorization request not found or expired")
            target = "approved" if allow else "denied"
            if row["status"] != "pending":
                if row["status"] == target:
                    return {"id": request_id, "status": target, "expires_at": row["expires"]}
                raise BridgeError(
                    "state_conflict", "Authorization request has already been decided"
                )
            expires = min(row["expires"], time.time() + CODE_SECONDS) if allow else row["expires"]
            code = secrets.token_urlsafe(48) if allow else None
            self.db.execute(
                "UPDATE oauth_requests SET status=?,expires=?,code=? WHERE id=?",
                (target, expires, code, request_id),
            )
            if code:
                self.db.execute(
                    "UPDATE oauth_clients SET authorized=1 WHERE id=?", (row["client_id"],)
                )
                self.db.execute(
                    "INSERT INTO oauth_codes VALUES(?,?,?,?,?,?,?,?,?,?,NULL,NULL)",
                    (
                        token_hash(code),
                        request_id,
                        row["client_id"],
                        self.issuer,
                        self.resource,
                        self.principal,
                        row["redirect_uri"],
                        row["challenge"],
                        row["explicit_redirect"],
                        expires,
                    ),
                )
            self._audit("oauth.consent_" + target, request_id=request_id)
            return {"id": request_id, "status": target, "expires_at": expires}

    def poll(self, request_id):
        with self.transaction():
            self._cleanup()
            row = self.db.execute(
                "SELECT * FROM oauth_requests WHERE id=? AND issuer=? AND principal=?",
                (request_id, self.issuer, self.principal),
            ).fetchone()
            if row is None or row["status"] == "consumed":
                return {"status": "expired"}
            result = {"status": row["status"]}
            if row["status"] == "approved":
                result["redirect_url"] = construct_redirect_uri(
                    row["redirect_uri"], code=row["code"], state=row["state"], iss=self.issuer
                )
            return result

    def _revoke_family(self, family_id, reason):
        changed = self.db.execute(
            "UPDATE oauth_families SET revoked=? WHERE id=? AND revoked IS NULL",
            (time.time(), family_id),
        ).rowcount
        if changed:
            self._audit("oauth.family_revoked", family_id=family_id, reason=reason)

    def load_code(self, client, code):
        if not isinstance(code, str) or not 32 <= len(code) <= 256:
            return None
        with self.transaction():
            row = self.db.execute(
                "SELECT * FROM oauth_codes WHERE hash=? AND client_id=? AND issuer=? "
                "AND principal=? "
                "AND resource=?",
                (token_hash(code), client.client_id, self.issuer, self.principal, self.resource),
            ).fetchone()
            if not row or row["expires"] <= time.time() or not self.get_client(client.client_id):
                return None
            if row["used"] is not None:
                if row["family_id"]:
                    self._revoke_family(row["family_id"], "authorization_code_replay")
                return None
            return AuthorizationCode(
                code=code,
                scopes=SCOPE.copy(),
                expires_at=row["expires"],
                client_id=row["client_id"],
                code_challenge=row["challenge"],
                redirect_uri=row["redirect_uri"],
                redirect_uri_provided_explicitly=bool(row["explicit_redirect"]),
                resource=self.resource,
                subject=self.principal,
            )

    def _mint(self, family_id, client_id, generation, family_expires, *, issue_refresh=True):
        now = time.time()
        access = secrets.token_urlsafe(48)
        refresh = secrets.token_urlsafe(48) if issue_refresh else None
        access_expires = min(now + ACCESS_SECONDS, family_expires)
        values = [(access, "access", access_expires)]
        if refresh is not None:
            values.append((refresh, "refresh", family_expires))
        for value, kind, expires in values:
            self.db.execute(
                "INSERT INTO oauth_tokens VALUES(?,?,?,?,?,?,?,?,NULL,?)",
                (
                    token_hash(value),
                    kind,
                    family_id,
                    client_id,
                    self.issuer,
                    self.resource,
                    self.principal,
                    expires,
                    generation,
                ),
            )
        self._audit("oauth.tokens_issued", family_id=family_id, generation=generation)
        return OAuthToken(
            access_token=access,
            refresh_token=refresh,
            expires_in=max(0, int(access_expires - now)),
            scope="kirabridge",
        )

    def exchange_code(self, client, code):
        denied, result = False, None
        with self.transaction():
            self._cleanup()
            current_client = self.get_client(client.client_id)
            row = self.db.execute(
                "SELECT * FROM oauth_codes WHERE hash=? AND client_id=? AND issuer=? "
                "AND resource=? "
                "AND principal=?",
                (
                    token_hash(code.code),
                    client.client_id,
                    self.issuer,
                    self.resource,
                    self.principal,
                ),
            ).fetchone()
            if (
                not row
                or row["expires"] <= time.time()
                or not current_client
                or code.resource != self.resource
                or code.subject != self.principal
            ):
                denied = True
            elif row["used"] is not None:
                if row["family_id"]:
                    self._revoke_family(row["family_id"], "authorization_code_replay")
                denied = True
            elif self.db.execute("SELECT count(*) FROM oauth_families").fetchone()[0] >= 64:
                denied = True
            else:
                now, family_id = time.time(), secrets.token_hex(24)
                issue_refresh = "refresh_token" in current_client.grant_types
                expires = now + (REFRESH_SECONDS if issue_refresh else ACCESS_SECONDS)
                self.db.execute(
                    "INSERT INTO oauth_families VALUES(?,?,?,?,?,?,?,NULL)",
                    (
                        family_id,
                        client.client_id,
                        self.issuer,
                        self.resource,
                        self.principal,
                        now,
                        expires,
                    ),
                )
                self.db.execute(
                    "UPDATE oauth_codes SET used=?,family_id=? WHERE hash=?",
                    (now, family_id, row["hash"]),
                )
                self.db.execute(
                    "UPDATE oauth_requests SET status='consumed',code=NULL,state=NULL WHERE id=?",
                    (row["request_id"],),
                )
                result = self._mint(
                    family_id, client.client_id, 0, expires, issue_refresh=issue_refresh
                )
        if denied:
            raise TokenError("invalid_grant", "Authorization grant is unavailable")
        return result

    def _token_row(self, value, kind, client_id=None):
        if not isinstance(value, str) or not 32 <= len(value) <= 256:
            return None
        row = self.db.execute(
            "SELECT t.*,f.revoked,f.expires AS family_expires FROM oauth_tokens t "
            "JOIN oauth_families f ON f.id=t.family_id JOIN oauth_clients c ON c.id=t.client_id "
            "WHERE t.hash=? AND t.kind=? AND t.issuer=? AND t.resource=? AND t.principal=? "
            "AND c.revoked IS NULL",
            (token_hash(value), kind, self.issuer, self.resource, self.principal),
        ).fetchone()
        if (
            not row
            or client_id is not None
            and row["client_id"] != client_id
            or row["expires"] <= time.time()
            or row["family_expires"] <= time.time()
            or row["revoked"] is not None
        ):
            return None
        return row

    def load_refresh(self, client, value):
        with self.transaction():
            row = self._token_row(value, "refresh", client.client_id)
            if not row:
                return None
            if row["used"] is not None:
                self._revoke_family(row["family_id"], "refresh_token_replay")
                return None
            return RefreshToken(
                token=value,
                client_id=row["client_id"],
                scopes=SCOPE.copy(),
                expires_at=int(row["expires"]),
                resource=self.resource,
                subject=self.principal,
            )

    def exchange_refresh(self, client, refresh, scopes):
        denied, result = False, None
        if scopes != SCOPE:
            raise TokenError("invalid_scope", "Only the granted kirabridge scope is supported")
        with self.transaction():
            current_client = self.get_client(client.client_id)
            row = self._token_row(refresh.token, "refresh", client.client_id)
            if (
                not row
                or not current_client
                or "refresh_token" not in current_client.grant_types
                or refresh.resource != self.resource
                or refresh.subject != self.principal
            ):
                denied = True
            elif row["used"] is not None:
                self._revoke_family(row["family_id"], "refresh_token_replay")
                denied = True
            elif row["generation"] >= MAX_GENERATIONS:
                self._revoke_family(row["family_id"], "refresh_rotation_limit")
                denied = True
            else:
                self.db.execute(
                    "UPDATE oauth_tokens SET used=? WHERE family_id=? "
                    "AND kind='access' AND used IS NULL",
                    (time.time(), row["family_id"]),
                )
                self.db.execute(
                    "UPDATE oauth_tokens SET used=? WHERE hash=?", (time.time(), row["hash"])
                )
                result = self._mint(
                    row["family_id"], client.client_id, row["generation"] + 1, row["family_expires"]
                )
        if denied:
            raise TokenError("invalid_grant", "Refresh grant is unavailable")
        return result

    def load_access(self, value):
        with self.lock:
            row = self._token_row(value, "access")
            if not row or row["used"] is not None:
                return None
            return AccessToken(
                token=value,
                client_id=row["client_id"],
                scopes=SCOPE.copy(),
                expires_at=int(row["expires"]),
                resource=self.resource,
                subject=self.principal,
                claims={"iss": self.issuer},
            )

    def revoke_token(self, token):
        with self.transaction():
            kind = "access" if isinstance(token, AccessToken) else "refresh"
            value = token.token
            row = self._token_row(value, kind, token.client_id)
            if row:
                self._revoke_family(row["family_id"], "token_revocation")

    def revoke_client(self, client_id):
        with self.transaction():
            row = self.db.execute(
                "SELECT id FROM oauth_clients WHERE id=? AND issuer=? AND principal=?",
                (client_id, self.issuer, self.principal),
            ).fetchone()
            if not row:
                return
            self.db.execute(
                "UPDATE oauth_clients SET revoked=? WHERE id=?", (time.time(), client_id)
            )
            for family in self.db.execute(
                "SELECT id FROM oauth_families WHERE client_id=?", (client_id,)
            ):
                self._revoke_family(family["id"], "client_revocation")
            self.db.execute(
                "UPDATE oauth_requests SET status='denied',code=NULL,state=NULL WHERE client_id=?",
                (client_id,),
            )
            self.db.execute("DELETE FROM oauth_codes WHERE client_id=?", (client_id,))
            self._audit("oauth.client_revoked", client_id_sha256=token_hash(client_id))

    def record_use(self, client_id, *, tool, request_ref=None):
        if not self.get_client(client_id):
            raise BridgeError("unauthorized", "OAuth client is unavailable")
        if not isinstance(tool, str) or not re.fullmatch(r"[a-zA-Z0-9_.:/-]{1,80}", tool):
            tool = None
        if request_ref is not None and (not isinstance(request_ref, str) or len(request_ref) > 256):
            request_ref = None
        with self.transaction():
            self._audit(
                "oauth.mcp_use",
                issuer_sha256=token_hash(self.issuer),
                principal=self.principal,
                client_id_sha256=token_hash(client_id),
                tool=tool,
                request_ref_sha256=token_hash(request_ref) if request_ref else None,
            )

    def status(self):
        with self.transaction():
            self._cleanup()
            counts = {}
            for key, table in [
                ("clients", "oauth_clients"),
                ("pending", "oauth_requests"),
                ("families", "oauth_families"),
            ]:
                extra = (
                    " AND revoked IS NULL"
                    if key in {"clients", "families"}
                    else " AND status='pending'"
                )
                counts[key] = self.db.execute(
                    f"SELECT count(*) FROM {table} WHERE issuer=? AND principal=?{extra}",
                    (self.issuer, self.principal),
                ).fetchone()[0]
            row = self.db.execute(
                "SELECT at,metadata FROM oauth_audit WHERE kind='oauth.mcp_use' "
                "ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            last_use = {"at": row["at"], **json.loads(row["metadata"])} if row else None
            if last_use and (
                last_use["issuer_sha256"] != token_hash(self.issuer)
                or last_use["principal"] != self.principal
            ):
                last_use = None
            return {
                "issuer": self.issuer,
                "resource": self.resource,
                "principal": self.principal,
                "counts": counts,
                "last_use": last_use,
            }

    def close(self):
        with self.lock:
            self.db.close()
