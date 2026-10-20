from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time

from kirabridge.bridge_core.config import Config, PrincipalConfig
from kirabridge.bridge_core.models import BridgeError, TaskRequest, digest
from kirabridge.operations import capability_for
from kirabridge.task_manager.store import Store


def request_hash(request: TaskRequest) -> str:
    return digest(request.model_dump())


class SecurityManager:
    def __init__(self, config: Config, store: Store):
        self.config, self.store = config, store
        with store.transaction():
            store.db.execute(
                "CREATE TABLE IF NOT EXISTS window_dispatches ("
                "token_hash TEXT PRIMARY KEY,principal TEXT NOT NULL,task_id TEXT NOT NULL,"
                "state TEXT NOT NULL,created REAL NOT NULL,UNIQUE(principal,task_id))"
            )

    def principal(self, name: str, capability: str | None = None) -> PrincipalConfig:
        principal = self.config.principals.get(name)
        if principal is None or (
            capability and capability_for(capability) not in principal.capabilities
        ):
            raise BridgeError("forbidden", "Capability not granted")
        return principal

    def authorize(self, name, operation, *, text=None):
        from kirabridge.permissions import decision

        result = decision(self.config, name, operation, text=text)
        if not result["authorized"]:
            raise BridgeError(
                "forbidden", "Capability not granted: " + ", ".join(result["missing_capabilities"])
            )
        return result

    def authenticate(self, token: str) -> str:
        if len(token) < 32:
            raise BridgeError("unauthorized", "Authentication required")
        for name, principal in self.config.principals.items():
            expected = os.environ.get(principal.token_env, "") if principal.token_env else ""
            if expected and hmac.compare_digest(token, expected):
                return name
        raise BridgeError("unauthorized", "Authentication required")

    def grant(self, principal: str, request: TaskRequest, ttl: int = 300) -> str:
        with self.store.transaction():
            return self.grant_in_transaction(principal, request, ttl)

    @staticmethod
    def window_hash(principal, task_id, args):
        return digest(
            {
                "purpose": "explicit_new_terminal_window",
                "principal": principal,
                "task_id": task_id,
                "arguments": args.model_dump(exclude={"window_authorization"}),
            }
        )

    def grant_window(self, principal, task_id, args):
        """Trusted local operator only; deliberately no MCP issuer or agent boolean."""
        self.principal(principal, "session.open")
        token = secrets.token_urlsafe(32)
        with self.store.transaction():
            self.store.assert_accepting()
            self.store.db.execute(
                "INSERT INTO approvals(token_hash,principal,task_id,request_hash,expires) "
                "VALUES(?,?,?,?,?)",
                (
                    hashlib.sha256(token.encode()).hexdigest(),
                    principal,
                    task_id,
                    self.window_hash(principal, task_id, args),
                    time.time() + 300,
                ),
            )
            self.store.audit(
                "control.window_authorized",
                principal,
                None,
                {
                    "window_task_id": task_id,
                    "request_hash": self.window_hash(principal, task_id, args),
                },
            )
        return token

    def consume_window(self, principal, task_id, args):
        """Shares enqueue's transaction; one grant cannot create two windows."""
        result = self.store.db.execute(
            "UPDATE approvals SET used=? WHERE token_hash=? AND principal=? AND task_id=? "
            "AND request_hash=? AND expires>? AND used IS NULL",
            (
                time.time(),
                hashlib.sha256(args.window_authorization.encode()).hexdigest(),
                principal,
                task_id,
                self.window_hash(principal, task_id, args),
                time.time(),
            ),
        )
        if result.rowcount != 1:
            raise BridgeError(
                "window_request_required",
                "Ein neues Fenster benötigt einen konkreten Auftrag im lokalen Bedienfenster",
            )

    def validate_window(self, principal, task_id, args):
        token_hash = hashlib.sha256(args.window_authorization.encode()).hexdigest()
        if not self.store.db.execute(
            "SELECT 1 FROM approvals WHERE token_hash=? AND principal=? AND task_id=? "
            "AND request_hash=? AND used IS NOT NULL AND expires>?",
            (
                token_hash,
                principal,
                task_id,
                self.window_hash(principal, task_id, args),
                time.time(),
            ),
        ).fetchone():
            raise BridgeError(
                "window_request_required", "No matching unexpired operator window grant"
            )

    def check_window(self, principal, task_id, args):
        token_hash = hashlib.sha256(args.window_authorization.encode()).hexdigest()
        with self.store.transaction():
            self.validate_window(principal, task_id, args)
            if self.store.db.execute(
                "SELECT 1 FROM window_dispatches WHERE token_hash=? OR (principal=? AND task_id=?)",
                (token_hash, principal, task_id),
            ).fetchone():
                raise BridgeError(
                    "window_already_dispatched", "Window attempt already recorded; do not repeat"
                )
            self.store.db.execute(
                "INSERT INTO window_dispatches VALUES(?,?,?,'dispatching',?)",
                (token_hash, principal, task_id, time.time()),
            )

    def window_outcome(self, principal, task_id, state):
        with self.store.transaction():
            self.store.db.execute(
                "UPDATE window_dispatches SET state=? WHERE principal=? AND task_id=? "
                "AND state='dispatching'",
                (state, principal, task_id),
            )
            self.store.audit(
                "control.window_" + state, principal, None, {"window_task_id": task_id}
            )

    def grant_in_transaction(self, principal: str, request: TaskRequest, ttl: int = 300) -> str:
        """Trusted local operator only; caller owns the enclosing transaction."""
        self.principal(principal, request.operation)
        if request.api_version != "1" or not 1 <= ttl <= 3600:
            raise BridgeError("invalid_grant", "Invalid API version or approval lifetime")
        token = secrets.token_urlsafe(32)
        self.store.db.execute(
            "INSERT INTO approvals(token_hash,principal,task_id,request_hash,expires) "
            "VALUES(?,?,?,?,?)",
            (
                hashlib.sha256(token.encode()).hexdigest(),
                principal,
                request.task_id,
                request_hash(request),
                time.time() + ttl,
            ),
        )
        self.store.audit(
            "approval.granted",
            principal,
            request.task_id,
            {"operation": request.operation, "request_hash": request_hash(request)},
        )
        return token

    def consume(self, principal: str, request: TaskRequest, token: str) -> None:
        # Must share the enqueue transaction: a crash cannot consume a grant without storing a task.
        result = self.store.db.execute(
            "UPDATE approvals SET used=? WHERE token_hash=? AND principal=? AND task_id=? "
            "AND request_hash=? AND expires>? AND used IS NULL",
            (
                time.time(),
                hashlib.sha256(token.encode()).hexdigest(),
                principal,
                request.task_id,
                request_hash(request),
                time.time(),
            ),
        )
        if result.rowcount != 1:
            raise BridgeError(
                "approval_required", "Valid one-use approval for this exact task required"
            )
