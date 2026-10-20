"""The shared, bounded read path for direct and legacy queued terminal tools."""

import asyncio

from pydantic import ValidationError

from kirabridge.bridge_core.models import BridgeError, EmptyInput
from kirabridge.session_manager import SessionRead

TERMINAL_QUERY_SECONDS = 8.0


class TerminalQueries:
    def __init__(self, security, sessions, store, slots):
        self.security, self.sessions, self.store = security, sessions, store
        self.slots = slots
        self.active = 0

    async def execute(self, principal, operation, arguments, *, task_id=None):
        if operation not in {"session.catalog", "session.read"}:
            raise BridgeError("unknown_operation", "Not a terminal read operation")
        try:
            args = (EmptyInput if operation == "session.catalog" else SessionRead).model_validate(
                arguments
            )
        except ValidationError:
            raise BridgeError(
                "invalid_arguments", "Arguments do not match the operation schema"
            ) from None
        decision = self.security.authorize(principal, operation)
        if task_id is None:
            if decision["approval_required"]:
                raise BridgeError(
                    "approval_required",
                    "Terminalabfrage benötigt Erlaubnis; über task_request einreichen",
                )
        else:
            task = self.store.get(task_id, principal)
            if (
                task["operation"] != operation
                or task["args"] != arguments
                or task["state"] not in {"accepted", "running"}
            ):
                raise BridgeError("query_context_conflict", "No matching dispatched terminal read")
        # A saturated read lane returns a bounded, explicit failure; it never
        # queues unbounded HTTP coroutines or takes capacity from stop commands.
        if self.active >= self.slots:
            raise BridgeError(
                "terminal_read_busy", "Terminal-Leseplätze belegt; später erneut lesen"
            )
        self.active += 1
        try:
            async with asyncio.timeout(TERMINAL_QUERY_SECONDS):
                if operation == "session.catalog":
                    return await self.sessions.catalog(principal)
                return await self.sessions.read_observed(
                    principal,
                    args.pane_id,
                    args.expected_pid,
                    max_bytes=args.max_bytes,
                )
        except TimeoutError:
            raise BridgeError(
                "terminal_read_timeout", "Terminalabfrage hat das Zeitbudget überschritten"
            ) from None
        finally:
            self.active -= 1
