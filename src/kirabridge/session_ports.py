"""Partners used by session coordination, without access to the complete core."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


class SessionAuthority(Protocol):
    def principal(self, principal, capability): ...
    def validate_window(self, principal, task_id, arguments): ...
    def check_window(self, principal, task_id, arguments): ...
    def window_outcome(self, principal, task_id, outcome): ...


class InputRelease(Protocol):
    def dispatch(self, principal, arguments, task_id): ...
    def sent(self, principal, task_id): ...


class SessionAudit(Protocol):
    def observe_terminal(self, principal, result): ...


class SessionTransport(Protocol):
    async def catalog(self): ...
    async def read(self, pane_id): ...
    async def insert(self, pane_id, text): ...
    async def press_return(self, pane_id): ...
    async def send(self, pane_id, text, *, submit, require_idle): ...


class TerminalAppPort(SessionTransport, Protocol):
    available: bool
    desktop: object

    async def open(self, command): ...


@dataclass(frozen=True)
class SessionPorts:
    authorization: SessionAuthority
    input_release: InputRelease
    audit: SessionAudit
    environment: dict[str, str]
    agent_registry: Callable
    clipboard_lock: object
    readiness: Callable | None = None
