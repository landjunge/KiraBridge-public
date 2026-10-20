"""Operation properties shared by authorization, catalog and dispatch.

Input models remain assembled by the composition root. This module imports no
manager, platform adapter or configuration and cannot start work.
"""

from dataclasses import asdict, dataclass
from typing import Literal

READ_OPERATIONS = frozenset(
    {
        "connection.check",
        "session.catalog",
        "session.read",
        "file.read",
        "file.list",
        "file.image",
        "clipboard.info",
        "process.list",
        "process.inspect",
        "agent.status",
        "policy.inspect",
        "handoff.status",
        "handoff.inbox",
        "threaddesk.read",
        "observations.read",
    }
)
STOP_OPERATIONS = frozenset({"process.terminate", "workflow.stop"})
RESERVED_READ_OPERATIONS = frozenset(
    {
        "session.catalog",
        "session.read",
        "process.list",
        "process.inspect",
        "agent.status",
        "policy.inspect",
        "handoff.status",
    }
)
LEGACY_CONTROL_OPERATIONS = (
    RESERVED_READ_OPERATIONS - {"session.catalog", "session.read"}
) | STOP_OPERATIONS


@dataclass(frozen=True)
class Operation:
    capability: str
    effect: Literal["read", "write", "execute", "control"]
    execution_class: Literal["normal", "read", "stop"]

    def describe(self):
        return asdict(self)


OPERATIONS = {}
for _name in (
    *READ_OPERATIONS,
    *STOP_OPERATIONS,
    "session.open",
    "session.input",
    "terminal.execute",
    "file.write",
    "file.mkdir",
    "file.move",
    "file.delete",
    "clipboard.read",
    "clipboard.write",
    "agent.execute",
    "handoff.issue",
    "handoff.start",
    "handoff.answer",
    "handoff.reconcile",
    "handoff.decide",
    "threaddesk.manage",
    "threaddesk.knowledge",
    "admin.execute",
):
    OPERATIONS[_name] = Operation(
        capability="session.inspect" if _name in {"session.catalog", "session.read"} else _name,
        effect="read"
        if _name in READ_OPERATIONS or _name == "clipboard.read"
        else "control"
        if _name in STOP_OPERATIONS
        else "execute"
        if _name in {"terminal.execute", "admin.execute", "agent.execute"}
        else "write",
        execution_class="stop"
        if _name in STOP_OPERATIONS
        else "read"
        if _name in RESERVED_READ_OPERATIONS
        else "normal",
    )


def capability_for(operation):
    descriptor = OPERATIONS.get(operation)
    return descriptor.capability if descriptor else operation


def lane_operations(lane):
    if lane == "control":  # Compatibility for existing local Store callers.
        return LEGACY_CONTROL_OPERATIONS
    return frozenset(name for name, spec in OPERATIONS.items() if spec.execution_class == lane)
