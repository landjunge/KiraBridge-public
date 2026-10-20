from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class BridgeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class UncertainExecution(BridgeError):
    """The external effect cannot be proven; never retry automatically."""


class State(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    ACCEPTED = "accepted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"
    CANCELLED = "cancelled"


TRANSITIONS = {
    State.CREATED: {State.QUEUED, State.CANCELLED},
    State.QUEUED: {State.ACCEPTED, State.CANCELLED, State.BLOCKED},
    State.ACCEPTED: {State.RUNNING, State.FAILED, State.UNKNOWN, State.CANCELLED},
    State.RUNNING: {State.COMPLETED, State.FAILED, State.UNKNOWN, State.CANCELLED},
    State.UNKNOWN: {State.COMPLETED, State.FAILED, State.CANCELLED},
    State.BLOCKED: set(),
    State.COMPLETED: set(),
    State.FAILED: set(),
    State.CANCELLED: set(),
}


def canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class TaskRequest(Input):
    api_version: str = "1"
    task_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    operation: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any]
    idempotency_key: str = Field(min_length=1, max_length=128)
    parent_id: str | None = None


class TerminalInput(Input):
    argv: list[str] = Field(min_length=1, max_length=256)
    cwd: str
    timeout: float = Field(default=60.0, gt=0, le=3600)
    max_output: int = Field(default=65536, ge=0, le=1048576)


class ConnectionCheckInput(Input):
    device: Literal["browser", "mobile", "desktop"]
    mode: Literal["text", "live", "voice"]


class PathInput(Input):
    path: str


class ReadInput(PathInput):
    max_bytes: int = Field(default=65536, ge=1, le=1048576)


class ImageInput(Input):
    path: str = Field(min_length=1, max_length=4096)


class WriteInput(PathInput):
    text: str = Field(max_length=1048576)
    overwrite: bool = False


class MoveInput(PathInput):
    destination: str


class ClipboardRead(Input):
    max_bytes: int = Field(default=65536, ge=1, le=1048576)


class ClipboardWrite(Input):
    text: str = Field(max_length=1048576)


class EmptyInput(Input):
    pass


class ProcessInput(Input):
    task_id: str


class AgentInput(Input):
    local_tools: bool = False
    agent: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,40}$")
    prompt: str = Field(min_length=1, max_length=262144)
    cwd: str
    timeout: float = Field(default=300.0, gt=0, le=3600)


class ThreadDeskReadInput(Input):
    tool: Literal[
        "list_threads",
        "get_thread",
        "current_thread",
        "list_snapshots",
        "thread_operation_status",
        "get_reentry",
    ]
    arguments: dict[str, Any] = Field(default_factory=dict)


class ThreadDeskManageInput(Input):
    operation_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    action: Literal[
        "create",
        "update",
        "set_note",
        "add_file",
        "remove_file",
        "organize",
        "archive",
        "unarchive",
        "delete",
        "switch",
    ]
    id: str | None = Field(default=None, min_length=1, max_length=128)
    expected_revision: int = Field(ge=0)
    data: dict[str, Any] = Field(default_factory=dict)


class ThreadDeskKnowledgeInput(Input):
    operation_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    action: Literal["record", "supersede", "resolve_question", "save_reentry"]
    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    expected_revision: int = Field(ge=0, strict=True)
    data: dict[str, Any]


class ObservationReadInput(Input):
    task_ids: list[str] = Field(min_length=1, max_length=16)
    cursor: int = Field(default=0, ge=0, lt=2**63, strict=True)
    limit: int = Field(default=100, ge=1, le=500, strict=True)
    through_seq: int | None = Field(default=None, ge=0, lt=2**63, strict=True)


class HandoffIssueInput(Input):
    operation_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    thread_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    expected_revision: int = Field(ge=0)
    target: Literal["generic", "codex"] = "codex"


class HandoffReference(Input):
    handoff_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    revision: int = Field(ge=1)


class WorkflowStopInput(HandoffReference):
    stop_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")


class HandoffStartInput(HandoffReference):
    agent: str = Field(default="codex", pattern=r"^[a-z][a-z0-9_-]{0,40}$")
    cwd: str
    timeout: float = Field(default=120.0, gt=0, le=300)


class HandoffAnswerInput(HandoffReference):
    question_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    answer_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    text: str = Field(min_length=1, max_length=10000)
    timeout: float = Field(default=120.0, gt=0, le=300)


class HandoffDecisionInput(HandoffReference):
    return_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    choice: Literal["accepted", "rejected", "rework"]
    note: str = Field(min_length=1, max_length=10000)


class HandoffAgentReply(Input):
    kind: Literal["question", "result"]
    text: str = Field(min_length=1, max_length=10000)
    files: list[str] = Field(default_factory=list, max_length=32)
    test_results: list[str] = Field(default_factory=list, max_length=32)
    open_issues: list[str] = Field(default_factory=list, max_length=32)


class HandoffInboxInput(Input):
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=20, ge=1, le=50)
