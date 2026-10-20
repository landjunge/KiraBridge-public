"""Versioned team inputs. Acting identities always come from authentication."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from kirabridge.bridge_core.models import Input

Role = Literal["coordinator", "worker", "reviewer", "observer"]


class TeamCreate(Input):
    team_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(min_length=1, max_length=256)
    members: dict[str, Role] = Field(min_length=1, max_length=16)
    coordinator: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_-]*$")
    idempotency_key: str = Field(min_length=1, max_length=128)


class TeamRoleSet(Input):
    team_id: str = Field(min_length=1, max_length=128)
    member: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_-]*$")
    role: Role
    active: bool = True
    expected_revision: int = Field(ge=1)
    idempotency_key: str = Field(min_length=1, max_length=128)


class TeamMessageSend(Input):
    team_id: str = Field(min_length=1, max_length=128)
    recipient: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_-]*$")
    body: str = Field(min_length=1, max_length=65536)
    kind: Literal["question", "answer", "work", "result", "note"] = "note"
    reply_to: str | None = Field(default=None, min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=128)


class TeamWorkCreate(Input):
    team_id: str = Field(min_length=1, max_length=128)
    assignee: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_-]*$")
    title: str = Field(min_length=1, max_length=256)
    body: str = Field(min_length=1, max_length=65536)
    parent_id: str | None = Field(default=None, min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=128)


class TeamWorkClaim(Input):
    team_id: str = Field(min_length=1, max_length=128)
    work_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=128)


class TeamWorkComplete(Input):
    team_id: str = Field(min_length=1, max_length=128)
    work_id: str = Field(min_length=1, max_length=128)
    result: str = Field(max_length=65536)
    success: bool = True
    idempotency_key: str = Field(min_length=1, max_length=128)


class TeamWorkReprocess(Input):
    team_id: str = Field(min_length=1, max_length=128)
    work_id: str = Field(min_length=1, max_length=128)
    core_task_id: str = Field(min_length=1, max_length=128)
    expected_result_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    idempotency_key: str = Field(min_length=1, max_length=128)
