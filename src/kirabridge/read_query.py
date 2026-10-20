"""Synchronous, bounded reads; never dispatch work or attach interactive sessions."""

import hashlib
import os
import stat
from typing import Literal

from pydantic import Field, model_validator

from kirabridge.bridge_core.models import BridgeError, Input
from kirabridge.filesystem_manager import PathScope
from kirabridge.permissions import state_exclusions


class ReadQuery(Input):
    operation: Literal[
        "file.read", "file.list", "terminal.output", "session.catalog", "session.read"
    ]
    path: str | None = Field(default=None, max_length=4096)
    task_id: str | None = Field(default=None, max_length=128)
    max_bytes: int = Field(default=32768, ge=1, le=65536)
    offset: int = Field(default=0, ge=0, le=2**63 - 1)
    tail: bool = False
    pane_id: str | None = Field(default=None, pattern=r"^(%[0-9]+|terminal:[0-9]+:ttys[0-9]+)$")
    expected_pid: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def selector(self):
        if self.operation.startswith("session."):
            if self.path or self.task_id or self.offset or self.tail:
                raise ValueError(
                    "session queries require exact catalog handles, not paths or tasks"
                )
            if self.operation == "session.read":
                if not self.pane_id or self.expected_pid is None:
                    raise ValueError("session.read requires pane_id and expected_pid")
            elif self.pane_id is not None or self.expected_pid is not None:
                raise ValueError("session.catalog does not accept a target")
        elif self.pane_id is not None or self.expected_pid is not None:
            raise ValueError("terminal handles are only valid for session.read")
        elif self.operation == "terminal.output":
            if not self.task_id or self.path is not None or self.offset or self.tail:
                raise ValueError("terminal.output requires only task_id and max_bytes")
        elif not self.path or self.task_id is not None:
            raise ValueError("file reads require path, not task_id")
        if self.operation == "file.list" and (self.offset or self.tail):
            raise ValueError("directory reads do not accept byte selectors")
        if self.tail and self.offset:
            raise ValueError("use either tail or offset")
        return self


async def read_query_async(bridge, principal: str, query: ReadQuery) -> dict:
    """Existing dictionary-shaped tool also works with cached client tool lists."""
    if query.operation == "session.catalog":
        return {
            "operation": query.operation,
            **await bridge.terminal_queries.execute(principal, query.operation, {}),
        }
    if query.operation == "session.read":
        result = await bridge.terminal_queries.execute(
            principal,
            query.operation,
            {
                "pane_id": query.pane_id,
                "expected_pid": query.expected_pid,
                "max_bytes": query.max_bytes,
            },
        )
        return {"operation": query.operation, **result}
    return read_query(bridge, principal, query)


def read_query(bridge, principal: str, query: ReadQuery) -> dict:
    capability = "process.inspect" if query.operation == "terminal.output" else query.operation
    policy = bridge.security.principal(principal, capability)
    if query.operation == "terminal.output":
        task = bridge.task(principal, query.task_id)
        if task["operation"] not in {"terminal.execute", "agent.execute"}:
            raise BridgeError("invalid_operation", "Task has no terminal output")
        try:
            source = bridge.terminal.inspect(principal, query.task_id)
            origin = "managed_terminal_buffer"
        except BridgeError as exc:
            if exc.code != "not_found":
                raise
            source = task.get("result") or {}
            origin = "persisted_task_result"
        remaining, output, truncated = query.max_bytes, {}, False
        for key in ("stdout", "stderr"):
            raw = str(source.get(key, "")).encode("utf-8")
            output[key] = raw[:remaining].decode("utf-8", "replace")
            truncated |= len(raw) > remaining
            remaining -= min(remaining, len(raw))
        return {
            "operation": query.operation,
            "task_id": query.task_id,
            "state": task["state"],
            "source": origin,
            **output,
            "bytes": query.max_bytes - remaining,
            "truncated": truncated,
            "output_available": source.get(
                "output_available", "stdout" in source or "stderr" in source
            ),
            "output_status": source.get("output_status", "available"),
            "exit_code": source.get("exit_code"),
            "scope": "owned Bridge task only; no external terminal attachment",
        }
    scope = PathScope(
        policy.roots + policy.read_roots, excluded=state_exclusions(bridge.config, policy)
    )
    if query.operation == "file.list":
        result = bridge.filesystem.list(scope, query.path)
        entries = result["entries"][:100]
        return {
            "operation": query.operation,
            "path": query.path,
            "entries": entries,
            "truncated": result["truncated"] or len(result["entries"]) > 100,
        }
    try:
        with scope.parent(query.path) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode):
                    raise BridgeError("file_type", "Only regular files can be read")
                offset = max(0, metadata.st_size - query.max_bytes) if query.tail else query.offset
                data = os.pread(fd, query.max_bytes + 1, offset)
            finally:
                os.close(fd)
    except OSError:
        raise BridgeError("read_unavailable", "File unavailable or unsafe to open") from None
    bounded = data[: query.max_bytes]
    return {
        "operation": query.operation,
        "path": query.path,
        "text": bounded.decode("utf-8", "replace"),
        "offset": offset,
        "next_offset": offset + len(bounded),
        "bytes": len(bounded),
        "truncated": len(data) > query.max_bytes,
        "size_observed": metadata.st_size,
        "modified_ns": metadata.st_mtime_ns,
        "content_sha256": hashlib.sha256(bounded).hexdigest(),
        "scope": "file snapshot; does not prove current agent activity or project completion",
    }
