"""Read an explicitly bound Codex rollout; never discover or control a process.

This observes append-only local event records, not terminal acceptance or agent
identity. The caller must independently verify the persisted window/thread binding.
"""

import asyncio
import hashlib
import json
import os
import stat
import threading
from dataclasses import dataclass
from pathlib import Path


@dataclass
class _Cursor:
    identity: tuple
    header_hash: str
    offset: int
    size: int
    modified: int
    state: str = "unknown"
    reason: str = "no_turn_event"
    last_event: str | None = None
    turn_id: str | None = None
    invalid: str | None = None


class CodexTurnState:
    def __init__(self, sessions_root=None, *, max_bytes=8 * 1024 * 1024, max_line_bytes=1048576):
        self.root = Path(sessions_root or Path.home() / ".codex" / "sessions").resolve()
        if max_line_bytes < 128 or max_bytes < max_line_bytes:
            raise ValueError("The scan budget must accommodate one bounded event line")
        self.max_bytes, self.max_line_bytes = max_bytes, max_line_bytes
        self._cursors = {}
        self._lock = asyncio.Lock()
        self._thread_lock = threading.Lock()

    @staticmethod
    def _result(cursor=None, *, reason=None):
        return {
            "state": "unknown" if reason else cursor.state,
            "reason": reason or cursor.reason,
            "last_event": cursor.last_event if cursor else None,
            "turn_id": cursor.turn_id if cursor else None,
        }

    async def read(self, path: str | None, thread_id: str | None) -> dict:
        async with self._lock:
            return await asyncio.to_thread(self._read, path, thread_id)

    def _read(self, path, thread_id):
        # Cancellation releases an asyncio waiter before to_thread has finished.
        # Keep cursor mutation serialized even across cancelled reads.
        with self._thread_lock:
            return self._read_locked(path, thread_id)

    def _read_locked(self, path, thread_id):
        if not path or not thread_id:
            return self._result(reason="thread_binding_missing")
        cursor = None
        try:
            selected = Path(path).resolve(strict=True)
            if not selected.is_relative_to(self.root) or selected == self.root:
                return self._result(reason="session_path_outside_root")
            key = (str(selected), thread_id)
            cursor = self._cursors.get(key)
            with os.fdopen(
                os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb"
            ) as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    return self._result(reason="session_not_regular")
                identity = (before.st_dev, before.st_ino)
                if cursor:
                    if cursor.invalid:
                        return self._result(cursor, reason=cursor.invalid)
                    if identity != cursor.identity:
                        cursor.invalid = "session_replaced"
                    elif before.st_size < cursor.size:
                        cursor.invalid = "session_truncated"
                    elif before.st_size == cursor.size and before.st_mtime_ns != cursor.modified:
                        cursor.invalid = "session_rewritten"
                    if cursor.invalid:
                        return self._result(cursor, reason=cursor.invalid)
                header = stream.readline(self.max_line_bytes + 1)
                if len(header) > self.max_line_bytes:
                    return self._result(cursor, reason="session_line_limit")
                if not header.endswith(b"\n"):
                    return self._result(cursor, reason="session_partial_header")
                metadata = json.loads(header)
                payload = metadata.get("payload", {})
                if (
                    metadata.get("type") != "session_meta"
                    or not isinstance(payload, dict)
                    or payload.get("id") != thread_id
                ):
                    return self._result(cursor, reason="session_header_mismatch")
                # Codex TUI sessions currently report source="vscode" too.
                # Source is not a PID mapping; never infer one from this field.
                if payload.get("originator", "codex-tui") != "codex-tui":
                    return self._result(cursor, reason="session_originator_mismatch")
                header_hash = hashlib.sha256(header).hexdigest()
                if cursor and header_hash != cursor.header_hash:
                    cursor.invalid = "session_header_changed"
                    return self._result(cursor, reason=cursor.invalid)
                if cursor is None:
                    cursor = _Cursor(
                        identity, header_hash, stream.tell(), before.st_size, before.st_mtime_ns
                    )
                    self._cursors[key] = cursor
                stream.seek(cursor.offset)
                remaining = self.max_bytes - len(header)
                incomplete = None
                while stream.tell() < before.st_size:
                    start = stream.tell()
                    if remaining <= 0:
                        incomplete = "session_scan_incomplete"
                        break
                    line = stream.readline(min(self.max_line_bytes, remaining) + 1)
                    if len(line) > self.max_line_bytes:
                        cursor.invalid = "session_line_limit"
                        break
                    if len(line) > remaining:
                        incomplete = "session_scan_incomplete"
                        break
                    if not line.endswith(b"\n"):
                        incomplete = "session_partial_line"
                        break
                    remaining -= len(line)
                    try:
                        record = json.loads(line)
                        self._event(cursor, record)
                    except (ValueError, TypeError, AttributeError):
                        cursor.invalid = "session_parse_error"
                        break
                    cursor.offset = start + len(line)
                after = os.fstat(stream.fileno())
                current = selected.stat()
                if (current.st_dev, current.st_ino) != identity:
                    cursor.invalid = "session_replaced"
                elif min(after.st_size, current.st_size) < before.st_size:
                    cursor.invalid = "session_truncated"
                elif (
                    after.st_size == before.st_size and after.st_mtime_ns != before.st_mtime_ns
                ) or (
                    current.st_size == after.st_size and current.st_mtime_ns != after.st_mtime_ns
                ):
                    cursor.invalid = "session_rewritten"
                elif (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns) or (
                    current.st_size,
                    current.st_mtime_ns,
                ) != (after.st_size, after.st_mtime_ns):
                    incomplete = "session_changed_during_read"
                cursor.size, cursor.modified = after.st_size, after.st_mtime_ns
                if cursor.invalid:
                    return self._result(cursor, reason=cursor.invalid)
                if incomplete or cursor.offset != after.st_size:
                    return self._result(cursor, reason=incomplete or "session_scan_incomplete")
                return self._result(cursor)
        except (OSError, ValueError, TypeError, AttributeError):
            return self._result(cursor, reason="session_unavailable_or_invalid")

    @staticmethod
    def _event(cursor, record):
        if not isinstance(record, dict):
            raise ValueError("Invalid record")
        if record.get("type") != "event_msg":
            return  # A quoted event in user text or tool output has no authority.
        payload = record.get("payload")
        if not isinstance(payload, dict) or not isinstance(payload.get("type"), str):
            raise ValueError("Invalid event")
        kind = payload["type"]
        if kind not in {"task_started", "task_complete", "turn_aborted"}:
            if kind.startswith(("task_", "turn_")):
                cursor.state, cursor.reason = "unknown", "unsupported_turn_event"
                cursor.last_event, cursor.turn_id = kind, None
            return
        turn = payload.get("turn_id")
        cursor.last_event = kind
        if not isinstance(turn, str) or not turn:
            cursor.state, cursor.reason, cursor.turn_id = "unknown", "turn_id_missing", None
        elif kind == "task_started":
            cursor.state, cursor.reason, cursor.turn_id = "working", "turn_started", turn
        elif cursor.state != "working" or cursor.turn_id != turn:
            cursor.state, cursor.reason, cursor.turn_id = (
                "unknown",
                "turn_completion_unmatched",
                None,
            )
        else:
            cursor.state = "idle"
            cursor.reason = "turn_completed" if kind == "task_complete" else "turn_interrupted"
