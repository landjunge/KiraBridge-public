"""Authorize exact existing sessions and invoke their selected transport once."""

from __future__ import annotations

import asyncio
import shlex
from pathlib import Path

from pydantic import Field

from kirabridge.bridge_core.models import BridgeError, Input
from kirabridge.filesystem_manager import PathScope
from kirabridge.platform_adapters.desktop import DESKTOP_MESSAGES
from kirabridge.platform_adapters.terminal_app import TerminalAppTransport
from kirabridge.platform_adapters.tmux import TmuxTransport
from kirabridge.session_ports import SessionPorts, SessionTransport, TerminalAppPort
from kirabridge.terminal_manager import check_executable


class SessionReference(Input):
    pane_id: str = Field(pattern=r"^(%[0-9]+|terminal:[0-9]+:ttys[0-9]+)$")
    expected_pid: int = Field(gt=0)


class SessionRead(SessionReference):
    max_bytes: int = Field(default=65536, ge=1, le=65536)


class SessionInput(SessionReference):
    text: str = Field(min_length=1, max_length=16384)
    submit: bool = True
    require_idle: bool = False


class SessionOpen(Input):
    cwd: str = Field(min_length=1, max_length=4096)
    argv: list[str] = Field(default_factory=list, max_length=256)
    window_authorization: str = Field(default="", max_length=128)


class SessionManager:
    def __init__(
        self,
        ports: SessionPorts,
        *,
        socket_name=None,
        terminal_app: TerminalAppPort | None = None,
        tmux: SessionTransport | None = None,
    ):
        self.ports, self.socket_name = ports, socket_name
        self.authorization, self.input_release, self.audit = (
            ports.authorization,
            ports.input_release,
            ports.audit,
        )
        self.environment, self.agent_registry = ports.environment, ports.agent_registry
        self.readiness = ports.readiness
        self.lock = asyncio.Lock()
        self.terminal_app = (
            terminal_app if terminal_app is not None else TerminalAppTransport(ports.clipboard_lock)
        )
        self.tmux = (
            tmux if tmux is not None else TmuxTransport(ports.environment, socket_name=socket_name)
        )
        self.desktop = self.terminal_app.desktop

    def transport(self, pane_id):
        return self.terminal_app if pane_id.startswith("terminal:") else self.tmux

    async def catalog(self, principal):
        self.authorization.principal(principal, "session.inspect")
        native_rows, errors = [], {}
        if self.terminal_app.available and self.socket_name is None:
            try:
                native_rows = await self.terminal_app.catalog()
            except BridgeError as exc:
                errors["terminal_app"] = {"code": exc.code, "message": str(exc)}
        try:
            rows = await self.tmux.catalog()
        except BridgeError as exc:
            return {
                "transport": "terminal_app" if native_rows else "tmux",
                "status": "available"
                if native_rows
                else errors.get("terminal_app", {}).get("code", exc.code),
                "sessions": native_rows,
                "transport_errors": {**errors, "tmux": {"code": exc.code}},
                "scope": "Exact Terminal.app tabs and tmux panes; existing sessions preserved",
            }
        return {
            "transport": "terminal_app_and_tmux" if native_rows else "tmux",
            "status": "available",
            "sessions": native_rows + rows,
            "transport_errors": errors,
            "truncated": getattr(self.tmux, "last_catalog_truncated", False),
        }

    async def read(self, principal, pane_id, expected_pid, *, max_bytes=65536):
        await self.selected(principal, pane_id, expected_pid)
        text = await self.transport(pane_id).read(pane_id)
        text = text.encode("utf-8")[-max_bytes:].decode("utf-8", "ignore")
        return {
            "pane_id": pane_id,
            "expected_pid": expected_pid,
            "text": text,
            "scope": "selected terminal output; not proof of project completion",
        }

    async def insert(self, principal, args):
        self.authorization.principal(principal, "session.input")
        self.authorization.principal(principal, "terminal.execute")
        if args.submit or "\x00" in args.text:
            raise BridgeError("invalid_arguments", "Insertion must not submit a line")
        async with self.lock:
            selected = await self.selected(principal, args.pane_id, args.expected_pid)
            self.assigned_agent(selected)
            if args.require_idle and selected.get("busy", True):
                raise BridgeError("session_busy", "Selected terminal is not an idle shell")
            await self.transport(args.pane_id).insert(args.pane_id, args.text)
        return {"paste_event_sent": True, "return_sent": False, "agent_confirmed": False}

    async def press_return(self, principal, pane_id, expected_pid):
        self.authorization.principal(principal, "session.input")
        self.authorization.principal(principal, "terminal.execute")
        async with self.lock:
            self.assigned_agent(await self.selected(principal, pane_id, expected_pid))
            await self.transport(pane_id).press_return(pane_id)
        return {"return_sent": True, "agent_confirmed": False}

    async def send(self, principal, args, *, task_id=None):
        self.authorization.principal(principal, "session.input")
        self.authorization.principal(principal, "terminal.execute")
        if "\x00" in args.text:
            raise BridgeError("invalid_arguments", "NUL in input")
        async with self.lock:
            selected = await self.selected(principal, args.pane_id, args.expected_pid)
            if self.assigned_agent(selected):
                raise BridgeError(
                    "visible_handoff_required", "CLI handoffs require the central route"
                )
            if args.require_idle and selected.get("busy", True):
                raise BridgeError("session_busy", "Selected terminal is not an idle shell")
            if args.pane_id.startswith("terminal:") and not args.submit:
                raise BridgeError("session_submit_required", "Terminal.app input submits a line")
            args = self.input_release.dispatch(principal, args, task_id)
            await self.transport(args.pane_id).send(
                args.pane_id, args.text, submit=args.submit, require_idle=args.require_idle
            )
            self.input_release.sent(principal, task_id)
        return {
            "pane_id": args.pane_id,
            "expected_pid": args.expected_pid,
            "input_handed_to_transport": True,
            "agent_processed": False,
            "submitted": args.submit,
        }

    async def selected(self, principal, pane_id, expected_pid):
        catalog = await self.catalog(principal)
        native_error = catalog.get("transport_errors", {}).get("terminal_app", {})
        if pane_id.startswith("terminal:") and native_error.get("code") in DESKTOP_MESSAGES:
            raise BridgeError(native_error["code"], native_error["message"])
        matches = [
            row
            for row in catalog["sessions"]
            if row["pane_id"] == pane_id and row["expected_pid"] == expected_pid
        ]
        if len(matches) == 1:
            return matches[0]
        raise BridgeError(
            "session_selection_changed",
            "Select an exact current pane_id and expected_pid from session_catalog",
        )

    def assigned_agent(self, selected):
        """Recognized CLI input always needs the persistent original binding."""
        selected = selected or {}
        agents, bindings = self.agent_registry()
        matches = [p for p in selected.get("processes", []) if p["name"] in agents]
        if not matches:
            return None
        if len(matches) != 1:
            raise BridgeError("visible_target_ambiguous", "Multiple CLI agents in this terminal")
        process = matches[0]
        binding = bindings.get(process["name"])
        if not binding or (binding.pane_id, binding.expected_pid, binding.agent_pid) != (
            selected.get("pane_id"),
            selected.get("expected_pid"),
            process["pid"],
        ):
            raise BridgeError(
                "visible_target_changed", "CLI input requires its assigned original window"
            )
        return process["name"]

    async def read_observed(self, principal, pane_id, expected_pid, *, max_bytes=65536):
        result = await self.read(principal, pane_id, expected_pid, max_bytes=max_bytes)
        if self.readiness:
            observation = await self.readiness(principal, result)
            if observation is not None:
                result = {**result, "input_readiness": observation}
        return self.audit.observe_terminal(principal, result)

    async def open(self, principal, args, *, task_id=None):
        policy = self.authorization.principal(principal, "session.open")
        self.authorization.principal(principal, "terminal.execute")
        self.authorization.validate_window(principal, task_id, args)
        PathScope(policy.terminal_roots or policy.roots).split(args.cwd)
        cwd = str(Path(args.cwd).resolve(strict=True))
        PathScope(policy.terminal_roots or policy.roots).split(cwd)
        argv = list(args.argv)
        if argv:
            argv[0] = check_executable(
                argv[0],
                policy.executables,
                policy.allow_any_executable,
                self.environment["PATH"],
            )
        if any("\x00" in arg for arg in argv):
            raise BridgeError("invalid_arguments", "NUL in command")
        command = "cd -- " + shlex.quote(cwd)
        if argv:
            command += " && " + shlex.join(argv)
        async with self.lock:
            self.authorization.check_window(principal, task_id, args)
            try:
                result = await self.terminal_app.open(command)
            except BaseException:
                self.authorization.window_outcome(principal, task_id, "unknown")
                raise
            self.authorization.window_outcome(principal, task_id, "opened")
            for _ in range(20):
                sessions = await self.terminal_app.catalog()
                selected = next((s for s in sessions if s["tty"] == result["tty"]), None)
                if selected:
                    return {**selected, "opened": True, "agent_processed": False}
                await asyncio.sleep(0.05)
        return {**result, "session_handle_pending": True, "agent_processed": False}
