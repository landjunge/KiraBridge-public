"""Read the macOS console state without opening windows or sending UI events."""

import asyncio
import os
import plistlib
import sys
import time

from kirabridge.bridge_core.models import BridgeError

DESKTOP_MESSAGES = {
    "desktop_locked": "Der Mac ist gesperrt. Bitte die bestehende Benutzersitzung entsperren. "
    "Terminalprozesse bleiben erhalten; es wird kein Ersatzfenster gestartet.",
    "desktop_session_inactive": "Die zugehörige Mac-Benutzersitzung ist nicht am Bildschirm aktiv. "
    "Vorhandene Terminalprozesse bleiben erhalten.",
}


def console_state(raw, uid):
    roots = plistlib.loads(raw)
    roots = roots if isinstance(roots, list) else [roots]
    users = []
    for root in roots:
        rows = root.get("IOConsoleUsers") if isinstance(root, dict) else None
        if isinstance(rows, list):
            users.extend(row for row in rows if isinstance(row, dict))
    own = [u for u in users if u.get("kCGSSessionUserIDKey") == uid]
    if any(u.get("CGSSessionScreenIsLocked") is True for u in own):
        return "desktop_locked"
    if any(u.get("kCGSSessionOnConsoleKey") is True for u in own):
        return "available"
    if own and any(u.get("kCGSSessionOnConsoleKey") is True for u in users):
        return "desktop_session_inactive"
    return "unknown"


class MacDesktop:
    def __init__(self):
        self.last = {"state": "not_probed", "observed_at": None}

    async def probe(self):
        if sys.platform != "darwin":
            self.last = {"state": "not_applicable", "observed_at": time.time()}
            return self.last
        child = None
        state = "unknown"
        try:
            child = await asyncio.create_subprocess_exec(
                "/usr/sbin/ioreg",
                "-n",
                "Root",
                "-d1",
                "-a",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            async with asyncio.timeout(2):
                raw, _ = await child.communicate()
            if child.returncode == 0 and len(raw) <= 1048576:
                state = console_state(raw, os.getuid())
        except (OSError, TimeoutError, ValueError, plistlib.InvalidFileException):
            pass  # An unavailable extra probe never removes an existing grant.
        finally:
            if child is not None and child.returncode is None:
                try:
                    child.kill()
                except ProcessLookupError:
                    pass
                await child.wait()
        self.last = {
            "state": state,
            "observed_at": time.time(),
            "scope": "macOS console availability, not permission or agent readiness",
        }
        return self.last

    async def require_interactive(self):
        state = await self.probe()
        if state["state"] in DESKTOP_MESSAGES:
            raise BridgeError(state["state"], DESKTOP_MESSAGES[state["state"]])
