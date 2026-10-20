"""Existing tmux pane transport. Never creates a server, pane or agent as fallback."""

from __future__ import annotations

import asyncio
import re
import shutil

from kirabridge.bridge_core.models import BridgeError, UncertainExecution


class TmuxTransport:
    def __init__(self, environment, *, socket_name=None):
        self.environment, self.socket_name = environment, socket_name
        self.last_catalog_truncated = False

    async def command(self, *args, mutation=False):
        executable = shutil.which("tmux", path=self.environment["PATH"])
        if not executable:
            raise BridgeError(
                "session_transport_unavailable", "tmux is not installed in configured PATH"
            )
        argv = [executable] + (["-L", self.socket_name] if self.socket_name else []) + list(args)
        child = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=self.environment.copy(),
        )
        try:
            async with asyncio.timeout(3):
                data = bytearray()
                while len(data) <= 65536:
                    chunk = await child.stdout.read(min(8192, 65537 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                raw = bytes(data)
                if len(raw) > 65536:
                    raise BridgeError("output_limit", "tmux response exceeds 65536 bytes")
                await child.wait()
                if child.returncode:
                    raise BridgeError(
                        "session_transport_unavailable", "No accessible tmux server or pane"
                    )
                return raw.decode("utf-8", "replace")
        except (TimeoutError, BridgeError):
            if mutation:
                raise UncertainExecution(
                    "session_input_unknown", "Input outcome unknown; do not resend automatically"
                ) from None
            raise
        finally:
            if child.returncode is None:
                child.kill()
                await child.wait()

    async def catalog(self):
        raw = await self.command(
            "list-panes",
            "-a",
            "-F",
            "#{pane_id}\t#{pane_pid}\t#{pane_tty}\t#{pane_current_command}",
        )
        rows = []
        for line in raw.splitlines()[:100]:
            parts = line.split("\t")
            if len(parts) == 4 and re.fullmatch(r"%[0-9]+", parts[0]) and parts[1].isdigit():
                rows.append(
                    dict(
                        pane_id=parts[0],
                        expected_pid=int(parts[1]),
                        tty=parts[2],
                        command=parts[3],
                        agent_identity_verified=False,
                    )
                )
        self.last_catalog_truncated = len(raw.splitlines()) > 100
        return rows

    async def read(self, pane_id):
        return await self.command("capture-pane", "-p", "-t", pane_id, "-S", "-200")

    async def insert(self, pane_id, text):
        await self.command("send-keys", "-t", pane_id, "-l", "--", text, mutation=True)

    async def press_return(self, pane_id):
        await self.command("send-keys", "-t", pane_id, "Enter", mutation=True)

    async def send(self, pane_id, text, *, submit, require_idle):
        argv = ["send-keys", "-t", pane_id, "-l", "--", text]
        if submit:
            argv += [";", "send-keys", "-t", pane_id, "Enter"]
        await self.command(*argv, mutation=True)
