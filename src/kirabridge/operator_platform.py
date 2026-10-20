"""OS process observation/execution and the authenticated local MCP transport."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from kirabridge.bridge_core.models import BridgeError
from kirabridge.local_runtime import peer
from kirabridge.mcp_gateway.client import MCPClientPool


class LocalDaemonClient:
    def __init__(self, config):
        self.config = config

    async def call(self, tool, arguments=None, principal="local", timeout=8):
        if tool in {"session_catalog", "session_read"}:
            from kirabridge.terminal_queries import TERMINAL_QUERY_SECONDS

            timeout = max(timeout, TERMINAL_QUERY_SECONDS + 2)
        async with MCPClientPool(call_timeout=timeout) as pool:
            await pool.connect(peer(self.config(), principal))
            result = await pool.call("daemon", tool, arguments or {})
            value = result.structuredContent
            if (
                result.isError
                or not isinstance(value, dict)
                or (value.get("error") and "id" not in value)
            ):
                error = value.get("error", {}) if isinstance(value, dict) else {}
                raise BridgeError(
                    error.get("code", "daemon_response"),
                    error.get("message", "Die Bridge hat nicht geantwortet"),
                )
            return value


class LocalProcessPlatform:
    async def command(self, *argv, timeout=8):
        child = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async with asyncio.timeout(timeout):
                out, err = await child.communicate()
            return child.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
        finally:
            if child.returncode is None:
                child.kill()
                await child.wait()

    async def processes(self):
        code, text, _ = await self.command("/bin/ps", "-axo", "uid=,pid=,ppid=,ucomm=,args=")
        if code:
            raise BridgeError("process_observation", "Prozesszustände konnten nicht gelesen werden")
        rows = []
        for line in text.splitlines():
            parts = line.strip().split(None, 4)
            if len(parts) == 5 and parts[0] == str(os.getuid()):
                rows.append(
                    {
                        "pid": int(parts[1]),
                        "ppid": int(parts[2]),
                        "comm": Path(parts[3]).name,
                        "args": parts[4],
                    }
                )
        return rows
