from __future__ import annotations

import asyncio
import hashlib
import os

from kirabridge.bridge_core.models import BridgeError
from kirabridge.platform_adapters import (
    PlatformAdapter,
    current_platform,
    reap_process,
    subprocess_options,
)
from kirabridge.terminal_manager import minimal_environment


class ClipboardManager:
    def __init__(self, platform: PlatformAdapter | None = None):
        self.platform = platform or current_platform()
        self.lock = asyncio.Lock()

    async def _transfer(self, data: bytes | None, max_bytes: int) -> bytes:
        command = self.platform.clipboard_command(write=data is not None)
        env = minimal_environment()
        for key in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XAUTHORITY"):
            if key in os.environ:
                env[key] = os.environ[key]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
            **subprocess_options(),
        )
        try:
            async with asyncio.timeout(5):
                if data is not None:
                    process.stdin.write(data)
                    await process.stdin.drain()
                    process.stdin.close()
                output = bytearray()
                while chunk := await process.stdout.read(8192):
                    output.extend(chunk)
                    if len(output) > max_bytes:
                        raise BridgeError(
                            "clipboard_limit", "Clipboard exceeds requested byte limit"
                        )
                await process.wait()
                if process.returncode != 0:
                    raise BridgeError("clipboard_unavailable", "Clipboard service unavailable")
                return bytes(output)
        finally:
            await reap_process(process)

    async def read(self, max_bytes: int) -> dict:
        async with self.lock:
            data = await self._transfer(None, max_bytes)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise BridgeError(
                "clipboard_format", "Clipboard does not contain valid UTF-8 text"
            ) from None
        return {"text": text, "bytes": len(data), "format": "text/plain;charset=utf-8"}

    async def write(self, text: str) -> dict:
        data = text.encode("utf-8")
        if len(data) > 1048576:
            raise BridgeError("clipboard_limit", "Clipboard exceeds 1 MiB byte limit")
        async with self.lock:
            await self._transfer(data, 0)
            # Verify only the just-authorized write, never poll the clipboard.
            observed = await self._transfer(None, 1048576)
        return {
            "written_bytes": len(data),
            "verified": observed == data,
            "content_sha256": hashlib.sha256(data).hexdigest(),
        }

    def info(self) -> dict:
        return {
            "platform": self.platform.name,
            "formats": ["text/plain;charset=utf-8"],
            "max_bytes": 1048576,
            "monitoring": False,
            "images": False,
            "files": False,
            "content_read": False,
        }
