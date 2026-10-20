from __future__ import annotations

import os
import shutil
import signal
import sys
from pathlib import Path
from typing import Protocol

from kirabridge.bridge_core.models import BridgeError, UncertainExecution


class PlatformAdapter(Protocol):
    name: str

    def clipboard_command(self, write: bool) -> list[str]: ...


class MacOSAdapter:
    name = "macos"

    def clipboard_command(self, write: bool) -> list[str]:
        return ["/usr/bin/pbcopy" if write else "/usr/bin/pbpaste"]


class LinuxAdapter:
    name = "linux"

    def clipboard_command(self, write: bool) -> list[str]:
        if os.environ.get("WAYLAND_DISPLAY"):
            executable = shutil.which("wl-copy" if write else "wl-paste")
            args = ["--type", "text/plain;charset=utf-8"] if write else ["--no-newline"]
        else:
            executable = shutil.which("xclip")
            args = ["-selection", "clipboard", "-in" if write else "-out"]
        if not executable:
            raise BridgeError("clipboard_unavailable", "Install wl-clipboard or xclip")
        return [executable, *args]


class WindowsAdapter:
    name = "windows"

    def clipboard_command(self, write: bool) -> list[str]:
        raise BridgeError(
            "unsupported_platform", "Windows native clipboard adapter is an extension"
        )


def current_platform() -> PlatformAdapter:
    if sys.platform == "darwin":
        return MacOSAdapter()
    if sys.platform.startswith("linux"):
        return LinuxAdapter()
    return WindowsAdapter()


def subprocess_options() -> dict:
    if os.name == "posix":
        return {"start_new_session": True}
    raise BridgeError("unsupported_platform", "A Windows process-tree adapter is required")


async def spawn_process(
    argv: list[str], cwd_fd: int, env: dict, *, stdin, stdout, stderr, limit: int = 1048576
):
    import asyncio

    subprocess_options()  # Fail closed on platforms without an adapter.
    read_fd, write_fd = os.pipe()
    process = None
    transport = None
    try:
        creation = asyncio.create_task(
            asyncio.create_subprocess_exec(
                sys.executable,
                "-I",
                str(Path(__file__).with_name("_exec.py")),
                str(cwd_fd),
                str(write_fd),
                *argv,
                pass_fds=(cwd_fd, write_fd),
                env=env,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                limit=limit,
                **subprocess_options(),
            )
        )
        try:
            process = await asyncio.shield(creation)
        except asyncio.CancelledError:
            process = await creation
            raise
        os.close(write_fd)
        write_fd = -1
        reader = asyncio.StreamReader(limit=1024)
        transport, _ = await asyncio.get_running_loop().connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(read_fd, "rb")
        )
        read_fd = -1
        async with asyncio.timeout(10):
            error = await reader.read(1024)
        if error:
            raise BridgeError("spawn_failed", "Configured executable could not be started")
        return process
    except BaseException as exc:
        if process:
            await reap_process(process)
            if not isinstance(exc, (BridgeError, asyncio.CancelledError)):
                raise UncertainExecution(
                    "spawn_unknown", "Process startup outcome is unknown"
                ) from exc
        raise
    finally:
        if transport:
            transport.close()
        for fd in (read_fd, write_fd):
            if fd != -1:
                os.close(fd)


async def stop_process(process, grace: float = 2.0) -> None:
    import asyncio

    async def signal_group(value):
        try:
            os.killpg(process.pid, value)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            # Darwin can report EPERM for an orphaned group containing only zombies.
            # Verify group membership instead of silently ignoring a live process.
            import subprocess

            result = await asyncio.to_thread(
                subprocess.run,
                ["/bin/ps", "-o", "stat=", "-g", str(process.pid)],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if result.returncode not in {0, 1} or any(
                line.strip() and not line.strip().startswith("Z")
                for line in result.stdout.splitlines()
            ):
                raise
            return False

    if not await signal_group(signal.SIGTERM):
        await process.wait()
        return
    # The group can outlive its leader. Do not confuse leader exit with tree termination.
    try:
        await asyncio.wait_for(process.wait(), grace)
    except TimeoutError:
        try:
            await signal_group(signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()
    try:
        await signal_group(signal.SIGKILL)
    except ProcessLookupError:
        pass


async def reap_process(process) -> None:
    """Call only after other stream readers stop; drain pipes to avoid transport leaks."""
    import asyncio

    async def discard(reader):
        if reader is not None:
            while await reader.read(8192):
                pass

    stopping = asyncio.create_task(stop_process(process))
    try:
        async with asyncio.timeout(5):
            if process.stdin is not None:
                process.stdin.close()
                try:
                    await process.stdin.wait_closed()
                except (BrokenPipeError, ConnectionResetError):
                    pass
            await asyncio.gather(stopping, discard(process.stdout), discard(process.stderr))
    except TimeoutError:
        # asyncio exposes no public Process.close(); force-close pipes after an escaped descendant.
        process._transport.close()
        raise UncertainExecution(
            "process_cleanup_unknown", "Process cleanup could not be confirmed"
        ) from None
    finally:
        if not stopping.done():
            stopping.cancel()
        await asyncio.gather(stopping, return_exceptions=True)


class RuntimeLock:
    """Only a dispatcher holds this lock; administrative CLI transactions remain possible."""

    def __init__(self, path: Path):
        self.path, self.fd = path, None

    def acquire(self) -> None:
        if os.name != "posix":
            raise BridgeError("unsupported_platform", "Runtime locking needs a Windows adapter")
        import fcntl

        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise BridgeError(
                "already_running", "A dispatcher already owns this state directory"
            ) from None
        self.fd = fd

    def release(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
