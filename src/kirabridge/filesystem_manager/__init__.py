from __future__ import annotations

import os
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path

from kirabridge.bridge_core.models import BridgeError


class PathScope:
    """POSIX descriptor-relative traversal: no symlink follows, including at open time."""

    def __init__(self, roots: list[str], excluded: list[str] | None = None):
        self.roots = sorted(
            (Path(p).absolute() for p in roots), key=lambda p: len(p.parts), reverse=True
        )
        self.excluded = [Path(p).absolute() for p in (excluded or [])]

    def split(self, value: str) -> tuple[Path, Path]:
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts or "\x00" in value:
            raise BridgeError("path_denied", "Use an absolute path inside an allowed root")
        if any(path.is_relative_to(excluded) for excluded in self.excluded):
            raise BridgeError("path_denied", "Bridge state is not available through file tools")
        for root in self.roots:
            if path.is_relative_to(root):
                return root, path.relative_to(root)
        raise BridgeError("path_denied", "Path outside allowed roots")

    @contextmanager
    def directory(self, value: str):
        if os.name != "posix":
            raise BridgeError("unsupported_platform", "Secure Windows filesystem adapter required")
        self.split(value)
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in Path(value).parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
        except OSError:
            os.close(fd)
            raise BridgeError(
                "path_denied", "Cannot open a directory without following symlinks"
            ) from None
        try:
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def parent(self, value: str):
        root, relative = self.split(value)
        if relative == Path("."):
            raise BridgeError("path_denied", "Cannot mutate or open the allowed root as a file")
        with self.directory(str(root / relative.parent)) as fd:
            yield fd, relative.name


class FilesystemManager:
    def read(self, scope: PathScope, path: str, max_bytes: int) -> dict:
        with scope.parent(path) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise BridgeError("file_type", "Only regular files can be read")
                with os.fdopen(fd, "rb", closefd=False) as source:
                    data = source.read(max_bytes + 1)
            finally:
                os.close(fd)
        try:
            text = data[:max_bytes].decode("utf-8")
        except UnicodeDecodeError:
            text = data[:max_bytes].decode("utf-8", errors="replace")
        return {
            "text": text,
            "bytes": min(len(data), max_bytes),
            "truncated": len(data) > max_bytes,
        }

    def list(self, scope: PathScope, path: str) -> dict:
        entries = []
        with scope.directory(path) as fd, os.scandir(fd) as iterator:
            for entry in iterator:
                if len(entries) == 1000:
                    return {"entries": entries, "truncated": True}
                entries.append(
                    {
                        "name": entry.name,
                        "directory": entry.is_dir(follow_symlinks=False),
                        "symlink": entry.is_symlink(),
                    }
                )
        return {"entries": sorted(entries, key=lambda x: x["name"]), "truncated": False}

    def write(self, scope: PathScope, path: str, text: str, overwrite: bool) -> dict:
        data = text.encode("utf-8")
        if len(data) > 1048576:
            raise BridgeError("payload_limit", "File content exceeds byte limit")
        with scope.parent(path) as (parent, name):
            temporary = ".kirabridge-" + uuid.uuid4().hex
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            try:
                with os.fdopen(fd, "wb") as target:
                    target.write(data)
                    target.flush()
                    os.fsync(target.fileno())
                if overwrite:
                    try:
                        mode = os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode
                        if not stat.S_ISREG(mode):
                            raise BridgeError("file_type", "Only regular files may be overwritten")
                    except FileNotFoundError:
                        pass
                    os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
                else:
                    os.link(
                        temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False
                    )
                os.fsync(parent)
            finally:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
        return {
            "written_bytes": len(data),
            "content_sha256": __import__("hashlib").sha256(data).hexdigest(),
        }

    def mkdir(self, scope: PathScope, path: str) -> dict:
        with scope.parent(path) as (parent, name):
            os.mkdir(name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
        return {"created": True}

    def delete(self, scope: PathScope, path: str) -> dict:
        # No recursive removal: approval authorizes exactly this file or empty directory.
        with scope.parent(path) as (parent, name):
            mode = os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode
            if stat.S_ISLNK(mode):
                raise BridgeError("path_denied", "Symlink deletion is not supported")
            if stat.S_ISDIR(mode):
                os.rmdir(name, dir_fd=parent)
            elif stat.S_ISREG(mode):
                os.unlink(name, dir_fd=parent)
            else:
                raise BridgeError("file_type", "Unsupported file type")
            os.fsync(parent)
        return {"deleted": True}

    def move(self, scope: PathScope, path: str, destination: str) -> dict:
        # Atomic no-clobber link/unlink of regular files, only on the same filesystem.
        with (
            scope.parent(path) as (source_fd, source),
            scope.parent(destination) as (dest_fd, dest),
        ):
            mode = os.stat(source, dir_fd=source_fd, follow_symlinks=False).st_mode
            if not stat.S_ISREG(mode):
                raise BridgeError("file_type", "Move supports regular files only")
            os.link(source, dest, src_dir_fd=source_fd, dst_dir_fd=dest_fd, follow_symlinks=False)
            os.fsync(dest_fd)
            os.unlink(source, dir_fd=source_fd)
            os.fsync(source_fd)
        return {"moved": True}
