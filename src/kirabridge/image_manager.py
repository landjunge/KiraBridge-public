"""Bounded PNG snapshots through the existing descriptor and task boundaries."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import stat
import struct
import zlib
from datetime import datetime, timezone

from kirabridge.bridge_core.models import BridgeError, canonical
from kirabridge.filesystem_manager import PathScope

MAX_IMAGE_BYTES = 1048576
MAX_IMAGE_SIDE = 2048
MAX_IMAGE_PIXELS = 4194304
MAX_TOOL_BYTES = 2097152
SIGNATURE = b"\x89PNG\r\n\x1a\n"


def invalid() -> BridgeError:
    return BridgeError("image_invalid", "Unsupported or invalid bounded static PNG")


def validate_png(data: bytes) -> tuple[int, int]:
    """Validate actual compressed rows, not just dimensions. No third-party decoder.

    Intentionally narrow: static, non-interlaced 8-bit RGB/RGBA; optional fixed-size
    colour/physical metadata only. Text, ICC profiles, animation and unknown chunks
    are rejected rather than passed to another decoder with different limits.
    """
    if len(data) > MAX_IMAGE_BYTES:
        raise BridgeError("image_limit", "PNG exceeds the one MiB limit")
    if not data.startswith(SIGNATURE):
        raise invalid()
    offset, width, height, channels, chunks = 8, 0, 0, 0, 0
    compressed = bytearray()
    seen = set()
    idat_ended = False
    ended = False
    metadata_lengths = {b"cHRM": 32, b"gAMA": 4, b"sRGB": 1, b"pHYs": 9}
    while offset < len(data):
        chunks += 1
        if chunks > 512:
            raise BridgeError("image_limit", "PNG exceeds the chunk count limit")
        if len(data) - offset < 12 or ended:
            raise invalid()
        length, kind = struct.unpack_from(">I4s", data, offset)
        end = offset + 12 + length
        if end > len(data):
            raise invalid()
        payload = data[offset + 8 : end - 4]
        checksum = struct.unpack_from(">I", data, end - 4)[0]
        if binascii.crc32(kind + payload) & 0xFFFFFFFF != checksum:
            raise invalid()
        if not width and kind != b"IHDR":
            raise invalid()
        if kind == b"IHDR":
            if kind in seen or offset != 8 or length != 13:
                raise invalid()
            width, height, depth, colour, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            if (
                not 1 <= width <= MAX_IMAGE_SIDE
                or not 1 <= height <= MAX_IMAGE_SIDE
                or width * height > MAX_IMAGE_PIXELS
            ):
                raise BridgeError("image_limit", "PNG dimensions exceed the image limit")
            if (
                depth != 8
                or colour not in {2, 6}
                or (compression, filtering, interlace) != (0, 0, 0)
            ):
                raise invalid()
            channels = 3 if colour == 2 else 4
        elif kind == b"IDAT":
            if idat_ended:
                raise invalid()
            compressed.extend(payload)
        elif kind == b"IEND":
            if length or b"IDAT" not in seen:
                raise invalid()
            ended = True
        elif kind in metadata_lengths:
            if kind in seen or b"IDAT" in seen or length != metadata_lengths[kind]:
                raise invalid()
            if kind == b"sRGB" and payload[0] > 3:
                raise invalid()
            if kind == b"pHYs" and payload[8] > 1:
                raise invalid()
            if kind == b"gAMA" and not int.from_bytes(payload, "big"):
                raise invalid()
        else:
            raise invalid()
        if b"IDAT" in seen and kind != b"IDAT":
            idat_ended = True
        seen.add(kind)
        offset = end
    if not ended:
        raise invalid()
    row_bytes = width * channels + 1
    expected = height * row_bytes
    try:
        decoder = zlib.decompressobj()
        rows = decoder.decompress(compressed, expected + 1)
    except zlib.error:
        raise invalid() from None
    if (
        len(rows) != expected
        or not decoder.eof
        or decoder.unconsumed_tail
        or decoder.unused_data
        or any(rows[row] > 4 for row in range(0, expected, row_bytes))
    ):
        raise invalid()
    return width, height


class ImageManager:
    def read(self, scope: PathScope, path: str) -> dict:
        with scope.parent(path) as (parent, name):
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except OSError:
                raise BridgeError(
                    "path_unavailable", "Cannot open image without symlinks"
                ) from None
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise BridgeError("file_type", "Only regular image files can be read")
                if before.st_size > MAX_IMAGE_BYTES:
                    raise BridgeError("image_limit", "PNG exceeds the one MiB limit")
                with os.fdopen(fd, "rb", closefd=False) as source:
                    data = source.read(MAX_IMAGE_BYTES + 1)
                after = os.fstat(fd)
            finally:
                os.close(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(data) != after.st_size:
            raise BridgeError("image_changed", "Image changed during snapshot read")
        width, height = validate_png(data)
        sha256 = hashlib.sha256(data).hexdigest()
        return {
            "mime_type": "image/png",
            "image_data": base64.b64encode(data).decode("ascii"),
            "bytes": len(data),
            "width": width,
            "height": height,
            "content_sha256": sha256,
            "source_mtime_ns": after.st_mtime_ns,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "source_scope": "Immutable snapshot at capture; current source may differ",
            "evidence": {"image_snapshot_validated": True, "content_sha256": sha256},
        }


def image_task_result(task: dict):
    """Return existing JSON metadata plus image only for an owned completed image task.

    Ownership MUST be checked by Bridge.task before this function. Revalidating the
    stored snapshot is bounded and never reopens or executes the original source.
    """
    from mcp.types import CallToolResult, ImageContent, TextContent

    if task.get("operation") != "file.image" or task.get("state") != "completed":
        return task
    result = task.get("result")
    if not isinstance(result, dict):
        raise invalid()
    encoded = result.get("image_data")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_IMAGE_BYTES + 2) // 3):
        raise invalid()
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise invalid() from None
    width, height = validate_png(data)
    if (
        result.get("mime_type") != "image/png"
        or result.get("content_sha256") != hashlib.sha256(data).hexdigest()
        or (result.get("width"), result.get("height"), result.get("bytes"))
        != (width, height, len(data))
    ):
        raise invalid()
    metadata = {**task, "result": {k: v for k, v in result.items() if k != "image_data"}}
    text = canonical(metadata)
    response = CallToolResult(
        content=[
            TextContent(type="text", text=text),
            ImageContent(type="image", data=encoded, mimeType="image/png"),
        ],
        structuredContent=metadata,
    )
    if len(response.model_dump_json(by_alias=True).encode()) > MAX_TOOL_BYTES:
        raise BridgeError("image_limit", "Image tool response exceeds two MiB")
    return response
