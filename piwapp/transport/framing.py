"""WhatsApp WebSocket frame framing.

WhatsApp prefixes every binary frame with a 3-byte big-endian length. The very
first frame of a connection is additionally prefixed with the literal routing
header ``WA\x06\x00`` (``WA`` + protocol version major/minor). This module deals
only with the length framing; encryption is handled by the Noise layer above.

Mirrors the framing logic in Baileys' ``Utils/noise-handler.ts``
(``encodeFrame`` / ``decodeFrame``).
"""

from __future__ import annotations

from collections.abc import Iterator

# Routing header sent before the very first frame: b"WA" + [version major, minor].
WA_HEADER_PREFIX = b"WA"
DEFAULT_WA_VERSION = (6, 0)
MAX_FRAME_LENGTH = (1 << 24) - 1  # 3-byte length ceiling


class FrameError(Exception):
    """Raised on malformed frames (oversized payloads, truncated lengths)."""


def wa_routing_header(version: tuple[int, int] = DEFAULT_WA_VERSION) -> bytes:
    """Return the one-time routing header prepended to the first frame."""
    return WA_HEADER_PREFIX + bytes([version[0] & 0xFF, version[1] & 0xFF])


def encode_frame(payload: bytes, *, with_header: bool = False,
                 version: tuple[int, int] = DEFAULT_WA_VERSION) -> bytes:
    """Wrap ``payload`` in a 3-byte big-endian length prefix.

    When ``with_header`` is true (only the first frame of a session), the WA
    routing header is emitted before the length-prefixed payload.
    """
    if len(payload) > MAX_FRAME_LENGTH:
        raise FrameError(f"frame too large to encode: {len(payload)} bytes")
    length = len(payload).to_bytes(3, "big")
    header = wa_routing_header(version) if with_header else b""
    return header + length + payload


class FrameDecoder:
    """Incremental decoder that yields complete frame payloads from a stream.

    WebSocket messages may arrive split or coalesced, so bytes are buffered and
    only fully-received frames are emitted. The 3-byte length prefix is consumed
    and stripped; what is yielded is the raw (still-encrypted) frame body.
    """

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> Iterator[bytes]:
        """Append ``data`` and yield every complete frame payload now available."""
        self._buf.extend(data)
        while True:
            if len(self._buf) < 3:
                return
            length = int.from_bytes(self._buf[:3], "big")
            if len(self._buf) < 3 + length:
                return
            frame = bytes(self._buf[3 : 3 + length])
            del self._buf[: 3 + length]
            yield frame

    @property
    def pending(self) -> int:
        """Number of buffered bytes not yet forming a complete frame."""
        return len(self._buf)
