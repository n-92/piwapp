"""Small shared helpers (big-endian encoding, message tags)."""

from __future__ import annotations

import os
import time


def encode_big_endian(value: int, length: int = 4) -> bytes:
    """Encode ``value`` as a big-endian byte string of ``length`` bytes."""
    return value.to_bytes(length, "big")


_epoch = int(time.time())
_counter = 0


def generate_message_tag() -> str:
    """Generate a process-unique message id/tag (epoch-based, like Baileys)."""
    global _counter
    _counter += 1
    return f"{_epoch}.{_counter}-{os.getpid() % 1000}"
