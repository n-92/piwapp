"""Event buffering with merge-on-flush.

While buffering, emitted events are queued instead of dispatched. On flush they
are coalesced — multiple ``messages.upsert`` of the same type merge into one
event, and multiple ``group-participants.update`` for the same (jid, action)
merge — then dispatched in original order. This mirrors Baileys' event buffer,
which batches a burst of server notifications into consolidated events.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from .emitter import TypedEventEmitter
from .types import GroupParticipantsUpdate, MessagesUpsert, WAEventType


class EventBuffer:
    """Wraps an emitter to optionally batch + merge events before dispatch."""

    def __init__(self, emitter: TypedEventEmitter) -> None:
        self._emitter = emitter
        self._depth = 0
        self._queue: list[tuple[WAEventType, Any]] = []

    @property
    def is_buffering(self) -> bool:
        return self._depth > 0

    def start(self) -> None:
        self._depth += 1

    async def flush(self) -> None:
        if self._depth == 0:
            return
        self._depth -= 1
        if self._depth > 0:
            return
        items, self._queue = self._queue, []
        for event, payload in self._merge(items):
            await self._emitter.emit(event, payload)

    @asynccontextmanager
    async def buffering(self) -> AsyncIterator[None]:
        """Async context manager: buffer events within the block, flush on exit."""
        self.start()
        try:
            yield
        finally:
            await self.flush()

    async def emit(self, event: WAEventType, payload: Any) -> None:
        """Emit now, or queue if buffering."""
        if self._depth > 0:
            self._queue.append((event, payload))
        else:
            await self._emitter.emit(event, payload)

    # -- merge -----------------------------------------------------------
    @staticmethod
    def _merge(items: list[tuple[WAEventType, Any]]) -> list[tuple[WAEventType, Any]]:
        out: list[tuple[WAEventType, Any]] = []
        upserts: dict[Any, int] = {}  # upsert type -> index in out
        participants: dict[tuple[str, str], int] = {}  # (jid, action) -> index

        for event, payload in items:
            if event == WAEventType.MESSAGES_UPSERT and isinstance(payload, MessagesUpsert):
                key = payload.type
                if key in upserts:
                    out[upserts[key]][1].messages.extend(payload.messages)
                else:
                    upserts[key] = len(out)
                    out.append((event, payload.model_copy(deep=True)))
            elif event == WAEventType.GROUP_PARTICIPANTS_UPDATE and isinstance(
                payload, GroupParticipantsUpdate
            ):
                key = (payload.jid, payload.action)
                if key in participants:
                    out[participants[key]][1].participants.extend(payload.participants)
                else:
                    participants[key] = len(out)
                    out.append((event, payload.model_copy(deep=True)))
            else:
                out.append((event, payload))
        return out
