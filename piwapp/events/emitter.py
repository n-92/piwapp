"""Typed async event emitter with optional group-JID and predicate filtering.

Beyond a plain emitter, this supports piwapp's group-chat differentiator:
subscribing to an event *filtered to a specific group JID* (or an arbitrary
predicate) at registration time, so handlers only fire for the groups they care
about. Handlers may be sync or async; ``emit`` awaits async ones in order.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .types import WAEventType


def extract_jid(payload: Any) -> str | None:
    """Best-effort extraction of the JID a payload pertains to (for filtering)."""
    if payload is None:
        return None
    # dict-like
    if isinstance(payload, dict):
        if "jid" in payload:
            return payload["jid"]
        key = payload.get("key")
        if isinstance(key, dict):
            return key.get("remoteJid") or key.get("remote_jid")
        return None
    # pydantic / attr objects
    return getattr(payload, "jid", None)


@dataclass
class _Handler:
    fn: Callable
    group_jid: str | None = None
    predicate: Callable[[Any], bool] | None = None

    def matches(self, payload: Any) -> bool:
        if self.group_jid is not None and extract_jid(payload) != self.group_jid:
            return False
        if self.predicate is not None and not self.predicate(payload):
            return False
        return True


@dataclass
class TypedEventEmitter:
    """Async event emitter keyed by :class:`WAEventType`."""

    _handlers: dict[WAEventType, list[_Handler]] = field(default_factory=dict)

    def on(
        self,
        event: WAEventType,
        handler: Callable,
        *,
        group_jid: str | None = None,
        predicate: Callable[[Any], bool] | None = None,
    ) -> Callable[[], None]:
        """Register ``handler``; returns an unsubscribe callable."""
        record = _Handler(handler, group_jid, predicate)
        self._handlers.setdefault(event, []).append(record)

        def _off() -> None:
            lst = self._handlers.get(event)
            if lst and record in lst:
                lst.remove(record)

        return _off

    def on_group(self, event: WAEventType, group_jid: str, handler: Callable) -> Callable[[], None]:
        """Subscribe to ``event`` but only for the given ``group_jid``."""
        return self.on(event, handler, group_jid=group_jid)

    async def emit(self, event: WAEventType, payload: Any) -> bool:
        """Dispatch ``payload`` to all matching handlers; returns True if any ran."""
        triggered = False
        for record in list(self._handlers.get(event, ())):
            if not record.matches(payload):
                continue
            triggered = True
            result = record.fn(payload)
            if inspect.isawaitable(result):
                await result
        return triggered

    def listener_count(self, event: WAEventType) -> int:
        return len(self._handlers.get(event, ()))
