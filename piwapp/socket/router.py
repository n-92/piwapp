"""Decoded-node router.

Replicates Baileys' ``CB:`` callback routing. When a binary node arrives, a set
of routing keys is derived from its tag, attributes, and first child tag; every
handler registered under a matching key is invoked. An id-keyed future registry
provides request/response (IQ) matching.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from typing import Union

from ..binary import BinaryNode

Handler = Callable[[BinaryNode], Union[None, Awaitable[None]]]


def routing_keys(node: BinaryNode) -> list[str]:
    """Derive the ordered ``CB:`` routing keys for a node (Baileys-compatible)."""
    tag = node.tag
    attrs = node.attrs or {}
    children = node.content if isinstance(node.content, list) else []
    first_child = children[0].tag if children else ""

    keys: list[str] = []
    for k, v in attrs.items():
        keys.append(f"{tag},{k}:{v},{first_child}")
        keys.append(f"{tag},{k}:{v}")
        keys.append(f"{tag},{k}")
    keys.append(f"{tag},,{first_child}")
    keys.append(f"{tag}")
    return keys


class MessageRouter:
    """Dispatches decoded nodes to registered handlers and pending requests."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = {}
        self._pending: dict[str, asyncio.Future[BinaryNode]] = {}

    # -- registration ----------------------------------------------------
    def on(self, key: str, handler: Handler) -> Callable[[], None]:
        """Register ``handler`` for routing ``key``; returns an unsubscribe fn."""
        self._handlers.setdefault(key, []).append(handler)

        def _off() -> None:
            handlers = self._handlers.get(key)
            if handlers and handler in handlers:
                handlers.remove(handler)

        return _off

    def wait_for_id(self, msg_id: str) -> asyncio.Future[BinaryNode]:
        """Return a future resolved when a node with attr ``id == msg_id`` arrives."""
        fut: asyncio.Future[BinaryNode] = asyncio.get_event_loop().create_future()
        self._pending[msg_id] = fut
        return fut

    # -- dispatch --------------------------------------------------------
    async def dispatch(self, node: BinaryNode) -> bool:
        """Route ``node`` to all matching handlers and any pending id-future."""
        triggered = False

        msg_id = (node.attrs or {}).get("id")
        if msg_id and msg_id in self._pending:
            fut = self._pending.pop(msg_id)
            if not fut.done():
                fut.set_result(node)
            triggered = True

        seen: set[int] = set()
        for key in routing_keys(node):
            for handler in list(self._handlers.get(key, ())):
                if id(handler) in seen:
                    continue
                seen.add(id(handler))
                triggered = True
                result = handler(node)
                if inspect.isawaitable(result):
                    await result
        return triggered
