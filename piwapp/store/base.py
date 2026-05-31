"""Abstract store protocol.

A store observes an emitter and maintains queryable state (messages, chats,
contacts, group metadata). The in-memory implementation lives in
:mod:`piwapp.store.memory_store`; a SQLite-backed store arrives in Phase 3.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..events import TypedEventEmitter


@runtime_checkable
class Store(Protocol):
    """Minimal store surface used by the client and group APIs."""

    def bind(self, emitter: TypedEventEmitter) -> None: ...

    def load_message(self, jid: str, message_id: str) -> dict[str, Any] | None: ...

    def get_chat_messages(self, jid: str) -> list[dict[str, Any]]: ...

    def get_group_metadata(self, jid: str) -> dict[str, Any] | None: ...
