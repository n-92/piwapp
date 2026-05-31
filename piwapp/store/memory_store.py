"""In-memory store, bindable to an event emitter.

Mirrors Baileys' ``makeInMemoryStore``: it subscribes to the event stream and
keeps messages, chats, contacts, and group metadata in memory for querying.
Message payloads follow the ``{"key": {"remoteJid", "id", "fromMe"}, ...}``
shape used throughout piwapp.
"""

from __future__ import annotations

from typing import Any

from ..events import MessagesUpsert, TypedEventEmitter, WAEventType


def _msg_key(message: dict[str, Any]) -> tuple[str, str] | None:
    key = message.get("key") or {}
    jid = key.get("remoteJid") or key.get("remote_jid")
    mid = key.get("id")
    if jid and mid:
        return jid, mid
    return None


class MemoryStore:
    """Holds messages/chats/contacts/group-metadata populated from events."""

    def __init__(self) -> None:
        # jid -> {message_id -> message}
        self.messages: dict[str, dict[str, dict[str, Any]]] = {}
        self.chats: dict[str, dict[str, Any]] = {}
        self.contacts: dict[str, dict[str, Any]] = {}
        self.group_metadata: dict[str, dict[str, Any]] = {}

    # -- binding ---------------------------------------------------------
    def bind(self, emitter: TypedEventEmitter) -> None:
        emitter.on(WAEventType.MESSAGES_UPSERT, self._on_messages_upsert)
        emitter.on(WAEventType.CHATS_UPSERT, self._on_chats_upsert)
        emitter.on(WAEventType.CHATS_UPDATE, self._on_chats_update)
        emitter.on(WAEventType.CONTACTS_UPSERT, self._on_contacts_upsert)
        emitter.on(WAEventType.GROUPS_UPSERT, self._on_groups_upsert)
        emitter.on(WAEventType.GROUPS_UPDATE, self._on_groups_update)

    # -- event handlers --------------------------------------------------
    def _on_messages_upsert(self, payload: Any) -> None:
        messages = payload.messages if isinstance(payload, MessagesUpsert) else payload.get("messages", [])
        for message in messages:
            ident = _msg_key(message)
            if ident is None:
                continue
            jid, mid = ident
            self.messages.setdefault(jid, {})[mid] = message

    def _on_chats_upsert(self, payload: Any) -> None:
        for chat in _as_list(payload):
            jid = chat.get("id") or chat.get("jid")
            if jid:
                self.chats[jid] = {**self.chats.get(jid, {}), **chat}

    def _on_chats_update(self, payload: Any) -> None:
        self._on_chats_upsert(payload)

    def _on_contacts_upsert(self, payload: Any) -> None:
        for contact in _as_list(payload):
            jid = contact.get("id") or contact.get("jid")
            if jid:
                self.contacts[jid] = {**self.contacts.get(jid, {}), **contact}

    def _on_groups_upsert(self, payload: Any) -> None:
        for group in _as_list(payload):
            jid = group.get("id") or group.get("jid")
            if jid:
                self.group_metadata[jid] = {**self.group_metadata.get(jid, {}), **group}

    def _on_groups_update(self, payload: Any) -> None:
        self._on_groups_upsert(payload)

    # -- queries ---------------------------------------------------------
    def load_message(self, jid: str, message_id: str) -> dict[str, Any] | None:
        return self.messages.get(jid, {}).get(message_id)

    def get_chat_messages(self, jid: str) -> list[dict[str, Any]]:
        return list(self.messages.get(jid, {}).values())

    def get_group_metadata(self, jid: str) -> dict[str, Any] | None:
        return self.group_metadata.get(jid)

    @property
    def message_count(self) -> int:
        return sum(len(m) for m in self.messages.values())


def _as_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return [payload]
    return []
