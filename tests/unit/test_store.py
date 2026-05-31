"""In-memory store binding tests."""

from __future__ import annotations

import pytest

from piwapp.events import MessagesUpsert, TypedEventEmitter, UpsertType, WAEventType
from piwapp.store import MemoryStore

pytestmark = pytest.mark.asyncio

JID = "111@s.whatsapp.net"
GROUP = "120363000000000000@g.us"


async def _emit(em, store):
    store.bind(em)


async def test_messages_upsert_stored():
    em = TypedEventEmitter()
    store = MemoryStore()
    store.bind(em)

    await em.emit(
        WAEventType.MESSAGES_UPSERT,
        MessagesUpsert(
            messages=[
                {"key": {"remoteJid": JID, "id": "M1", "fromMe": False}, "text": "hi"},
                {"key": {"remoteJid": JID, "id": "M2", "fromMe": True}, "text": "yo"},
            ],
            type=UpsertType.NOTIFY,
        ),
    )

    assert store.message_count == 2
    assert store.load_message(JID, "M1")["text"] == "hi"
    assert len(store.get_chat_messages(JID)) == 2


async def test_groups_and_chats_and_contacts():
    em = TypedEventEmitter()
    store = MemoryStore()
    store.bind(em)

    await em.emit(WAEventType.GROUPS_UPSERT, [{"id": GROUP, "subject": "Team"}])
    await em.emit(WAEventType.GROUPS_UPDATE, [{"id": GROUP, "subject": "Team v2"}])
    await em.emit(WAEventType.CHATS_UPSERT, [{"id": JID, "unreadCount": 3}])
    await em.emit(WAEventType.CONTACTS_UPSERT, [{"id": JID, "name": "Alice"}])

    assert store.get_group_metadata(GROUP)["subject"] == "Team v2"
    assert store.chats[JID]["unreadCount"] == 3
    assert store.contacts[JID]["name"] == "Alice"


async def test_partial_update_merges():
    em = TypedEventEmitter()
    store = MemoryStore()
    store.bind(em)
    await em.emit(WAEventType.GROUPS_UPSERT, [{"id": GROUP, "subject": "S", "size": 5}])
    await em.emit(WAEventType.GROUPS_UPDATE, [{"id": GROUP, "size": 6}])
    meta = store.get_group_metadata(GROUP)
    assert meta["subject"] == "S" and meta["size"] == 6  # merged, not replaced


async def test_messages_without_key_ignored():
    em = TypedEventEmitter()
    store = MemoryStore()
    store.bind(em)
    await em.emit(WAEventType.MESSAGES_UPSERT, MessagesUpsert(messages=[{"text": "no key"}]))
    assert store.message_count == 0
