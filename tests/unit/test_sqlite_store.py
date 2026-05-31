"""SQLite store: event-binding, persistence across reopen, and queries."""

from __future__ import annotations

import pytest

from piwapp import proto
from piwapp.events import MessagesUpsert, TypedEventEmitter, UpsertType, WAEventType
from piwapp.store import SqliteStore

pytestmark = pytest.mark.asyncio

JID = "111@s.whatsapp.net"
GROUP = "120363000000000000@g.us"


def _msg(jid, mid, *, from_me=False, text="hi", ts=1000, msg=None):
    return {
        "key": {"remoteJid": jid, "id": mid, "fromMe": from_me, "participant": None},
        "message": msg if msg is not None else proto.Message(conversation=text),
        "text": text,
        "messageTimestamp": ts,
        "pushName": "X",
    }


async def test_messages_persist_across_reopen(tmp_path):
    db = str(tmp_path / "a.db")
    em = TypedEventEmitter()
    store = SqliteStore(db)
    store.bind(em)
    await em.emit(WAEventType.MESSAGES_UPSERT,
                  MessagesUpsert(messages=[_msg(JID, "M1", text="hello", ts=100),
                                           _msg(JID, "M2", from_me=True, text="bye", ts=200)],
                                 type=UpsertType.NOTIFY))
    assert store.message_count == 2
    store.close()

    # reopen a fresh store on the same file — data should still be there
    store2 = SqliteStore(db)
    assert store2.message_count == 2
    msgs = store2.get_chat_messages(JID)
    assert {m["key"]["id"] for m in msgs} == {"M1", "M2"}
    assert store2.load_message(JID, "M1")["text"] == "hello"
    store2.close()


async def test_last_sent_message(tmp_path):
    em = TypedEventEmitter()
    store = SqliteStore(str(tmp_path / "b.db"))
    store.bind(em)
    await em.emit(WAEventType.MESSAGES_UPSERT, MessagesUpsert(messages=[
        _msg(JID, "A", from_me=True, text="first", ts=10),
        _msg(GROUP, "B", from_me=True, text="latest sent", ts=999),
        _msg(JID, "C", from_me=False, text="incoming", ts=1000),
    ]))
    last = store.last_sent_message()
    assert last["key"]["remoteJid"] == GROUP and last["text"] == "latest sent"
    store.close()


async def test_upsert_replaces_and_proto_roundtrip(tmp_path):
    em = TypedEventEmitter()
    store = SqliteStore(str(tmp_path / "c.db"))
    store.bind(em)
    await em.emit(WAEventType.MESSAGES_UPSERT, MessagesUpsert(messages=[_msg(JID, "M1", text="v1")]))
    await em.emit(WAEventType.MESSAGES_UPSERT, MessagesUpsert(messages=[_msg(JID, "M1", text="v2")]))
    assert store.message_count == 1  # replaced, not duplicated
    row = store.load_message(JID, "M1")
    assert row["text"] == "v2"
    # the stored proto round-trips
    parsed = proto.Message.FromString(row["proto"])
    assert parsed.conversation == "v2"
    store.close()


async def test_chats_contacts_and_search(tmp_path):
    em = TypedEventEmitter()
    store = SqliteStore(str(tmp_path / "d.db"))
    store.bind(em)
    await em.emit(WAEventType.CHATS_UPSERT, [{"id": JID, "name": "Alice", "conversationTimestamp": 5}])
    await em.emit(WAEventType.CONTACTS_UPSERT, [{"id": JID, "name": "Alice", "notify": "al"}])
    await em.emit(WAEventType.MESSAGES_UPSERT,
                  MessagesUpsert(messages=[_msg(JID, "S1", text="weather is nice", ts=1)]))
    assert store.recent_chats()[0]["name"] == "Alice"
    assert store.search_text("weather")[0]["key"]["id"] == "S1"
    store.close()
