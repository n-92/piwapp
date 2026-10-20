"""SQLite store: event-binding, persistence across reopen, and queries."""

from __future__ import annotations

import pytest

from piwapp import proto
from piwapp.events import MessagesUpsert, TypedEventEmitter, UpsertType, WAEventType
from piwapp.store import SqliteStore

pytestmark = pytest.mark.asyncio

JID = "111@s.whatsapp.net"
GROUP = "120363000000000000@g.us"


def _msg(jid, mid, *, from_me=False, text="hi", ts=1000, msg=None, push="X"):
    return {
        "key": {"remoteJid": jid, "id": mid, "fromMe": from_me, "participant": None},
        "message": msg if msg is not None else proto.Message(conversation=text),
        "text": text,
        "messageTimestamp": ts,
        "pushName": push,
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


async def test_chat_name_falls_back_to_contact_and_group(tmp_path):
    """Live chats carry no name; contacts/groups metadata must fill them in."""
    em = TypedEventEmitter()
    store = SqliteStore(str(tmp_path / "f.db"))
    store.bind(em)

    await em.emit(WAEventType.CONTACTS_UPSERT, [{"id": JID, "name": None, "notify": "alice"}])
    await em.emit(WAEventType.GROUPS_UPSERT, [{"id": GROUP, "subject": "Team"}])
    await em.emit(WAEventType.MESSAGES_UPSERT,
                  MessagesUpsert(messages=[_msg(JID, "M1", text="hi", ts=10, push=None),
                                           _msg(GROUP, "M2", text="hey", ts=20, push=None)],
                                 type=UpsertType.NOTIFY))

    by_jid = {c["jid"]: c for c in store.recent_chats()}
    assert by_jid[JID]["name"] == "alice"   # contact.notify
    assert by_jid[GROUP]["name"] == "Team"  # group subject

    # a real chat name always wins over the fallback
    await em.emit(WAEventType.CHATS_UPSERT, [{"id": JID, "name": "Alice G.", "conversationTimestamp": 10}])
    assert {c["jid"]: c for c in store.recent_chats()}[JID]["name"] == "Alice G."
    store.close()


async def test_chat_row_is_created_from_archived_message(tmp_path):
    """Live traffic must keep `chats` populated; history sync may never arrive."""
    em = TypedEventEmitter()
    store = SqliteStore(str(tmp_path / "e.db"))
    store.bind(em)

    await em.emit(WAEventType.MESSAGES_UPSERT,
                  MessagesUpsert(messages=[_msg(JID, "C1", text="hi", ts=100)],
                                 type=UpsertType.NOTIFY))
    chats = store.recent_chats()
    assert [c["jid"] for c in chats] == [JID]
    assert chats[0]["conversation_timestamp"] == 100
    assert chats[0]["name"] == "X"  # pushName seeds a 1:1 chat name

    # an older message must not move the chat back in time, nor clobber the name
    await em.emit(WAEventType.MESSAGES_UPSERT,
                  MessagesUpsert(messages=[_msg(JID, "C2", text="older", ts=5)],
                                 type=UpsertType.NOTIFY))
    assert store.recent_chats()[0]["conversation_timestamp"] == 100
    assert store.recent_chats()[0]["name"] == "X"

    # groups get no name from pushName (that would be a participant's)
    await em.emit(WAEventType.MESSAGES_UPSERT,
                  MessagesUpsert(messages=[_msg(GROUP, "G1", text="hey", ts=200)],
                                 type=UpsertType.NOTIFY))
    by_jid = {c["jid"]: c for c in store.recent_chats()}
    assert set(by_jid) == {JID, GROUP}
    assert by_jid[GROUP]["name"] is None
    assert by_jid[GROUP]["conversation_timestamp"] == 200
    store.close()


async def test_status_and_channel_traffic_does_not_create_chats(tmp_path):
    """Statuses and channel posts are traffic, not conversations: they must not
    show up as chats (an earlier revision named `status@broadcast` after the
    contact who posted the status)."""
    db = str(tmp_path / "pseudo.db")
    em = TypedEventEmitter()
    store = SqliteStore(db)
    store.bind(em)

    await em.emit(WAEventType.MESSAGES_UPSERT, MessagesUpsert(messages=[
        _msg("status@broadcast", "S1", text="story", ts=300, push="Ana"),
        _msg("120363000000000000@newsletter", "N1", text="post", ts=200, push="Canal"),
        _msg(JID, "M1", text="hola", ts=100),
    ]))

    assert [c["jid"] for c in store.recent_chats(10)] == [JID]
    # the messages are still archived; only the chat rows are suppressed
    assert store.message_count == 3
    store.close()


async def test_recent_chats_hides_already_stored_pseudo_chats(tmp_path):
    """Archives written before the fix (or by a history sync) already contain
    these rows; listing must hide them without requiring a migration."""
    db = str(tmp_path / "legacy.db")
    em = TypedEventEmitter()
    store = SqliteStore(db)
    store.bind(em)

    await em.emit(WAEventType.CHATS_UPSERT, [
        {"id": "status@broadcast", "name": "Ana", "conversationTimestamp": 500},
        {"id": JID, "name": "Ana", "conversationTimestamp": 100},
    ])

    assert [c["jid"] for c in store.recent_chats(10)] == [JID]
    store.close()
