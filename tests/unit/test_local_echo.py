"""Outgoing messages must show up in the local archive (from_me=1).

WhatsApp does not echo a message back to the sending device, so the send path
has to emit ``messages.upsert`` itself — otherwise ``last_sent_message()`` is
always ``None`` and chat rows are never created from live traffic.
"""

from __future__ import annotations

from piwapp.auth.creds import AuthenticationCreds, Me
from piwapp.config import ConnectionConfig
from piwapp.events import TypedEventEmitter, WAEventType
from piwapp.socket.connection import Connection
from piwapp.store import SqliteStore

USER = "111@s.whatsapp.net"
GROUP = "120363000000000000@g.us"
ME_ID = "999:3@s.whatsapp.net"


def _connection(events: TypedEventEmitter) -> Connection:
    creds = AuthenticationCreds.initial()
    creds.me = Me(id=ME_ID, name="me")
    return Connection(creds, ConnectionConfig(), events=events)


def _capture(events: TypedEventEmitter) -> list:
    seen: list = []
    events.on(WAEventType.MESSAGES_UPSERT, seen.append)
    return seen


async def test_send_text_emits_from_me_message(monkeypatch):
    events = TypedEventEmitter()
    conn = _connection(events)
    seen = _capture(events)

    async def fake_relay(to_jid, message, msg_id, **kwargs):
        return None

    monkeypatch.setattr(conn, "_relay_dm", fake_relay)

    msg_id = await conn.send_text(USER, "hello")

    assert len(seen) == 1
    m = seen[0].messages[0]
    assert m["key"] == {"remoteJid": USER, "id": msg_id, "fromMe": True, "participant": None}
    assert m["text"] == "hello"
    assert isinstance(m["messageTimestamp"], int)


async def test_group_send_emits_participant(monkeypatch):
    events = TypedEventEmitter()
    conn = _connection(events)
    seen = _capture(events)

    async def fake_relay(to_jid, message, msg_id, **kwargs):
        return None

    monkeypatch.setattr(conn, "_relay_group", fake_relay)

    msg_id = await conn.send_group_text(GROUP, "hi all")

    m = seen[0].messages[0]
    assert m["key"]["remoteJid"] == GROUP
    assert m["key"]["id"] == msg_id
    assert m["key"]["fromMe"] is True
    assert m["key"]["participant"] == ME_ID


async def test_sent_message_reaches_the_archive(monkeypatch, tmp_path):
    events = TypedEventEmitter()
    store = SqliteStore(str(tmp_path / "sent.db"))
    store.bind(events)
    conn = _connection(events)

    async def fake_relay(to_jid, message, msg_id, **kwargs):
        return None

    monkeypatch.setattr(conn, "_relay_dm", fake_relay)

    await conn.send_text(USER, "archived?")

    assert store.last_sent_message()["key"]["id"]
    assert store.last_sent_message()["text"] == "archived?"
    assert store.recent_chats()[0]["jid"] == USER
    store.close()


async def test_fetch_groups_emits_groups_upsert(monkeypatch):
    """Nothing else emits groups.upsert, so archives never learned subjects."""
    from piwapp.api import groups as gmod

    events = TypedEventEmitter()
    conn = _connection(events)
    seen: list = []
    events.on(WAEventType.GROUPS_UPSERT, seen.append)

    async def fake_query(_node):
        return None

    parsed = [{"id": GROUP, "subject": "Team", "participants": []}]
    monkeypatch.setattr(conn, "query", fake_query)
    monkeypatch.setattr(gmod, "parse_groups_list", lambda _result: parsed)

    assert await conn.fetch_groups() == parsed
    assert seen == [parsed]


async def test_broken_listener_does_not_break_fetch_groups(monkeypatch):
    from piwapp.api import groups as gmod

    events = TypedEventEmitter()
    conn = _connection(events)

    def boom(_payload):
        raise RuntimeError("listener exploded")

    events.on(WAEventType.GROUPS_UPSERT, boom)

    async def fake_query(_node):
        return None

    monkeypatch.setattr(conn, "query", fake_query)
    monkeypatch.setattr(gmod, "parse_groups_list", lambda _result: [{"id": GROUP, "subject": "T"}])

    assert await conn.fetch_groups() == [{"id": GROUP, "subject": "T"}]


async def test_broken_listener_does_not_fail_the_send(monkeypatch):
    events = TypedEventEmitter()
    conn = _connection(events)

    def boom(_payload):
        raise RuntimeError("listener exploded")

    events.on(WAEventType.MESSAGES_UPSERT, boom)

    async def fake_relay(to_jid, message, msg_id, **kwargs):
        return None

    monkeypatch.setattr(conn, "_relay_dm", fake_relay)

    assert await conn.send_text(USER, "still delivered")
