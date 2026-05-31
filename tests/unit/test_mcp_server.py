"""MCP server: archive tools over a seeded DB, helpers, and read-only guards."""

from __future__ import annotations

import json

import pytest

mcp_mod = pytest.importorskip("piwapp.mcp_server")  # skip if mcp SDK absent

from piwapp import proto  # noqa: E402
from piwapp.events import MessagesUpsert, TypedEventEmitter, WAEventType  # noqa: E402
from piwapp.store import SqliteStore  # noqa: E402

GROUP = "120363000000000000@g.us"
USER = "111@s.whatsapp.net"


def _structured(result):
    """call_tool -> (content, structured) or content-only; return python value."""
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        s = result[1]
        return s["result"] if list(s.keys()) == ["result"] else s
    # fall back to parsing TextContent JSON
    content = result[0] if isinstance(result, tuple) else result
    vals = [json.loads(c.text) for c in content]
    return vals[0] if len(vals) == 1 else vals


def _msg(jid, mid, *, from_me=False, text="hi", ts=1000):
    return {
        "key": {"remoteJid": jid, "id": mid, "fromMe": from_me, "participant": None},
        "message": proto.Message(conversation=text),
        "text": text,
        "messageTimestamp": ts,
        "pushName": "X",
    }


async def _seed(db_path: str) -> None:
    em = TypedEventEmitter()
    store = SqliteStore(db_path)
    store.bind(em)
    await em.emit(WAEventType.CHATS_UPSERT,
                  [{"id": GROUP, "name": "Test group", "conversationTimestamp": 50}])
    await em.emit(WAEventType.MESSAGES_UPSERT, MessagesUpsert(messages=[
        _msg(USER, "A", from_me=False, text="hello there", ts=10),
        _msg(GROUP, "B", from_me=True, text="weather update", ts=99),
    ]))
    store.close()


def test_normalize_jid():
    assert mcp_mod._normalize_jid("12345@s.whatsapp.net") == "12345@s.whatsapp.net"
    assert mcp_mod._normalize_jid("g@g.us") == "g@g.us"
    assert mcp_mod._normalize_jid("+1 234-567") == "1234567@s.whatsapp.net"


def test_fmt_msg_drops_proto():
    out = mcp_mod._fmt_msg(_msg(USER, "Z", from_me=True, text="hi", ts=10))
    assert out["chat"] == USER and out["from_me"] is True and out["text"] == "hi"
    assert "proto" not in out  # raw protobuf blob is never leaked


@pytest.mark.asyncio
async def test_archive_tools(tmp_path, monkeypatch):
    db = str(tmp_path / "mcp.db")
    await _seed(db)
    monkeypatch.setattr(mcp_mod.state, "db_path", db)
    monkeypatch.setattr(mcp_mod.state, "auth_path", None)

    async with mcp_mod._lifespan(mcp_mod.mcp):
        stats = _structured(await mcp_mod.mcp.call_tool("archive_stats", {}))
        assert stats["messages"] == 2 and stats["live"] is False

        chats = _structured(await mcp_mod.mcp.call_tool("list_chats", {"limit": 5}))
        assert chats[0]["jid"] == GROUP and chats[0]["is_group"] is True

        last = _structured(await mcp_mod.mcp.call_tool("last_sent_message", {}))
        assert last["chat"] == GROUP and last["text"] == "weather update"

        msgs = _structured(await mcp_mod.mcp.call_tool("get_messages", {"chat_jid": USER}))
        assert msgs[0]["text"] == "hello there"

        found = _structured(await mcp_mod.mcp.call_tool("search_messages", {"query": "weather"}))
        assert found[0]["id"] == "B"


async def test_send_refused_in_readonly(tmp_path, monkeypatch):
    db = str(tmp_path / "ro.db")
    await _seed(db)
    monkeypatch.setattr(mcp_mod.state, "db_path", db)
    monkeypatch.setattr(mcp_mod.state, "auth_path", None)
    async with mcp_mod._lifespan(mcp_mod.mcp):
        with pytest.raises(Exception):  # tool raises -> ToolError surfaced
            await mcp_mod.mcp.call_tool("send_message", {"to": "123", "text": "x"})


def test_on_incoming_skips_from_me(monkeypatch):
    import asyncio

    from piwapp.events import MessagesUpsert
    q = asyncio.Queue()
    monkeypatch.setattr(mcp_mod.state, "incoming", q)
    mcp_mod._on_incoming(MessagesUpsert(messages=[
        _msg(USER, "A", from_me=False, text="incoming"),
        _msg(USER, "B", from_me=True, text="my own echo"),
    ]))
    assert q.qsize() == 1
    assert q.get_nowait()["text"] == "incoming"


@pytest.mark.asyncio
async def test_wait_for_messages(monkeypatch):
    import asyncio

    monkeypatch.setattr(mcp_mod.state, "client", object())   # pretend live
    q = asyncio.Queue()
    monkeypatch.setattr(mcp_mod.state, "incoming", q)

    # already-queued message returns immediately
    q.put_nowait({"chat": GROUP, "text": "hello", "from_me": False})
    res = _structured(await mcp_mod.mcp.call_tool("wait_for_messages", {"timeout": 1}))
    assert res[0]["text"] == "hello"

    # nothing queued -> times out to empty
    empty = _structured(await mcp_mod.mcp.call_tool("wait_for_messages", {"timeout": 0}))
    assert empty == []


@pytest.mark.asyncio
async def test_missing_auth_stays_unpaired(tmp_path, monkeypatch):
    """PIWAPP_AUTH pointing at a missing file must not crash; pairing is offered."""
    db = str(tmp_path / "u.db")
    await _seed(db)
    monkeypatch.setattr(mcp_mod.state, "db_path", db)
    monkeypatch.setattr(mcp_mod.state, "auth_path", str(tmp_path / "nope.json"))
    monkeypatch.setattr(mcp_mod.state, "client", None)
    async with mcp_mod._lifespan(mcp_mod.mcp):     # no crash
        names = {t.name for t in await mcp_mod.mcp.list_tools()}
        assert {"start_pairing", "pairing_status"} <= names
        status = _structured(await mcp_mod.mcp.call_tool("pairing_status", {}))
        assert status["client_started"] is False and status["online"] is False
