"""Tests for the typed emitter, group filtering, and event buffer."""

from __future__ import annotations

import pytest

from piwapp.events import (
    EventBuffer,
    GroupParticipantsUpdate,
    MessagesUpsert,
    TypedEventEmitter,
    UpsertType,
    WAEventType,
)

pytestmark = pytest.mark.asyncio

G1 = "120363000000000001@g.us"
G2 = "120363000000000002@g.us"


async def test_basic_emit_sync_and_async_handlers():
    em = TypedEventEmitter()
    seen: list = []

    em.on(WAEventType.PRESENCE_UPDATE, lambda p: seen.append(("sync", p)))

    async def ahandler(p):
        seen.append(("async", p))

    em.on(WAEventType.PRESENCE_UPDATE, ahandler)
    triggered = await em.emit(WAEventType.PRESENCE_UPDATE, {"jid": "x"})
    assert triggered
    assert ("sync", {"jid": "x"}) in seen and ("async", {"jid": "x"}) in seen


async def test_unsubscribe():
    em = TypedEventEmitter()
    hits = []
    off = em.on(WAEventType.CHATS_UPSERT, lambda p: hits.append(p))
    await em.emit(WAEventType.CHATS_UPSERT, 1)
    off()
    await em.emit(WAEventType.CHATS_UPSERT, 2)
    assert hits == [1]


async def test_group_jid_filtering():
    em = TypedEventEmitter()
    g1_events, all_events = [], []
    em.on_group(WAEventType.GROUP_PARTICIPANTS_UPDATE, G1, lambda p: g1_events.append(p))
    em.on(WAEventType.GROUP_PARTICIPANTS_UPDATE, lambda p: all_events.append(p))

    await em.emit(WAEventType.GROUP_PARTICIPANTS_UPDATE,
                  GroupParticipantsUpdate(jid=G1, participants=["a@s"], action="add"))
    await em.emit(WAEventType.GROUP_PARTICIPANTS_UPDATE,
                  GroupParticipantsUpdate(jid=G2, participants=["b@s"], action="add"))

    assert len(g1_events) == 1 and g1_events[0].jid == G1
    assert len(all_events) == 2  # unfiltered handler sees both


async def test_predicate_filtering():
    em = TypedEventEmitter()
    hits = []
    em.on(WAEventType.MESSAGES_UPSERT, lambda p: hits.append(p),
          predicate=lambda p: p.type == UpsertType.NOTIFY)
    await em.emit(WAEventType.MESSAGES_UPSERT, MessagesUpsert(messages=[{"a": 1}], type=UpsertType.APPEND))
    await em.emit(WAEventType.MESSAGES_UPSERT, MessagesUpsert(messages=[{"a": 2}], type=UpsertType.NOTIFY))
    assert len(hits) == 1 and hits[0].type == UpsertType.NOTIFY


async def test_buffer_merges_messages_upsert():
    em = TypedEventEmitter()
    buf = EventBuffer(em)
    received: list[MessagesUpsert] = []
    em.on(WAEventType.MESSAGES_UPSERT, lambda p: received.append(p))

    async with buf.buffering():
        await buf.emit(WAEventType.MESSAGES_UPSERT, MessagesUpsert(messages=[{"id": 1}], type=UpsertType.NOTIFY))
        await buf.emit(WAEventType.MESSAGES_UPSERT, MessagesUpsert(messages=[{"id": 2}], type=UpsertType.NOTIFY))
        await buf.emit(WAEventType.MESSAGES_UPSERT, MessagesUpsert(messages=[{"id": 3}], type=UpsertType.APPEND))
        assert received == []  # nothing dispatched while buffering

    # NOTIFY messages merged into one event; APPEND kept separate
    assert len(received) == 2
    notify = next(r for r in received if r.type == UpsertType.NOTIFY)
    assert [m["id"] for m in notify.messages] == [1, 2]


async def test_buffer_merges_participant_updates():
    em = TypedEventEmitter()
    buf = EventBuffer(em)
    received: list[GroupParticipantsUpdate] = []
    em.on(WAEventType.GROUP_PARTICIPANTS_UPDATE, lambda p: received.append(p))

    async with buf.buffering():
        await buf.emit(WAEventType.GROUP_PARTICIPANTS_UPDATE,
                       GroupParticipantsUpdate(jid=G1, participants=["a@s"], action="add"))
        await buf.emit(WAEventType.GROUP_PARTICIPANTS_UPDATE,
                       GroupParticipantsUpdate(jid=G1, participants=["b@s"], action="add"))
        await buf.emit(WAEventType.GROUP_PARTICIPANTS_UPDATE,
                       GroupParticipantsUpdate(jid=G1, participants=["c@s"], action="remove"))

    # same (jid, add) merged; (jid, remove) separate
    assert len(received) == 2
    add = next(r for r in received if r.action == "add")
    assert add.participants == ["a@s", "b@s"]


async def test_buffer_passthrough_when_not_buffering():
    em = TypedEventEmitter()
    buf = EventBuffer(em)
    hits = []
    em.on(WAEventType.CHATS_UPSERT, lambda p: hits.append(p))
    await buf.emit(WAEventType.CHATS_UPSERT, {"x": 1})
    assert hits == [{"x": 1}]
