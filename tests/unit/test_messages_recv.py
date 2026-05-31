"""Receive-pipeline tests: decrypt inbound nodes -> messages.upsert + store."""

from __future__ import annotations

import pytest

from piwapp.api.messages import encrypt_dm_node, encrypt_group_node
from piwapp.api.messages_recv import MessageReceiver
from piwapp.auth.creds import AuthenticationCreds
from piwapp.crypto import signal_curve as curve
from piwapp.crypto.double_ratchet import SessionBuilder
from piwapp.crypto.pre_keys import make_pre_key
from piwapp.crypto.sender_key import GroupSessionBuilder, sender_key_name
from piwapp.crypto.signal_store import SignalStore
from piwapp.events import TypedEventEmitter, WAEventType
from piwapp.store import MemoryStore

ALICE = "111@s.whatsapp.net"
BOB = "222@s.whatsapp.net"
GROUP = "120363000000000000@g.us"

pytestmark = pytest.mark.asyncio


def _bundle(creds, store, pid=777):
    pk = make_pre_key(pid)
    store.add_pre_key_from_keypair(pk.key_id, pk.key_pair)
    return {
        "identityKey": curve.prefix(creds.signed_identity_key.public),
        "registrationId": creds.registration_id,
        "signedPreKey": {
            "keyId": creds.signed_pre_key.key_id,
            "publicKey": curve.prefix(creds.signed_pre_key.key_pair.public),
            "signature": creds.signed_pre_key.signature,
        },
        "preKey": {"keyId": pk.key_id, "publicKey": curve.prefix(pk.key_pair.public)},
    }


async def test_receive_dm_emits_and_stores():
    a_creds, b_creds = AuthenticationCreds.initial(), AuthenticationCreds.initial()
    a_store, b_store = SignalStore.from_creds(a_creds), SignalStore.from_creds(b_creds)
    SessionBuilder(a_store, BOB).init_outgoing(_bundle(b_creds, b_store))

    _, node = encrypt_dm_node(a_store, BOB, "hey there")
    node.attrs["from"] = ALICE
    node.attrs["t"] = "1700000000"

    emitter = TypedEventEmitter()
    store = MemoryStore()
    store.bind(emitter)
    received = []
    emitter.on(WAEventType.MESSAGES_UPSERT, lambda p: received.append(p))

    receiver = MessageReceiver(b_store, emitter)
    out = await receiver.handle(node)

    assert out["text"] == "hey there"
    assert received and received[0].messages[0]["text"] == "hey there"
    # the bound store captured it under the chat
    assert store.message_count == 1
    msgs = store.get_chat_messages(ALICE)
    assert msgs[0]["text"] == "hey there"


async def test_receive_group_message():
    a_creds, b_creds = AuthenticationCreds.initial(), AuthenticationCreds.initial()
    a_store, b_store = SignalStore.from_creds(a_creds), SignalStore.from_creds(b_creds)
    name = sender_key_name(GROUP, ALICE)
    GroupSessionBuilder(b_store).process(name, GroupSessionBuilder(a_store).create(name))

    _, node = encrypt_group_node(a_store, GROUP, name, "group hello")
    node.attrs["from"] = GROUP
    node.attrs["participant"] = ALICE

    emitter = TypedEventEmitter()
    received = []
    emitter.on(WAEventType.MESSAGES_UPSERT, lambda p: received.append(p))

    out = await MessageReceiver(b_store, emitter).handle(node)
    assert out["text"] == "group hello"
    assert received[0].messages[0]["key"]["remoteJid"] == GROUP


async def test_undecryptable_message_emits_update_not_upsert():
    b_store = SignalStore.from_creds(AuthenticationCreds.initial())
    emitter = TypedEventEmitter()
    upserts, updates = [], []
    emitter.on(WAEventType.MESSAGES_UPSERT, lambda p: upserts.append(p))
    emitter.on(WAEventType.MESSAGES_UPDATE, lambda p: updates.append(p))

    from piwapp.binary import BinaryNode

    node = BinaryNode(
        tag="message",
        attrs={"from": ALICE, "id": "X1"},
        content=[BinaryNode(tag="enc", attrs={"v": "2", "type": "msg"}, content=b"garbage")],
    )
    out = await MessageReceiver(b_store, emitter).handle(node)
    assert out is None
    assert not upserts and updates  # surfaced as a decrypt-error update
