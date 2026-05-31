"""End-to-end message encode/decode over Signal sessions and sender keys."""

from __future__ import annotations

import pytest

from piwapp.api.messages import (
    decrypt_dm_node,
    decrypt_group_node,
    encode_wa_message,
    encrypt_dm_node,
    encrypt_group_node,
    generate_message_id,
    pad_message,
    text_of,
    unpad_message,
)
from piwapp.auth.creds import AuthenticationCreds
from piwapp.crypto import signal_curve as curve
from piwapp.crypto.double_ratchet import SessionBuilder
from piwapp.crypto.pre_keys import make_pre_key
from piwapp.crypto.sender_key import GroupSessionBuilder, sender_key_name
from piwapp.crypto.signal_store import SignalStore
from piwapp.models.message import TextContent, to_message_proto

ALICE = "111@s.whatsapp.net"
BOB = "222@s.whatsapp.net"
GROUP = "120363000000000000@g.us"


def test_padding_roundtrip():
    for n in (0, 1, 31, 256):
        data = bytes(range(n % 256)) if n else b""
        padded = pad_message(data)
        assert 1 <= len(padded) - len(data) <= 16
        assert unpad_message(padded) == data


def test_message_id_format():
    mid = generate_message_id()
    assert mid.startswith("3EB0") and len(mid) == 4 + 36


def test_encode_wa_message_is_padded_proto():
    proto_msg = to_message_proto(TextContent(text="hi"))
    raw = proto_msg.SerializeToString()
    assert len(encode_wa_message(proto_msg)) > len(raw)


def _bundle(creds, store, pre_key_id=999):
    pk = make_pre_key(pre_key_id)
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


def test_dm_message_node_roundtrip():
    alice_creds, bob_creds = AuthenticationCreds.initial(), AuthenticationCreds.initial()
    alice_store, bob_store = SignalStore.from_creds(alice_creds), SignalStore.from_creds(bob_creds)
    SessionBuilder(alice_store, BOB).init_outgoing(_bundle(bob_creds, bob_store))

    # Alice encrypts a DM node to Bob
    mid, node = encrypt_dm_node(alice_store, BOB, "hello bob")
    assert node.tag == "message" and node.attrs["to"] == BOB
    enc = node.get_child("enc")
    assert enc.attrs["type"] == "pkmsg"  # first message is a pre-key message

    # Bob receives it (sender stamped in 'from')
    node.attrs["from"] = ALICE
    sender, message = decrypt_dm_node(bob_store, node)
    assert sender == ALICE
    assert text_of(message) == "hello bob"


def test_group_message_node_roundtrip():
    alice_creds, bob_creds = AuthenticationCreds.initial(), AuthenticationCreds.initial()
    alice_store, bob_store = SignalStore.from_creds(alice_creds), SignalStore.from_creds(bob_creds)
    name = sender_key_name(GROUP, ALICE)

    # Alice creates + distributes her sender key; Bob processes it
    skdm = GroupSessionBuilder(alice_store).create(name)
    GroupSessionBuilder(bob_store).process(name, skdm)

    mid, node = encrypt_group_node(alice_store, GROUP, name, "hello group")
    assert node.get_child("enc").attrs["type"] == "skmsg"

    message = decrypt_group_node(bob_store, name, node)
    assert text_of(message) == "hello group"
