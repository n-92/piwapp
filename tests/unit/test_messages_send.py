"""Outbound send: USync/bundle parsing + per-device encryption round-trip."""

from __future__ import annotations

from piwapp.api.messages import decrypt_dm_node, text_of
from piwapp.api.messages_send import (
    build_prekey_fetch,
    build_usync_query,
    create_participant_nodes,
    inject_sessions,
    parse_prekey_bundles,
    parse_usync_devices,
    text_message,
)
from piwapp.auth.creds import AuthenticationCreds
from piwapp.binary import BinaryNode
from piwapp.crypto import signal_curve as curve
from piwapp.crypto.pre_keys import make_pre_key
from piwapp.crypto.signal_store import SignalStore
from piwapp.utils import encode_big_endian

ALICE = "111:0@s.whatsapp.net"
BOB = "222:0@s.whatsapp.net"


def test_usync_query_structure():
    q = build_usync_query(["1@s.whatsapp.net", "2@s.whatsapp.net"], "SID1")
    usync = q.get_child("usync")
    assert usync.attrs["mode"] == "query"
    assert usync.get_child("query").get_child("devices").attrs["version"] == "2"
    assert len(usync.get_child("list").get_children("user")) == 2


def test_parse_usync_devices():
    result = BinaryNode(tag="iq", content=[BinaryNode(tag="usync", content=[
        BinaryNode(tag="list", content=[
            BinaryNode(tag="user", attrs={"jid": "5511999@s.whatsapp.net"}, content=[
                BinaryNode(tag="devices", content=[BinaryNode(tag="device-list", content=[
                    BinaryNode(tag="device", attrs={"id": "0"}),
                    BinaryNode(tag="device", attrs={"id": "23"}),
                ])])])])])])
    jids = parse_usync_devices(result)
    assert jids == ["5511999@s.whatsapp.net", "5511999:23@s.whatsapp.net"]


def test_prekey_fetch_and_bundle_roundtrip():
    creds = AuthenticationCreds.initial()
    store = SignalStore.from_creds(creds)
    pk = make_pre_key(321)
    store.add_pre_key_from_keypair(pk.key_id, pk.key_pair)

    fetch = build_prekey_fetch([BOB], "S")
    assert fetch.attrs["xmlns"] == "encrypt"
    assert fetch.get_child("key").get_children("user")[0].attrs["jid"] == BOB

    spk = creds.signed_pre_key
    # build a server-style bundle response node
    user = BinaryNode(tag="user", attrs={"jid": BOB}, content=[
        BinaryNode(tag="registration", content=encode_big_endian(creds.registration_id, 4)),
        BinaryNode(tag="identity", content=creds.signed_identity_key.public),
        BinaryNode(tag="skey", content=[
            BinaryNode(tag="id", content=encode_big_endian(spk.key_id, 3)),
            BinaryNode(tag="value", content=spk.key_pair.public),
            BinaryNode(tag="signature", content=spk.signature)]),
        BinaryNode(tag="key", content=[
            BinaryNode(tag="id", content=encode_big_endian(pk.key_id, 3)),
            BinaryNode(tag="value", content=pk.key_pair.public)]),
    ])
    result = BinaryNode(tag="iq", content=[BinaryNode(tag="list", content=[user])])
    bundles = parse_prekey_bundles(result)
    assert BOB in bundles
    b = bundles[BOB]
    assert b["identityKey"] == curve.prefix(creds.signed_identity_key.public)
    assert b["signedPreKey"]["keyId"] == spk.key_id
    assert b["preKey"]["keyId"] == pk.key_id


def test_send_encryption_decrypts_on_receiver():
    """create_participant_nodes output decrypts via our receive pipeline."""
    alice_creds, bob_creds = AuthenticationCreds.initial(), AuthenticationCreds.initial()
    alice_store, bob_store = SignalStore.from_creds(alice_creds), SignalStore.from_creds(bob_creds)

    # Bob publishes a bundle; Alice establishes a session to Bob's device
    pk = make_pre_key(99)
    bob_store.add_pre_key_from_keypair(pk.key_id, pk.key_pair)
    bundle = {
        "registrationId": bob_creds.registration_id,
        "identityKey": curve.prefix(bob_creds.signed_identity_key.public),
        "signedPreKey": {
            "keyId": bob_creds.signed_pre_key.key_id,
            "publicKey": curve.prefix(bob_creds.signed_pre_key.key_pair.public),
            "signature": bob_creds.signed_pre_key.signature,
        },
        "preKey": {"keyId": pk.key_id, "publicKey": curve.prefix(pk.key_pair.public)},
    }
    inject_sessions(alice_store, {BOB: bundle})

    nodes, include_di = create_participant_nodes(alice_store, text_message("hi from send"), [BOB])
    assert len(nodes) == 1 and include_di is True  # first message is a pkmsg
    enc = nodes[0].get_child("enc")
    assert enc.attrs["type"] == "pkmsg"

    # the server delivers this to Bob as <message from=ALICE><enc></message>
    delivered = BinaryNode(tag="message", attrs={"from": ALICE}, content=[enc])
    sender, msg = decrypt_dm_node(bob_store, delivered)
    assert text_of(msg) == "hi from send"
