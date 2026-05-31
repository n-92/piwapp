"""Pre-key upload node-building tests."""

from __future__ import annotations

from piwapp.api import prekeys
from piwapp.auth.creds import AuthenticationCreds
from piwapp.binary import BinaryNode
from piwapp.crypto.signal_store import SignalStore
from piwapp.utils import encode_big_endian


def test_count_query_structure():
    q = prekeys.build_count_query("ID1")
    assert q.tag == "iq"
    assert q.attrs == {"id": "ID1", "xmlns": "encrypt", "type": "get", "to": "@s.whatsapp.net"}
    assert q.get_child("count") is not None


def test_parse_count():
    result = BinaryNode(tag="iq", content=[BinaryNode(tag="count", attrs={"value": "42"})])
    assert prekeys.parse_count(result) == 42
    assert prekeys.parse_count(BinaryNode(tag="iq")) == 0


def test_upload_node_structure_and_registers_keys():
    creds = AuthenticationCreds.initial()
    store = SignalStore.from_creds(creds)
    start = creds.next_pre_key_id

    node = prekeys.build_upload_node(creds, store, 5, "ID2")

    assert node.attrs["xmlns"] == "encrypt" and node.attrs["type"] == "set"
    assert node.get_child("registration").content == encode_big_endian(creds.registration_id, 4)
    assert node.get_child("type").content == bytes([5])
    assert node.get_child("identity").content == creds.signed_identity_key.public

    keys = node.get_child("list").get_children("key")
    assert len(keys) == 5
    # each key has a 3-byte id and a 32-byte public value
    for k in keys:
        assert len(k.get_child("id").content) == 3
        assert len(k.get_child("value").content) == 32

    skey = node.get_child("skey")
    assert skey.get_child("value").content == creds.signed_pre_key.key_pair.public
    assert skey.get_child("signature").content == creds.signed_pre_key.signature

    # creds advanced and the generated pre-keys are now loadable from the store
    assert creds.next_pre_key_id == start + 5
    assert creds.first_unuploaded_pre_key_id == creds.next_pre_key_id
    assert store.load_pre_key(start) is not None
    assert store.load_pre_key(start + 4) is not None


def test_consecutive_uploads_use_fresh_ids():
    creds = AuthenticationCreds.initial()
    store = SignalStore.from_creds(creds)
    n1 = prekeys.build_upload_node(creds, store, 3, "A")
    n2 = prekeys.build_upload_node(creds, store, 3, "B")
    ids1 = {bytes(k.get_child("id").content) for k in n1.get_child("list").get_children("key")}
    ids2 = {bytes(k.get_child("id").content) for k in n2.get_child("list").get_children("key")}
    assert ids1.isdisjoint(ids2)
