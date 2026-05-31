"""Sender-key (group) protocol tests with multiple members."""

from __future__ import annotations

import pytest

from piwapp.auth.creds import AuthenticationCreds
from piwapp.crypto.sender_key import (
    GroupCipher,
    GroupSessionBuilder,
    SenderKeyError,
    sender_key_name,
)
from piwapp.crypto.signal_store import SignalStore

GROUP = "120363000000000000@g.us"
ALICE = "111@s.whatsapp.net"


def _store() -> SignalStore:
    return SignalStore.from_creds(AuthenticationCreds.initial())


def test_distribute_and_decrypt_single_member():
    alice_store, bob_store = _store(), _store()
    name = sender_key_name(GROUP, ALICE)

    # Alice creates her sender key and distributes it
    skdm = GroupSessionBuilder(alice_store).create(name)
    GroupSessionBuilder(bob_store).process(name, skdm)

    alice = GroupCipher(alice_store, name)
    bob = GroupCipher(bob_store, name)

    ct = alice.encrypt(b"hello group")
    assert bob.decrypt(ct) == b"hello group"


def test_multiple_members_receive():
    alice_store = _store()
    member_stores = [_store() for _ in range(4)]
    name = sender_key_name(GROUP, ALICE)

    skdm = GroupSessionBuilder(alice_store).create(name)
    for ms in member_stores:
        GroupSessionBuilder(ms).process(name, skdm)

    alice = GroupCipher(alice_store, name)
    ct = alice.encrypt(b"broadcast to all")
    for ms in member_stores:
        assert GroupCipher(ms, name).decrypt(ct) == b"broadcast to all"


def test_sequence_of_messages():
    alice_store, bob_store = _store(), _store()
    name = sender_key_name(GROUP, ALICE)
    skdm = GroupSessionBuilder(alice_store).create(name)
    GroupSessionBuilder(bob_store).process(name, skdm)

    alice = GroupCipher(alice_store, name)
    bob = GroupCipher(bob_store, name)
    for i in range(30):
        ct = alice.encrypt(f"msg-{i}".encode())
        assert bob.decrypt(ct) == f"msg-{i}".encode()


def test_out_of_order_group_messages():
    alice_store, bob_store = _store(), _store()
    name = sender_key_name(GROUP, ALICE)
    skdm = GroupSessionBuilder(alice_store).create(name)
    GroupSessionBuilder(bob_store).process(name, skdm)

    alice = GroupCipher(alice_store, name)
    bob = GroupCipher(bob_store, name)
    cts = [alice.encrypt(f"o{i}".encode()) for i in range(5)]
    # decrypt in reverse order
    for i in reversed(range(5)):
        assert bob.decrypt(cts[i]) == f"o{i}".encode()


def test_tampered_signature_rejected():
    alice_store, bob_store = _store(), _store()
    name = sender_key_name(GROUP, ALICE)
    skdm = GroupSessionBuilder(alice_store).create(name)
    GroupSessionBuilder(bob_store).process(name, skdm)

    ct = bytearray(GroupCipher(alice_store, name).encrypt(b"x"))
    ct[-1] ^= 0x01  # corrupt the signature
    with pytest.raises(SenderKeyError):
        GroupCipher(bob_store, name).decrypt(bytes(ct))


def test_decrypt_without_distribution_fails():
    alice_store, bob_store = _store(), _store()
    name = sender_key_name(GROUP, ALICE)
    GroupSessionBuilder(alice_store).create(name)
    ct = GroupCipher(alice_store, name).encrypt(b"secret")
    # Bob never processed the distribution message
    with pytest.raises(SenderKeyError):
        GroupCipher(bob_store, name).decrypt(ct)
