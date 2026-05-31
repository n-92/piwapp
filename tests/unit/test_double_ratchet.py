"""Two-party Signal X3DH + Double Ratchet tests."""

from __future__ import annotations

import pytest

from piwapp.auth.creds import AuthenticationCreds
from piwapp.crypto import signal_curve as curve
from piwapp.crypto.double_ratchet import SessionBuilder, SessionCipher
from piwapp.crypto.pre_keys import make_pre_key
from piwapp.crypto.signal_store import SignalStore


def _store(creds: AuthenticationCreds) -> SignalStore:
    return SignalStore.from_creds(creds)


def deliver(cipher: SessionCipher, packet: tuple[int, bytes]) -> bytes:
    """Route a (type, body) packet to the right decrypt method.

    The initiator keeps emitting type-3 (PreKeySignalMessage) packets until it
    has received and decrypted a reply; this helper handles both kinds.
    """
    msg_type, body = packet
    if msg_type == 3:
        return cipher.decrypt_prekey_message(body)
    return cipher.decrypt_message(body)


def _bundle(creds: AuthenticationCreds, store: SignalStore, pre_key_id: int = 12345):
    """Build a pre-key bundle for ``creds`` and register the one-time pre-key."""
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
        "preKey": {
            "keyId": pk.key_id,
            "publicKey": curve.prefix(pk.key_pair.public),
        },
    }


@pytest.fixture
def parties():
    alice_creds = AuthenticationCreds.initial()
    bob_creds = AuthenticationCreds.initial()
    alice_store = _store(alice_creds)
    bob_store = _store(bob_creds)
    bob_bundle = _bundle(bob_creds, bob_store)
    # Alice establishes an outgoing session to Bob
    SessionBuilder(alice_store, "bob").init_outgoing(bob_bundle)
    return alice_store, bob_store


def test_initial_prekey_message_and_reply(parties):
    alice_store, bob_store = parties
    alice = SessionCipher(alice_store, "bob")
    bob = SessionCipher(bob_store, "alice")

    msg_type, body = alice.encrypt(b"hello bob")
    assert msg_type == 3  # PreKeySignalMessage
    assert bob.decrypt_prekey_message(body) == b"hello bob"

    # Bob can now reply with a normal (type 1) message
    rtype, rbody = bob.encrypt(b"hi alice")
    assert rtype == 1
    assert alice.decrypt_message(rbody) == b"hi alice"


def test_many_back_and_forth(parties):
    alice_store, bob_store = parties
    alice = SessionCipher(alice_store, "bob")
    bob = SessionCipher(bob_store, "alice")

    for i in range(25):
        assert deliver(bob, alice.encrypt(f"a{i}".encode())) == f"a{i}".encode()
        assert deliver(alice, bob.encrypt(f"b{i}".encode())) == f"b{i}".encode()


def test_out_of_order_delivery(parties):
    alice_store, bob_store = parties
    alice = SessionCipher(alice_store, "bob")
    bob = SessionCipher(bob_store, "alice")

    # bootstrap so the session exists on Bob's side
    assert deliver(bob, alice.encrypt(b"start")) == b"start"

    # Alice sends three more; Bob receives them out of order
    msgs = [alice.encrypt(f"m{i}".encode()) for i in range(3)]
    assert deliver(bob, msgs[2]) == b"m2"
    assert deliver(bob, msgs[0]) == b"m0"
    assert deliver(bob, msgs[1]) == b"m1"


def test_replay_is_rejected(parties):
    alice_store, bob_store = parties
    alice = SessionCipher(alice_store, "bob")
    bob = SessionCipher(bob_store, "alice")

    assert deliver(bob, alice.encrypt(b"start")) == b"start"
    once = alice.encrypt(b"once")
    assert deliver(bob, once) == b"once"
    with pytest.raises(Exception):
        deliver(bob, once)  # message key already consumed


def test_session_without_one_time_prekey():
    alice_creds = AuthenticationCreds.initial()
    bob_creds = AuthenticationCreds.initial()
    alice_store, bob_store = _store(alice_creds), _store(bob_creds)
    # bundle WITHOUT a one-time pre-key
    bundle = {
        "identityKey": curve.prefix(bob_creds.signed_identity_key.public),
        "registrationId": bob_creds.registration_id,
        "signedPreKey": {
            "keyId": bob_creds.signed_pre_key.key_id,
            "publicKey": curve.prefix(bob_creds.signed_pre_key.key_pair.public),
            "signature": bob_creds.signed_pre_key.signature,
        },
    }
    SessionBuilder(alice_store, "bob").init_outgoing(bundle)
    alice = SessionCipher(alice_store, "bob")
    bob = SessionCipher(bob_store, "alice")
    assert deliver(bob, alice.encrypt(b"no-otp")) == b"no-otp"
    # and a reply round-trips
    assert deliver(alice, bob.encrypt(b"reply")) == b"reply"
