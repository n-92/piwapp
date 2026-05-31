"""SignalStore persistence: dump/load preserves working sessions + sender keys."""

from __future__ import annotations

import json

from piwapp.api.messages import (
    decrypt_dm_node,
    decrypt_group_node,
    encrypt_dm_node,
    encrypt_group_node,
    text_of,
)
from piwapp.auth.creds import AuthenticationCreds
from piwapp.crypto import signal_curve as curve
from piwapp.crypto.double_ratchet import SessionBuilder
from piwapp.crypto.pre_keys import make_pre_key
from piwapp.crypto.sender_key import GroupSessionBuilder, sender_key_name
from piwapp.crypto.signal_store import SignalStore

ALICE = "111@s.whatsapp.net"
BOB = "222@s.whatsapp.net"
GROUP = "120363000000000000@g.us"


def _bundle(creds, store, pid=555):
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


def _reload(store: SignalStore, creds) -> SignalStore:
    """Round-trip a store through JSON into a fresh store (as on restart)."""
    blob = json.dumps(store.dump())
    fresh = SignalStore.from_creds(creds)
    fresh.load(json.loads(blob))
    return fresh


def test_dm_session_survives_reload():
    a_creds, b_creds = AuthenticationCreds.initial(), AuthenticationCreds.initial()
    a_store, b_store = SignalStore.from_creds(a_creds), SignalStore.from_creds(b_creds)
    SessionBuilder(a_store, BOB).init_outgoing(_bundle(b_creds, b_store))

    # establish the session on Bob's side via the first (prekey) message
    _, node = encrypt_dm_node(a_store, BOB, "first")
    node.attrs["from"] = ALICE
    assert text_of(decrypt_dm_node(b_store, node)[1]) == "first"

    # persist Bob's store and reload into a brand-new store (simulates a restart)
    b_store2 = _reload(b_store, b_creds)

    # a subsequent message decrypts using the *reloaded* session
    _, node2 = encrypt_dm_node(a_store, BOB, "after reload")
    node2.attrs["from"] = ALICE
    sender, msg = decrypt_dm_node(b_store2, node2)
    assert text_of(msg) == "after reload"


def test_sender_key_survives_reload():
    a_creds, b_creds = AuthenticationCreds.initial(), AuthenticationCreds.initial()
    a_store, b_store = SignalStore.from_creds(a_creds), SignalStore.from_creds(b_creds)
    name = sender_key_name(GROUP, ALICE)
    GroupSessionBuilder(b_store).process(name, GroupSessionBuilder(a_store).create(name))

    b_store2 = _reload(b_store, b_creds)

    _, node = encrypt_group_node(a_store, GROUP, name, "group after reload")
    assert text_of(decrypt_group_node(b_store2, name, node)) == "group after reload"


def test_prekeys_survive_reload():
    creds = AuthenticationCreds.initial()
    store = SignalStore.from_creds(creds)
    pk = make_pre_key(4242)
    store.add_pre_key_from_keypair(pk.key_id, pk.key_pair)
    store2 = _reload(store, creds)
    assert store2.load_pre_key(4242) is not None
    assert store2.pre_key_count() == store.pre_key_count()


def test_on_change_callback_fires():
    creds = AuthenticationCreds.initial()
    store = SignalStore.from_creds(creds)
    hits = []
    store.on_change = lambda: hits.append(1)
    store.add_pre_key_from_keypair(1, make_pre_key(1).key_pair)
    assert hits  # mutation triggered persistence callback
