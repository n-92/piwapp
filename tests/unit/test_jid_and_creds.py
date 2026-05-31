"""JID parsing/formatting and auth-credential serialisation tests."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from piwapp.auth.creds import AuthenticationCreds
from piwapp.binary import jid_decode, jid_encode
from piwapp.models.jid import JID


def test_parse_user_jid():
    j = JID.parse("1234567890@s.whatsapp.net")
    assert j.user == "1234567890"
    assert j.server == "s.whatsapp.net"
    assert j.device is None
    assert j.is_user and not j.is_group


def test_parse_device_jid():
    j = JID.parse("1234567890:7@s.whatsapp.net")
    assert j.device == 7
    assert str(j) == "1234567890:7@s.whatsapp.net"


def test_parse_group_and_lid():
    assert JID.parse("12036330@g.us").is_group
    assert JID.parse("99999@lid").is_lid


def test_status_broadcast():
    assert JID.parse("status@broadcast").is_status_broadcast


def test_same_user_ignores_device():
    a = JID.parse("123:1@s.whatsapp.net")
    assert a.same_user("123:2@s.whatsapp.net")
    assert not a.same_user("456@s.whatsapp.net")


def test_invalid_jid_raises():
    with pytest.raises(ValueError):
        JID.parse("not-a-jid")
    assert JID.try_parse("not-a-jid") is None


def test_encode_decode_inverse():
    for jid in ["123@s.whatsapp.net", "123:5@s.whatsapp.net", "g@g.us", "9@lid"]:
        d = jid_decode(jid)
        assert d is not None
        assert jid_encode(d.user, d.server, d.device) == jid


@given(st.text(min_size=0, max_size=20))
def test_jid_decode_never_crashes(s: str):
    jid_decode(s)  # must not raise


# -- credentials ---------------------------------------------------------
def test_initial_creds_are_valid():
    creds = AuthenticationCreds.initial()
    assert not creds.registered
    assert 0 <= creds.registration_id <= 16383
    assert len(creds.adv_secret_key) == 32
    assert len(creds.noise_key.private) == 32
    assert creds.next_pre_key_id == 1


def test_creds_json_roundtrip():
    creds = AuthenticationCreds.initial()
    restored = AuthenticationCreds.from_json(creds.to_json())
    assert restored.registration_id == creds.registration_id
    assert restored.noise_key.private == creds.noise_key.private
    assert restored.signed_identity_key.public == creds.signed_identity_key.public
    assert restored.signed_pre_key.signature == creds.signed_pre_key.signature
    assert restored.adv_secret_key == creds.adv_secret_key


def test_signed_pre_key_signature_in_creds_verifies():
    from piwapp.crypto.key_utils import xeddsa_verify
    from piwapp.crypto.pre_keys import generate_signal_pubkey

    creds = AuthenticationCreds.initial()
    identity_pub = creds.signed_identity_key.public
    signed_pub = generate_signal_pubkey(creds.signed_pre_key.key_pair.public)
    assert xeddsa_verify(identity_pub, signed_pub, creds.signed_pre_key.signature)
