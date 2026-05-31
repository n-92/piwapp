"""Crypto primitive tests: DH symmetry, XEdDSA, HKDF vectors, AEAD round-trips."""

from __future__ import annotations

import os

import pytest

from piwapp.crypto import key_utils as k
from piwapp.crypto.pre_keys import (
    generate_registration_id,
    generate_signal_pubkey,
    make_signed_pre_key,
)


def test_dh_is_symmetric():
    a, b = k.generate_key_pair(), k.generate_key_pair()
    assert k.shared_secret(a.private, b.public) == k.shared_secret(b.private, a.public)


def test_key_pair_from_private_roundtrip():
    kp = k.generate_key_pair()
    assert k.key_pair_from_private(kp.private).public == kp.public


@pytest.mark.parametrize("seed", [os.urandom(8) for _ in range(20)])
def test_xeddsa_sign_verify(seed):
    kp = k.generate_key_pair()
    msg = k.sha256(seed)
    sig = k.xeddsa_sign(kp.private, msg)
    assert len(sig) == 64
    assert k.xeddsa_verify(kp.public, msg, sig)


def test_xeddsa_rejects_tampered_message_and_signature():
    kp = k.generate_key_pair()
    msg = b"important payload"
    sig = k.xeddsa_sign(kp.private, msg)
    assert not k.xeddsa_verify(kp.public, msg + b"!", sig)
    bad = bytearray(sig)
    bad[10] ^= 0x40
    assert not k.xeddsa_verify(kp.public, msg, bytes(bad))


def test_xeddsa_wrong_key_fails():
    signer, other = k.generate_key_pair(), k.generate_key_pair()
    msg = b"msg"
    sig = k.xeddsa_sign(signer.private, msg)
    assert not k.xeddsa_verify(other.public, msg, sig)


def test_xeddsa_deterministic_with_fixed_nonce():
    kp = k.generate_key_pair()
    z = b"\x07" * 64
    assert k.xeddsa_sign(kp.private, b"x", z) == k.xeddsa_sign(kp.private, b"x", z)


def test_hkdf_rfc5869_case1():
    # RFC 5869 Test Case 1
    ikm = b"\x0b" * 22
    salt = bytes(range(0x00, 0x0D))
    info = bytes(range(0xF0, 0xFA))
    okm = k.hkdf(ikm, 42, salt=salt, info=info)
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert okm == expected


def test_aes_gcm_roundtrip_with_aad():
    key, nonce = os.urandom(32), os.urandom(12)
    ct = k.aes_gcm_encrypt(key, b"secret", nonce, b"aad")
    assert k.aes_gcm_decrypt(key, ct, nonce, b"aad") == b"secret"


def test_aes_cbc_roundtrip_various_lengths():
    key, iv = os.urandom(32), os.urandom(16)
    for n in (1, 15, 16, 17, 64):
        pt = os.urandom(n)
        assert k.aes_cbc_decrypt(key, k.aes_cbc_encrypt(key, pt, iv), iv) == pt


def test_signed_pre_key_signature_verifies():
    identity = k.generate_key_pair()
    spk = make_signed_pre_key(identity, 1)
    signed_pub = generate_signal_pubkey(spk.key_pair.public)
    assert k.xeddsa_verify(identity.public, signed_pub, spk.signature)


def test_registration_id_is_14_bit():
    for _ in range(100):
        assert 0 <= generate_registration_id() <= 16383
