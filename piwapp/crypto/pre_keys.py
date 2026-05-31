"""Signal pre-key structures and generators.

Ports Baileys' ``signedKeyPair`` / ``generateRegistrationId`` helpers. Pre-keys
are one-time Curve25519 key pairs published to the server so other devices can
asynchronously establish Signal sessions; the signed pre-key is additionally
signed by the identity key (XEdDSA) for authenticity.

The async pre-key *manager* (generation queue + upload) is added in a later
phase; this module provides the value types and pure generators it builds on.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .key_utils import KeyPair, generate_key_pair, xeddsa_sign


@dataclass(slots=True)
class PreKey:
    """A one-time pre-key: an id plus its Curve25519 key pair."""

    key_id: int
    key_pair: KeyPair


@dataclass(slots=True)
class SignedPreKey:
    """A signed pre-key: a pre-key whose public key carries an XEdDSA signature."""

    key_id: int
    key_pair: KeyPair
    signature: bytes


def generate_signal_pubkey(public: bytes) -> bytes:
    """Prepend the Signal ``0x05`` type byte to a 32-byte public key (idempotent)."""
    if len(public) == 33:
        return public
    return b"\x05" + public


def generate_registration_id() -> int:
    """A random 14-bit registration id, matching Baileys' generator."""
    return int.from_bytes(os.urandom(2), "big") & 16383


def make_signed_pre_key(identity_key: KeyPair, key_id: int) -> SignedPreKey:
    """Generate a signed pre-key signed by ``identity_key`` (XEdDSA over 0x05||pub)."""
    sign_keys = generate_key_pair()
    pub = generate_signal_pubkey(sign_keys.public)
    signature = xeddsa_sign(identity_key.private, pub)
    return SignedPreKey(key_id=key_id, key_pair=sign_keys, signature=signature)


def make_pre_key(key_id: int) -> PreKey:
    """Generate a fresh one-time pre-key with the given id."""
    return PreKey(key_id=key_id, key_pair=generate_key_pair())


def generate_pre_keys(start_id: int, count: int) -> list[PreKey]:
    """Generate ``count`` consecutive pre-keys starting at ``start_id``."""
    return [make_pre_key(start_id + i) for i in range(count)]
