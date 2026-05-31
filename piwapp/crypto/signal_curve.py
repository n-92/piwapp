"""Curve helpers in the libsignal convention.

libsignal stores/transmits public keys in 33-byte ``0x05``-prefixed form and
strips the prefix before X25519 DH. Signatures use XEdDSA over the raw private
scalar. This module adapts :mod:`piwapp.crypto.key_utils` to those conventions so
the double-ratchet and sender-key code can mirror libsignal exactly.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import key_utils as _k

DJB_TYPE = 0x05


def prefix(pub: bytes) -> bytes:
    """Return the 33-byte ``0x05``-prefixed form of a public key (idempotent)."""
    if len(pub) == 33 and pub[0] == DJB_TYPE:
        return pub
    return bytes([DJB_TYPE]) + pub


def unprefix(pub: bytes) -> bytes:
    """Return the raw 32-byte key, stripping a ``0x05`` prefix if present."""
    if len(pub) == 33 and pub[0] == DJB_TYPE:
        return pub[1:]
    return pub


@dataclass(frozen=True, slots=True)
class SignalKeyPair:
    """A key pair with a 33-byte public key (libsignal convention)."""

    pub: bytes  # 33 bytes (0x05 || X25519)
    priv: bytes  # 32 bytes

    @property
    def pub32(self) -> bytes:
        return unprefix(self.pub)


def generate_key_pair() -> SignalKeyPair:
    """Generate a Curve25519 key pair with a 33-byte prefixed public key."""
    kp = _k.generate_key_pair()
    return SignalKeyPair(pub=prefix(kp.public), priv=kp.private)


def key_pair_from_private(priv: bytes) -> SignalKeyPair:
    kp = _k.key_pair_from_private(priv)
    return SignalKeyPair(pub=prefix(kp.public), priv=priv)


def calculate_agreement(pub: bytes, priv: bytes) -> bytes:
    """X25519 DH; ``pub`` may be 32- or 33-byte, ``priv`` is 32-byte."""
    return _k.shared_secret(priv, unprefix(pub))


def calculate_signature(priv: bytes, message: bytes) -> bytes:
    """XEdDSA signature over ``message`` with a 32-byte private scalar."""
    return _k.xeddsa_sign(priv, message)


def verify_signature(pub: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an XEdDSA signature; ``pub`` may be 32- or 33-byte."""
    return _k.xeddsa_verify(unprefix(pub), message, signature)
