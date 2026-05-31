"""Cryptographic primitives shared across the Noise, Signal, and auth layers.

WhatsApp/Signal use Curve25519 keys for *both* Diffie-Hellman (X25519) and
signatures (XEdDSA — signing with a Montgomery key by deriving the matching
Edwards key). Standard Ed25519 is not interchangeable with XEdDSA, so signed
pre-keys and device signatures MUST use the XEdDSA functions here.

The XEdDSA implementation is built on libsodium's reduced-scalar / Edwards
point primitives (exposed via PyNaCl) rather than hand-rolled field math, to
minimise the risk of subtle arithmetic bugs.

Primitive choices:

* X25519 DH, AES-GCM, AES-CBC, HKDF, HMAC — :mod:`cryptography`.
* Ed25519 scalar/point ops for XEdDSA — :mod:`nacl.bindings` (libsodium).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

import nacl.bindings as sodium
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Curve25519 field / group constants.
_P = 2**255 - 19  # field prime
# XEdDSA nonce-hash domain separator: (2**256 - 1 - 1) little-endian.
_XEDDSA_HASH1_PREFIX = b"\xfe" + b"\xff" * 31


@dataclass(frozen=True, slots=True)
class KeyPair:
    """A Curve25519 key pair.

    ``private`` is the 32-byte clamped scalar (as Signal stores it); ``public``
    is the 32-byte Montgomery u-coordinate.
    """

    private: bytes
    public: bytes

    def __post_init__(self) -> None:
        if len(self.private) != 32 or len(self.public) != 32:
            raise ValueError("Curve25519 keys must be 32 bytes")


# ----------------------------------------------------------------------
# Randomness & hashes
# ----------------------------------------------------------------------
def random_bytes(n: int) -> bytes:
    """Return ``n`` cryptographically-secure random bytes."""
    return os.urandom(n)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


# ----------------------------------------------------------------------
# X25519 (Diffie-Hellman)
# ----------------------------------------------------------------------
def _clamp(seed: bytes) -> bytes:
    a = bytearray(seed)
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return bytes(a)


def generate_key_pair() -> KeyPair:
    """Generate a fresh Curve25519 key pair with a clamped private scalar."""
    seed = _clamp(os.urandom(32))
    priv = X25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes_raw()
    return KeyPair(private=seed, public=pub)


def key_pair_from_private(private: bytes) -> KeyPair:
    """Reconstruct a :class:`KeyPair` from a 32-byte private scalar."""
    priv = X25519PrivateKey.from_private_bytes(private)
    return KeyPair(private=private, public=priv.public_key().public_bytes_raw())


def shared_secret(private: bytes, peer_public: bytes) -> bytes:
    """Compute the X25519 shared secret between ``private`` and ``peer_public``."""
    priv = X25519PrivateKey.from_private_bytes(private)
    pub = X25519PublicKey.from_public_bytes(peer_public)
    return priv.exchange(pub)


# ----------------------------------------------------------------------
# XEdDSA (Curve25519 signatures, Signal-compatible)
# ----------------------------------------------------------------------
def _reduce_scalar(data: bytes) -> bytes:
    """Reduce a little-endian byte string mod the group order L (-> 32 bytes)."""
    if len(data) < 64:
        data = data + b"\x00" * (64 - len(data))
    return sodium.crypto_core_ed25519_scalar_reduce(data[:64])


def _edwards_pubkey_from_scalar(scalar: bytes) -> bytes:
    return sodium.crypto_scalarmult_ed25519_base_noclamp(scalar)


def _montgomery_to_edwards(u_pub: bytes) -> bytes:
    """Map a Montgomery u-coordinate to a compressed Edwards point (sign bit 0)."""
    u = int.from_bytes(u_pub, "little") % (2**255)
    u %= _P
    denom = (u + 1) % _P
    if denom == 0:
        raise ValueError("invalid Montgomery point")
    y = ((u - 1) * pow(denom, _P - 2, _P)) % _P
    enc = bytearray(y.to_bytes(32, "little"))
    enc[31] &= 0x7F  # force sign bit 0
    return bytes(enc)


def xeddsa_sign(private_scalar: bytes, message: bytes, nonce: bytes | None = None) -> bytes:
    """Produce a 64-byte XEdDSA signature ``R || s`` over ``message``.

    ``private_scalar`` is the 32-byte Curve25519 private key. ``nonce`` (the
    64-byte ``Z`` value) is randomised unless supplied (useful for test vectors).
    """
    z = nonce if nonce is not None else os.urandom(64)
    a = _reduce_scalar(private_scalar)
    big_a = _edwards_pubkey_from_scalar(a)
    sign_bit = big_a[31] >> 7
    big_a = big_a[:31] + bytes([big_a[31] & 0x7F])
    if sign_bit:
        a = sodium.crypto_core_ed25519_scalar_negate(a)

    r = _reduce_scalar(sha512(_XEDDSA_HASH1_PREFIX + a + message + z))
    big_r = _edwards_pubkey_from_scalar(r)
    h = _reduce_scalar(sha512(big_r + big_a + message))
    s = sodium.crypto_core_ed25519_scalar_add(
        r, sodium.crypto_core_ed25519_scalar_mul(h, a)
    )
    return big_r + s


def xeddsa_verify(montgomery_public: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a 64-byte XEdDSA signature against a Montgomery public key."""
    if len(signature) != 64:
        return False
    big_r, s = signature[:32], signature[32:]
    # s must be canonical (< L): top 4 bits of the last byte are always zero.
    if s[31] & 0xE0:
        return False
    try:
        big_a = _montgomery_to_edwards(montgomery_public)
        h = _reduce_scalar(sha512(big_r + big_a + message))
        s_b = sodium.crypto_scalarmult_ed25519_base_noclamp(s)
        h_a = sodium.crypto_scalarmult_ed25519_noclamp(h, big_a)
        rhs = sodium.crypto_core_ed25519_add(big_r, h_a)
    except Exception:
        return False
    return hmac.compare_digest(s_b, rhs)


# ----------------------------------------------------------------------
# HKDF / symmetric ciphers
# ----------------------------------------------------------------------
def hkdf(input_key_material: bytes, length: int, *, salt: bytes = b"", info: bytes = b"") -> bytes:
    """HKDF-SHA256 (extract-then-expand), returning ``length`` bytes."""
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, input_key_material, hashlib.sha256).digest()
    okm = bytearray()
    previous = b""
    counter = 1
    while len(okm) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(previous)
        counter += 1
    return bytes(okm[:length])


def aes_gcm_encrypt(key: bytes, plaintext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM encrypt; returns ciphertext with the 16-byte tag appended."""
    return AESGCM(key).encrypt(nonce, plaintext, aad if aad else None)


def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM decrypt (``ciphertext`` includes the trailing tag)."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad if aad else None)


def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """AES-CBC encrypt with PKCS#7 padding (used by the sender-key ratchet)."""
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def aes_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """AES-CBC decrypt and strip PKCS#7 padding."""
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    if not padded:
        return padded
    pad = padded[-1]
    if pad < 1 or pad > 16 or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return padded[:-pad]
