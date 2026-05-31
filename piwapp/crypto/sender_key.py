"""Signal Sender Key protocol for group messaging.

A faithful port of Baileys' ``src/Signal/Group`` (sender chain/message keys,
``SenderKeyState``/``Record``, ``GroupSessionBuilder``, ``GroupCipher``). Each
group member derives a sender key once and distributes it (signed) to the
group; thereafter a single symmetric ratchet encrypts each outgoing message,
which every other member decrypts — O(1) crypto per message regardless of group
size. This is the foundation of piwapp's group-chat feature set.

The ``SenderKeyName`` is ``"<groupJid>::<senderJid>"``. Message/distribution
wire formats use the ``proto.SenderKeyMessage`` /
``proto.SenderKeyDistributionMessage`` types and the libsignal ``0x33`` version
byte; sender-key messages are XEdDSA-signed.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field

from . import signal_curve as curve
from .key_utils import aes_cbc_decrypt, aes_cbc_encrypt, hkdf, hmac_sha256

CURRENT_VERSION = 3
VERSION_BYTE = ((CURRENT_VERSION << 4) | CURRENT_VERSION) & 0xFF  # 0x33
SIGNATURE_LENGTH = 64
MAX_MESSAGE_KEYS = 2000


class SenderKeyError(Exception):
    """Raised on signature failure, old counters, or missing state."""


def sender_key_name(group_jid: str, sender_jid: str) -> str:
    """Compose the sender-key store name for a (group, sender) pair."""
    return f"{group_jid}::{sender_jid}"


# ----------------------------------------------------------------------
# Chain / message keys
# ----------------------------------------------------------------------
@dataclass(slots=True)
class SenderMessageKey:
    iteration: int
    seed: bytes
    iv: bytes = field(init=False)
    cipher_key: bytes = field(init=False)

    def __post_init__(self) -> None:
        derivative = [
            hkdf(self.seed, 96, salt=b"\x00" * 32, info=b"WhisperGroup")[i * 32 : (i + 1) * 32]
            for i in range(3)
        ]
        self.iv = derivative[0][:16]
        self.cipher_key = derivative[0][16:32] + derivative[1][:16]


@dataclass(slots=True)
class SenderChainKey:
    iteration: int
    seed: bytes

    _MESSAGE_KEY_SEED = b"\x01"
    _CHAIN_KEY_SEED = b"\x02"

    def sender_message_key(self) -> SenderMessageKey:
        return SenderMessageKey(self.iteration, hmac_sha256(self.seed, self._MESSAGE_KEY_SEED))

    def next(self) -> "SenderChainKey":
        return SenderChainKey(self.iteration + 1, hmac_sha256(self.seed, self._CHAIN_KEY_SEED))


# ----------------------------------------------------------------------
# Sender key state / record
# ----------------------------------------------------------------------
@dataclass(slots=True)
class SenderKeyState:
    key_id: int
    chain_iteration: int
    chain_seed: bytes
    signing_public: bytes  # 33-byte
    signing_private: bytes | None  # 32-byte (only for our own state)
    message_keys: list[SenderMessageKey] = field(default_factory=list)

    def get_chain_key(self) -> SenderChainKey:
        return SenderChainKey(self.chain_iteration, self.chain_seed)

    def set_chain_key(self, chain: SenderChainKey) -> None:
        self.chain_iteration = chain.iteration
        self.chain_seed = chain.seed

    def signing_key_public(self) -> bytes:
        return curve.prefix(self.signing_public)

    def has_message_key(self, iteration: int) -> bool:
        return any(k.iteration == iteration for k in self.message_keys)

    def add_message_key(self, key: SenderMessageKey) -> None:
        self.message_keys.append(key)
        if len(self.message_keys) > MAX_MESSAGE_KEYS:
            self.message_keys.pop(0)

    def remove_message_key(self, iteration: int) -> SenderMessageKey | None:
        for i, k in enumerate(self.message_keys):
            if k.iteration == iteration:
                return self.message_keys.pop(i)
        return None


class SenderKeyRecord:
    """Holds sender-key states (newest first); ``getSenderKeyState`` picks by id."""

    def __init__(self) -> None:
        self.states: list[SenderKeyState] = []

    def is_empty(self) -> bool:
        return not self.states

    def get_state(self, key_id: int | None = None) -> SenderKeyState | None:
        if key_id is None:
            return self.states[0] if self.states else None
        for s in self.states:
            if s.key_id == key_id:
                return s
        return None

    def set_state(self, key_id: int, iteration: int, chain_key: bytes,
                  signing_public: bytes, signing_private: bytes | None) -> None:
        self.states = [
            SenderKeyState(key_id, iteration, chain_key, curve.unprefix(signing_public), signing_private)
        ]

    def add_state(self, key_id: int, iteration: int, chain_key: bytes,
                  signing_public: bytes, signing_private: bytes | None = None) -> None:
        self.states.insert(
            0,
            SenderKeyState(key_id, iteration, chain_key, curve.unprefix(signing_public), signing_private),
        )

    # -- serialization (for persistence) --------------------------------
    def to_dict(self) -> dict:
        return {"states": [_state_to_dict(s) for s in self.states]}

    @classmethod
    def from_dict(cls, data: dict) -> "SenderKeyRecord":
        rec = cls()
        rec.states = [_state_from_dict(d) for d in data.get("states", [])]
        return rec


def _state_to_dict(s: SenderKeyState) -> dict:
    return {
        "key_id": s.key_id,
        "chain_iteration": s.chain_iteration,
        "chain_seed": base64.b64encode(s.chain_seed).decode(),
        "signing_public": base64.b64encode(s.signing_public).decode(),
        "signing_private": base64.b64encode(s.signing_private).decode() if s.signing_private else None,
        "message_keys": [{"iteration": k.iteration, "seed": base64.b64encode(k.seed).decode()}
                         for k in s.message_keys],
    }


def _state_from_dict(d: dict) -> SenderKeyState:
    st = SenderKeyState(
        key_id=d["key_id"],
        chain_iteration=d["chain_iteration"],
        chain_seed=base64.b64decode(d["chain_seed"]),
        signing_public=base64.b64decode(d["signing_public"]),
        signing_private=base64.b64decode(d["signing_private"]) if d.get("signing_private") else None,
    )
    st.message_keys = [SenderMessageKey(k["iteration"], base64.b64decode(k["seed"]))
                       for k in d.get("message_keys", [])]
    return st


# ----------------------------------------------------------------------
# Wire messages
# ----------------------------------------------------------------------
def encode_sender_key_message(key_id: int, iteration: int, ciphertext: bytes, signing_private: bytes) -> bytes:
    """Serialise + sign a SenderKeyMessage (``version || proto || signature``)."""
    from .. import proto

    body = proto.SenderKeyMessage(id=key_id, iteration=iteration, ciphertext=ciphertext).SerializeToString()
    signed = bytes([VERSION_BYTE]) + body
    signature = curve.calculate_signature(signing_private, signed)
    return signed + signature


def decode_sender_key_message(serialized: bytes) -> tuple[int, int, bytes, bytes, bytes]:
    """Parse a SenderKeyMessage; returns (key_id, iteration, ciphertext, signed, signature)."""
    from .. import proto

    signed = serialized[: len(serialized) - SIGNATURE_LENGTH]
    signature = serialized[-SIGNATURE_LENGTH:]
    body = signed[1:]
    m = proto.SenderKeyMessage.FromString(body)
    return m.id, m.iteration, bytes(m.ciphertext), signed, signature


def encode_distribution_message(key_id: int, iteration: int, chain_key: bytes, signing_public: bytes) -> bytes:
    """Serialise a SenderKeyDistributionMessage (``version || proto``)."""
    from .. import proto

    body = proto.SenderKeyDistributionMessage(
        id=key_id, iteration=iteration, chainKey=chain_key, signingKey=curve.prefix(signing_public)
    ).SerializeToString()
    return bytes([VERSION_BYTE]) + body


def decode_distribution_message(serialized: bytes) -> tuple[int, int, bytes, bytes]:
    """Parse a SenderKeyDistributionMessage; returns (id, iteration, chainKey, signingKey)."""
    from .. import proto

    m = proto.SenderKeyDistributionMessage.FromString(serialized[1:])
    return m.id, m.iteration, bytes(m.chainKey), bytes(m.signingKey)


# ----------------------------------------------------------------------
# Group session builder + cipher
# ----------------------------------------------------------------------
class GroupSessionBuilder:
    """Creates our sender key and processes others' distribution messages."""

    def __init__(self, store) -> None:
        self.store = store

    def create(self, name: str) -> bytes:
        """Create (if needed) our sender key for ``name`` and return its SKDM bytes."""
        record = self.store.load_sender_key(name)
        if record.is_empty():
            key_id = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
            chain_seed = os.urandom(32)
            signing = curve.generate_key_pair()
            record.set_state(key_id, 0, chain_seed, signing.pub, signing.priv)
            self.store.store_sender_key(name, record)
        state = record.get_state()
        chain = state.get_chain_key()
        skdm = encode_distribution_message(
            state.key_id, chain.iteration, chain.seed, state.signing_key_public()
        )
        return skdm

    def process(self, name: str, distribution_message: bytes) -> None:
        """Process a peer's SKDM, registering their sender key under ``name``."""
        key_id, iteration, chain_key, signing_key = decode_distribution_message(distribution_message)
        record = self.store.load_sender_key(name)
        record.add_state(key_id, iteration, chain_key, signing_key, None)
        self.store.store_sender_key(name, record)


class GroupCipher:
    """Encrypts/decrypts group messages using a stored sender key."""

    def __init__(self, store, name: str) -> None:
        self.store = store
        self.name = name

    def encrypt(self, padded_plaintext: bytes) -> bytes:
        record = self.store.load_sender_key(self.name)
        if record.is_empty():
            raise SenderKeyError("No SenderKeyRecord for encryption")
        state = record.get_state()
        iteration = state.get_chain_key().iteration
        sender_key = self._get_sender_key(state, 0 if iteration == 0 else iteration + 1)
        ciphertext = aes_cbc_encrypt(sender_key.cipher_key, padded_plaintext, sender_key.iv)
        serialized = encode_sender_key_message(
            state.key_id, sender_key.iteration, ciphertext, state.signing_private
        )
        self.store.store_sender_key(self.name, record)
        return serialized

    def decrypt(self, serialized: bytes) -> bytes:
        record = self.store.load_sender_key(self.name)
        if record.is_empty():
            raise SenderKeyError("No SenderKeyRecord for decryption")
        key_id, iteration, ciphertext, signed, signature = decode_sender_key_message(serialized)
        state = record.get_state(key_id)
        if state is None:
            raise SenderKeyError("No session to decrypt message")
        if not curve.verify_signature(state.signing_key_public(), signed, signature):
            raise SenderKeyError("Invalid signature!")
        sender_key = self._get_sender_key(state, iteration)
        plaintext = aes_cbc_decrypt(sender_key.cipher_key, ciphertext, sender_key.iv)
        self.store.store_sender_key(self.name, record)
        return plaintext

    @staticmethod
    def _get_sender_key(state: SenderKeyState, iteration: int) -> SenderMessageKey:
        chain = state.get_chain_key()
        if chain.iteration > iteration:
            mk = state.remove_message_key(iteration)
            if mk is None:
                raise SenderKeyError(f"Received message with old counter: {chain.iteration}, {iteration}")
            return mk
        if iteration - chain.iteration > MAX_MESSAGE_KEYS:
            raise SenderKeyError("Over 2000 messages into the future!")
        while chain.iteration < iteration:
            state.add_message_key(chain.sender_message_key())
            chain = chain.next()
        state.set_chain_key(chain.next())
        return chain.sender_message_key()
