"""Pydantic models for persisted Signal/Noise key material.

These mirror the crypto-layer dataclasses (:class:`piwapp.crypto.key_utils.KeyPair`,
:class:`piwapp.crypto.pre_keys.SignedPreKey`) but serialise cleanly to/from JSON
using base64 for all binary fields, so they can be written to disk or SQLite.
"""

from __future__ import annotations

import base64
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, PlainSerializer

from ..crypto.key_utils import KeyPair
from ..crypto.pre_keys import PreKey, SignedPreKey


def _to_bytes(value: object) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return base64.b64decode(value)
    raise TypeError(f"expected bytes or base64 str, got {type(value)}")


# A bytes field that serialises as a base64 string in JSON mode.
Base64Bytes = Annotated[
    bytes,
    BeforeValidator(_to_bytes),
    PlainSerializer(lambda b: base64.b64encode(b).decode(), return_type=str, when_used="json"),
]


class KeyPairModel(BaseModel):
    """Serialisable Curve25519 key pair."""

    private: Base64Bytes
    public: Base64Bytes

    @classmethod
    def from_key_pair(cls, kp: KeyPair) -> "KeyPairModel":
        return cls(private=kp.private, public=kp.public)

    def to_key_pair(self) -> KeyPair:
        return KeyPair(private=self.private, public=self.public)


class SignedPreKeyModel(BaseModel):
    """Serialisable signed pre-key."""

    key_id: int
    key_pair: KeyPairModel
    signature: Base64Bytes

    @classmethod
    def from_signed_pre_key(cls, spk: SignedPreKey) -> "SignedPreKeyModel":
        return cls(
            key_id=spk.key_id,
            key_pair=KeyPairModel.from_key_pair(spk.key_pair),
            signature=spk.signature,
        )

    def to_signed_pre_key(self) -> SignedPreKey:
        return SignedPreKey(
            key_id=self.key_id,
            key_pair=self.key_pair.to_key_pair(),
            signature=self.signature,
        )


class PreKeyModel(BaseModel):
    """Serialisable one-time pre-key."""

    key_id: int
    key_pair: KeyPairModel

    @classmethod
    def from_pre_key(cls, pk: PreKey) -> "PreKeyModel":
        return cls(key_id=pk.key_id, key_pair=KeyPairModel.from_key_pair(pk.key_pair))

    def to_pre_key(self) -> PreKey:
        return PreKey(key_id=self.key_id, key_pair=self.key_pair.to_key_pair())
