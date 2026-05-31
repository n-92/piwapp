"""Authentication credentials model and initial-credential generation.

Ports Baileys' ``initAuthCreds`` (``Utils/auth-utils.ts``). ``AuthenticationCreds``
holds the long-lived identity material for a device registration: the Noise
static key, the Signal identity key, the first signed pre-key, the registration
id, and the adv secret used during multi-device pairing.
"""

from __future__ import annotations

import base64

from pydantic import BaseModel, Field

from ..crypto.key_utils import generate_key_pair, random_bytes
from ..crypto.pre_keys import generate_registration_id, make_signed_pre_key
from ..models.signal import Base64Bytes, KeyPairModel, SignedPreKeyModel


class AccountSettings(BaseModel):
    """Per-account behaviour flags synced with the server."""

    unarchive_chats: bool = False


class Me(BaseModel):
    """Identity of the logged-in account, populated after pairing."""

    id: str
    name: str | None = None
    lid: str | None = None


class AuthenticationCreds(BaseModel):
    """Long-lived credentials for a registered device."""

    noise_key: KeyPairModel
    pairing_ephemeral_key_pair: KeyPairModel
    signed_identity_key: KeyPairModel
    signed_pre_key: SignedPreKeyModel
    registration_id: int
    adv_secret_key: Base64Bytes

    processed_history_messages: list[str] = Field(default_factory=list)
    next_pre_key_id: int = 1
    first_unuploaded_pre_key_id: int = 1
    account_sync_counter: int = 0
    account_settings: AccountSettings = Field(default_factory=AccountSettings)

    me: Me | None = None
    account: dict | None = None
    signal_identities: list[dict] = Field(default_factory=list)
    my_lid: str | None = None
    platform: str | None = None
    device_id: str | None = None
    phone_number: str | None = None
    routing_info: Base64Bytes | None = None
    last_prop_hash: str | None = None
    registered: bool = False

    @classmethod
    def initial(cls) -> "AuthenticationCreds":
        """Generate a brand-new, unregistered credential set."""
        identity_key = generate_key_pair()
        return cls(
            noise_key=KeyPairModel.from_key_pair(generate_key_pair()),
            pairing_ephemeral_key_pair=KeyPairModel.from_key_pair(generate_key_pair()),
            signed_identity_key=KeyPairModel.from_key_pair(identity_key),
            signed_pre_key=SignedPreKeyModel.from_signed_pre_key(
                make_signed_pre_key(identity_key, 1)
            ),
            registration_id=generate_registration_id(),
            adv_secret_key=random_bytes(32),
            registered=False,
        )

    def to_json(self) -> str:
        """Serialise to a JSON string (binary fields base64-encoded)."""
        return self.model_dump_json()

    @classmethod
    def from_json(cls, data: str | bytes) -> "AuthenticationCreds":
        """Deserialise from a JSON string produced by :meth:`to_json`."""
        return cls.model_validate_json(data)
