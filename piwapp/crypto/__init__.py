"""piwapp.crypto — key utilities, pre-keys, and (later) Signal ratchets."""

from __future__ import annotations

from .key_utils import (
    KeyPair,
    generate_key_pair,
    hkdf,
    key_pair_from_private,
    random_bytes,
    sha256,
    sha512,
    shared_secret,
    xeddsa_sign,
    xeddsa_verify,
)
from .pre_keys import (
    PreKey,
    SignedPreKey,
    generate_pre_keys,
    generate_registration_id,
    generate_signal_pubkey,
    make_pre_key,
    make_signed_pre_key,
)

__all__ = [
    "KeyPair",
    "generate_key_pair",
    "key_pair_from_private",
    "shared_secret",
    "xeddsa_sign",
    "xeddsa_verify",
    "hkdf",
    "sha256",
    "sha512",
    "random_bytes",
    "PreKey",
    "SignedPreKey",
    "make_pre_key",
    "make_signed_pre_key",
    "generate_pre_keys",
    "generate_signal_pubkey",
    "generate_registration_id",
    # signal protocol
    "SignalStore",
    "SessionBuilder",
    "SessionCipher",
    "SessionRecord",
    "GroupSessionBuilder",
    "GroupCipher",
    "sender_key_name",
]

from .double_ratchet import SessionBuilder, SessionCipher, SessionRecord  # noqa: E402
from .sender_key import (  # noqa: E402
    GroupCipher,
    GroupSessionBuilder,
    sender_key_name,
)
from .signal_store import SignalStore  # noqa: E402
