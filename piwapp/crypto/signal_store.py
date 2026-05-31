"""In-memory Signal protocol store.

Provides the storage interface the double-ratchet and group ciphers expect:
our identity / registration id, sessions, pre-keys, signed pre-keys, and sender
keys. Persistent stores (SQLite) implement the same surface in later phases.

Identity, registration id, and the first signed pre-key are seeded from
:class:`piwapp.auth.creds.AuthenticationCreds`.
"""

from __future__ import annotations

import base64
from collections.abc import Callable

from . import signal_curve as curve
from .double_ratchet import SessionRecord
from .key_utils import KeyPair


class SignalStore:
    """Mutable in-memory implementation of the Signal storage interface."""

    def __init__(self, identity: curve.SignalKeyPair, registration_id: int) -> None:
        self._identity = identity
        self._registration_id = registration_id
        self._sessions: dict[str, SessionRecord] = {}
        self._pre_keys: dict[int, curve.SignalKeyPair] = {}
        self._signed_pre_keys: dict[int, curve.SignalKeyPair] = {}
        self._sender_keys: dict[str, object] = {}
        # optional callback invoked after any mutation, for persistence
        self.on_change: "Callable[[], None] | None" = None

    def _changed(self) -> None:
        if self.on_change is not None:
            self.on_change()

    # -- identity --------------------------------------------------------
    @classmethod
    def from_creds(cls, creds) -> "SignalStore":
        identity = curve.key_pair_from_private(creds.signed_identity_key.private)
        store = cls(identity, creds.registration_id)
        spk = creds.signed_pre_key
        store.store_signed_pre_key(
            spk.key_id, curve.key_pair_from_private(spk.key_pair.private)
        )
        return store

    def get_our_identity(self) -> curve.SignalKeyPair:
        return self._identity

    def get_our_registration_id(self) -> int:
        return self._registration_id

    def is_trusted_identity(self, address: str, key: bytes) -> bool:
        # Baileys trusts on first use; piwapp mirrors that default here.
        return True

    # -- sessions --------------------------------------------------------
    def load_session(self, address: str) -> SessionRecord | None:
        return self._sessions.get(address)

    def store_session(self, address: str, record: SessionRecord) -> None:
        self._sessions[address] = record
        self._changed()

    def contains_session(self, address: str) -> bool:
        rec = self._sessions.get(address)
        return rec is not None and rec.get_open_session() is not None

    # -- pre-keys --------------------------------------------------------
    def load_pre_key(self, key_id: int) -> curve.SignalKeyPair | None:
        return self._pre_keys.get(key_id)

    def store_pre_key(self, key_id: int, key_pair: curve.SignalKeyPair) -> None:
        self._pre_keys[key_id] = key_pair
        self._changed()

    def remove_pre_key(self, key_id: int) -> None:
        self._pre_keys.pop(key_id, None)
        self._changed()

    def pre_key_count(self) -> int:
        """Number of one-time pre-key *privates* held locally."""
        return len(self._pre_keys)

    def load_signed_pre_key(self, key_id: int) -> curve.SignalKeyPair | None:
        return self._signed_pre_keys.get(key_id)

    def store_signed_pre_key(self, key_id: int, key_pair: curve.SignalKeyPair) -> None:
        self._signed_pre_keys[key_id] = key_pair
        self._changed()

    def add_pre_key_from_keypair(self, key_id: int, kp: KeyPair) -> None:
        self._pre_keys[key_id] = curve.key_pair_from_private(kp.private)
        self._changed()

    # -- sender keys -----------------------------------------------------
    def load_sender_key(self, name: str):
        from .sender_key import SenderKeyRecord

        rec = self._sender_keys.get(name)
        if rec is None:
            rec = SenderKeyRecord()
            self._sender_keys[name] = rec
        return rec

    def store_sender_key(self, name: str, record) -> None:
        self._sender_keys[name] = record
        self._changed()

    # -- persistence -----------------------------------------------------
    def dump(self) -> dict:
        """Serialise all key material to a JSON-friendly dict (identity excluded)."""
        from .sender_key import SenderKeyRecord  # noqa: F401 (type only)

        def kp(p: curve.SignalKeyPair) -> dict:
            return {"pub": base64.b64encode(p.pub).decode(),
                    "priv": base64.b64encode(p.priv).decode()}

        return {
            "registration_id": self._registration_id,
            "pre_keys": {str(k): kp(v) for k, v in self._pre_keys.items()},
            "signed_pre_keys": {str(k): kp(v) for k, v in self._signed_pre_keys.items()},
            "sessions": {addr: rec.to_dict() for addr, rec in self._sessions.items()},
            "sender_keys": {name: rec.to_dict() for name, rec in self._sender_keys.items()},
        }

    def load(self, data: dict) -> None:
        """Populate this store from a :meth:`dump` dict (merges over current)."""
        from .sender_key import SenderKeyRecord

        def kp(d: dict) -> curve.SignalKeyPair:
            return curve.SignalKeyPair(pub=base64.b64decode(d["pub"]),
                                       priv=base64.b64decode(d["priv"]))

        for k, v in data.get("pre_keys", {}).items():
            self._pre_keys[int(k)] = kp(v)
        for k, v in data.get("signed_pre_keys", {}).items():
            self._signed_pre_keys[int(k)] = kp(v)
        for addr, rec in data.get("sessions", {}).items():
            self._sessions[addr] = SessionRecord.from_dict(rec)
        for name, rec in data.get("sender_keys", {}).items():
            self._sender_keys[name] = SenderKeyRecord.from_dict(rec)
