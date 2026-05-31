"""Signal X3DH + Double Ratchet for 1:1 sessions.

A faithful Python port of libsignal-node's ``session_builder.js`` and
``session_cipher.js`` (as used by Baileys). Public keys are handled in 33-byte
``0x05``-prefixed form; KDF info strings, the ``0x33`` version byte, the
identity-key MAC layout, and chain/message-key derivation all match libsignal
so sessions interoperate with WhatsApp.

The classes are synchronous (pure CPU crypto); the async message layer wraps
them. Storage is provided by :class:`piwapp.crypto.signal_store.SignalStore`.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Optional

from . import signal_curve as curve
from .key_utils import aes_cbc_decrypt, aes_cbc_encrypt, hkdf, hmac_sha256

VERSION = 3
VERSION_BYTE = (VERSION << 4) | VERSION  # 0x33

# Chain / base-key type tags (values internal to piwapp; only consistency matters)
SENDING = 1
RECEIVING = 2
BASE_OURS = 1
BASE_THEIRS = 2


class SignalMessageError(Exception):
    """Raised on MAC failure, bad version, or missing keys."""


def _derive(input_key: bytes, salt: bytes, info: bytes, chunks: int) -> list[bytes]:
    """libsignal ``deriveSecrets``: HKDF-SHA256 returning ``chunks`` 32-byte blocks."""
    okm = hkdf(input_key, 32 * chunks, salt=salt, info=info)
    return [okm[i * 32 : (i + 1) * 32] for i in range(chunks)]


@dataclass(slots=True)
class Chain:
    chain_key_counter: int
    chain_key: bytes | None
    chain_type: int
    message_keys: dict[int, bytes] = field(default_factory=dict)


@dataclass(slots=True)
class Ratchet:
    root_key: bytes
    ephemeral_key_pair: curve.SignalKeyPair
    last_remote_ephemeral_key: bytes
    previous_counter: int = 0


@dataclass(slots=True)
class IndexInfo:
    base_key: bytes
    base_key_type: int
    remote_identity_key: bytes
    closed: int = -1


@dataclass(slots=True)
class Session:
    registration_id: int
    current_ratchet: Ratchet
    index_info: IndexInfo
    chains: dict[str, Chain] = field(default_factory=dict)
    pending_pre_key: Optional[dict] = None

    @staticmethod
    def _key(pub: bytes) -> str:
        return base64.b64encode(pub).decode()

    def get_chain(self, pub: bytes) -> Chain | None:
        return self.chains.get(self._key(pub))

    def add_chain(self, pub: bytes, chain: Chain) -> None:
        self.chains[self._key(pub)] = chain

    def delete_chain(self, pub: bytes) -> None:
        self.chains.pop(self._key(pub), None)


class SessionRecord:
    """Holds the open session plus a few archived ones (for out-of-order msgs)."""

    ARCHIVED_LIMIT = 6

    def __init__(self) -> None:
        self.sessions: list[Session] = []

    def is_empty(self) -> bool:
        return not self.sessions

    def get_open_session(self) -> Session | None:
        for s in self.sessions:
            if s.index_info.closed == -1:
                return s
        return None

    def get_session_by_base_key(self, base_key: bytes) -> Session | None:
        for s in self.sessions:
            if s.index_info.base_key == base_key:
                return s
        return None

    def set_session(self, session: Session) -> None:
        self.sessions.insert(0, session)

    def close_session(self, session: Session) -> None:
        if session.index_info.closed == -1:
            session.index_info.closed = 0

    def remove_old_sessions(self) -> None:
        # keep the open session + most recent archived ones
        if len(self.sessions) > self.ARCHIVED_LIMIT + 1:
            self.sessions = self.sessions[: self.ARCHIVED_LIMIT + 1]

    # -- serialization (for persistence) --------------------------------
    def to_dict(self) -> dict:
        return {"sessions": [_session_to_dict(s) for s in self.sessions]}

    @classmethod
    def from_dict(cls, data: dict) -> "SessionRecord":
        rec = cls()
        rec.sessions = [_session_from_dict(d) for d in data.get("sessions", [])]
        return rec


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _session_to_dict(s: Session) -> dict:
    r, ix = s.current_ratchet, s.index_info
    return {
        "registration_id": s.registration_id,
        "ratchet": {
            "root_key": _b64e(r.root_key),
            "ephemeral": {"pub": _b64e(r.ephemeral_key_pair.pub),
                          "priv": _b64e(r.ephemeral_key_pair.priv)},
            "last_remote": _b64e(r.last_remote_ephemeral_key),
            "previous_counter": r.previous_counter,
        },
        "index": {
            "base_key": _b64e(ix.base_key),
            "base_key_type": ix.base_key_type,
            "remote_identity_key": _b64e(ix.remote_identity_key),
            "closed": ix.closed,
        },
        "chains": {
            k: {"counter": c.chain_key_counter,
                "key": _b64e(c.chain_key) if c.chain_key is not None else None,
                "type": c.chain_type,
                "message_keys": {str(i): _b64e(mk) for i, mk in c.message_keys.items()}}
            for k, c in s.chains.items()
        },
        "pending_pre_key": _pending_to_dict(s.pending_pre_key),
    }


def _session_from_dict(d: dict) -> Session:
    r, ix = d["ratchet"], d["index"]
    session = Session(
        registration_id=d["registration_id"],
        current_ratchet=Ratchet(
            root_key=_b64d(r["root_key"]),
            ephemeral_key_pair=curve.SignalKeyPair(pub=_b64d(r["ephemeral"]["pub"]),
                                                   priv=_b64d(r["ephemeral"]["priv"])),
            last_remote_ephemeral_key=_b64d(r["last_remote"]),
            previous_counter=r["previous_counter"],
        ),
        index_info=IndexInfo(
            base_key=_b64d(ix["base_key"]),
            base_key_type=ix["base_key_type"],
            remote_identity_key=_b64d(ix["remote_identity_key"]),
            closed=ix["closed"],
        ),
        pending_pre_key=_pending_from_dict(d.get("pending_pre_key")),
    )
    for k, c in d.get("chains", {}).items():
        session.chains[k] = Chain(
            chain_key_counter=c["counter"],
            chain_key=_b64d(c["key"]) if c["key"] is not None else None,
            chain_type=c["type"],
            message_keys={int(i): _b64d(mk) for i, mk in c.get("message_keys", {}).items()},
        )
    return session


def _pending_to_dict(p: dict | None) -> dict | None:
    if p is None:
        return None
    out = {"signedKeyId": p["signedKeyId"], "baseKey": _b64e(p["baseKey"])}
    if p.get("preKeyId") is not None:
        out["preKeyId"] = p["preKeyId"]
    return out


def _pending_from_dict(p: dict | None) -> dict | None:
    if p is None:
        return None
    out = {"signedKeyId": p["signedKeyId"], "baseKey": _b64d(p["baseKey"])}
    if p.get("preKeyId") is not None:
        out["preKeyId"] = p["preKeyId"]
    return out


# ----------------------------------------------------------------------
# Session builder (X3DH)
# ----------------------------------------------------------------------
class SessionBuilder:
    """Establishes new sessions from a pre-key bundle (out) or a message (in)."""

    def __init__(self, store, address: str) -> None:
        self.store = store
        self.address = address

    def init_outgoing(self, device: dict) -> None:
        """Start an outgoing session from a fetched pre-key ``device`` bundle.

        ``device`` keys: ``identityKey`` (33b), ``registrationId``,
        ``signedPreKey`` {``keyId``, ``publicKey`` 33b, ``signature`` 64b},
        optional ``preKey`` {``keyId``, ``publicKey`` 33b}.
        """
        base_key = curve.generate_key_pair()
        device_pre_key = device.get("preKey", {}).get("publicKey") if device.get("preKey") else None
        session = self._init_session(
            is_initiator=True,
            our_ephemeral=base_key,
            our_signed=None,
            their_identity=device["identityKey"],
            their_ephemeral=device_pre_key,
            their_signed=device["signedPreKey"]["publicKey"],
            registration_id=device.get("registrationId", 0),
        )
        session.pending_pre_key = {
            "signedKeyId": device["signedPreKey"]["keyId"],
            "baseKey": base_key.pub,
        }
        if device.get("preKey"):
            session.pending_pre_key["preKeyId"] = device["preKey"]["keyId"]

        record = self.store.load_session(self.address) or SessionRecord()
        open_session = record.get_open_session()
        if open_session:
            record.close_session(open_session)
        record.set_session(session)
        self.store.store_session(self.address, record)

    def init_incoming(self, record: SessionRecord, message) -> int | None:
        """Process an inbound PreKeySignalMessage, building the responder session."""
        if record.get_session_by_base_key(bytes(message.baseKey)):
            return None  # already replied
        pre_key_pair = None
        if message.preKeyId:
            pre_key_pair = self.store.load_pre_key(message.preKeyId)
            if not pre_key_pair:
                raise SignalMessageError("Invalid PreKey ID")
        signed_pre_key_pair = self.store.load_signed_pre_key(message.signedPreKeyId)
        if not signed_pre_key_pair:
            raise SignalMessageError("Missing SignedPreKey")

        existing = record.get_open_session()
        if existing:
            record.close_session(existing)

        session = self._init_session(
            is_initiator=False,
            our_ephemeral=pre_key_pair,
            our_signed=signed_pre_key_pair,
            their_identity=bytes(message.identityKey),
            their_ephemeral=bytes(message.baseKey),
            their_signed=None,
            registration_id=message.registrationId,
        )
        record.set_session(session)
        return message.preKeyId or None

    def _init_session(
        self,
        *,
        is_initiator: bool,
        our_ephemeral: curve.SignalKeyPair | None,
        our_signed: curve.SignalKeyPair | None,
        their_identity: bytes,
        their_ephemeral: bytes | None,
        their_signed: bytes | None,
        registration_id: int,
    ) -> Session:
        if is_initiator:
            assert our_signed is None
            our_signed = our_ephemeral
        else:
            assert their_signed is None
            their_signed = their_ephemeral

        if not our_ephemeral or not their_ephemeral:
            shared = bytearray(32 * 4)
        else:
            shared = bytearray(32 * 5)
        shared[0:32] = b"\xff" * 32

        our_identity = self.store.get_our_identity()
        a1 = curve.calculate_agreement(their_signed, our_identity.priv)
        a2 = curve.calculate_agreement(their_identity, our_signed.priv)
        a3 = curve.calculate_agreement(their_signed, our_signed.priv)
        if is_initiator:
            shared[32:64] = a1
            shared[64:96] = a2
        else:
            shared[64:96] = a1
            shared[32:64] = a2
        shared[96:128] = a3
        if our_ephemeral and their_ephemeral:
            a4 = curve.calculate_agreement(their_ephemeral, our_ephemeral.priv)
            shared[128:160] = a4

        master = _derive(bytes(shared), b"\x00" * 32, b"WhisperText", 3)

        ratchet = Ratchet(
            root_key=master[0],
            ephemeral_key_pair=curve.generate_key_pair() if is_initiator else our_signed,
            last_remote_ephemeral_key=their_signed,
            previous_counter=0,
        )
        session = Session(
            registration_id=registration_id,
            current_ratchet=ratchet,
            index_info=IndexInfo(
                base_key=our_ephemeral.pub if is_initiator else their_ephemeral,
                base_key_type=BASE_OURS if is_initiator else BASE_THEIRS,
                remote_identity_key=their_identity,
            ),
        )
        if is_initiator:
            self._calculate_sending_ratchet(session, their_signed)
        return session

    @staticmethod
    def _calculate_sending_ratchet(session: Session, remote_key: bytes) -> None:
        ratchet = session.current_ratchet
        shared = curve.calculate_agreement(remote_key, ratchet.ephemeral_key_pair.priv)
        master = _derive(shared, ratchet.root_key, b"WhisperRatchet", 2)
        session.add_chain(
            ratchet.ephemeral_key_pair.pub,
            Chain(chain_key_counter=-1, chain_key=master[1], chain_type=SENDING),
        )
        ratchet.root_key = master[0]


# ----------------------------------------------------------------------
# Session cipher
# ----------------------------------------------------------------------
class SessionCipher:
    """Encrypts/decrypts 1:1 messages for one remote address."""

    def __init__(self, store, address: str) -> None:
        self.store = store
        self.address = address

    # -- encryption ------------------------------------------------------
    def encrypt(self, data: bytes) -> tuple[int, bytes]:
        """Encrypt ``data``; returns ``(type, body)`` with type 3=prekey, 1=msg."""
        our_identity = self.store.get_our_identity()
        record = self.store.load_session(self.address)
        if not record:
            raise SignalMessageError("No sessions")
        session = record.get_open_session()
        if not session:
            raise SignalMessageError("No open session")

        chain = session.get_chain(session.current_ratchet.ephemeral_key_pair.pub)
        if chain is None or chain.chain_type == RECEIVING:
            raise SignalMessageError("Tried to encrypt on a receiving chain")
        self._fill_message_keys(chain, chain.chain_key_counter + 1)
        keys = _derive(chain.message_keys[chain.chain_key_counter], b"\x00" * 32, b"WhisperMessageKeys", 3)
        del chain.message_keys[chain.chain_key_counter]

        from .. import proto

        msg = proto.SignalMessage(
            ratchetKey=session.current_ratchet.ephemeral_key_pair.pub,
            counter=chain.chain_key_counter,
            previousCounter=session.current_ratchet.previous_counter,
            ciphertext=aes_cbc_encrypt(keys[0], data, keys[2][:16]),
        )
        msg_buf = msg.SerializeToString()

        mac_input = (
            our_identity.pub
            + session.index_info.remote_identity_key
            + bytes([VERSION_BYTE])
            + msg_buf
        )
        mac = hmac_sha256(keys[1], mac_input)[:8]
        result = bytes([VERSION_BYTE]) + msg_buf + mac

        record.remove_old_sessions()
        self.store.store_session(self.address, record)

        if session.pending_pre_key:
            pk = proto.PreKeySignalMessage(
                identityKey=our_identity.pub,
                registrationId=self.store.get_our_registration_id(),
                baseKey=session.pending_pre_key["baseKey"],
                signedPreKeyId=session.pending_pre_key["signedKeyId"],
                message=result,
            )
            if session.pending_pre_key.get("preKeyId"):
                pk.preKeyId = session.pending_pre_key["preKeyId"]
            body = bytes([VERSION_BYTE]) + pk.SerializeToString()
            return 3, body
        return 1, result

    # -- decryption ------------------------------------------------------
    def decrypt_prekey_message(self, data: bytes) -> bytes:
        """Decrypt a PreKeySignalMessage, building the responder session."""
        from .. import proto

        if (data[0] >> 4) < VERSION or (data[0] & 0x0F) > VERSION:
            raise SignalMessageError("Incompatible version on PreKeySignalMessage")
        record = self.store.load_session(self.address) or SessionRecord()
        pre_key = proto.PreKeySignalMessage.FromString(data[1:])
        builder = SessionBuilder(self.store, self.address)
        pre_key_id = builder.init_incoming(record, pre_key)
        session = record.get_session_by_base_key(bytes(pre_key.baseKey))
        plaintext = self._do_decrypt(bytes(pre_key.message), session)
        self.store.store_session(self.address, record)
        if pre_key_id:
            self.store.remove_pre_key(pre_key_id)
        return plaintext

    def decrypt_message(self, data: bytes) -> bytes:
        """Decrypt a (non-prekey) SignalMessage against the stored session(s)."""
        record = self.store.load_session(self.address)
        if not record:
            raise SignalMessageError("No session record")
        errors = []
        for session in list(record.sessions):
            try:
                plaintext = self._do_decrypt(data, session)
                self.store.store_session(self.address, record)
                return plaintext
            except Exception as exc:  # try next session
                errors.append(exc)
        raise SignalMessageError(f"No matching session: {errors}")

    def _do_decrypt(self, message_buffer: bytes, session: Session) -> bytes:
        from .. import proto

        if (message_buffer[0] >> 4) < VERSION or (message_buffer[0] & 0x0F) > VERSION:
            raise SignalMessageError("Incompatible version on SignalMessage")
        message_proto = message_buffer[1:-8]
        message = proto.SignalMessage.FromString(message_proto)
        ratchet_key = bytes(message.ratchetKey)

        self._maybe_step_ratchet(session, ratchet_key, message.previousCounter)
        chain = session.get_chain(ratchet_key)
        if chain is None or chain.chain_type == SENDING:
            raise SignalMessageError("Tried to decrypt on a sending chain")
        self._fill_message_keys(chain, message.counter)
        if message.counter not in chain.message_keys:
            raise SignalMessageError("Key used already or never filled")
        message_key = chain.message_keys.pop(message.counter)
        keys = _derive(message_key, b"\x00" * 32, b"WhisperMessageKeys", 3)

        our_identity = self.store.get_our_identity()
        mac_input = (
            session.index_info.remote_identity_key
            + our_identity.pub
            + bytes([VERSION_BYTE])
            + message_proto
        )
        if hmac_sha256(keys[1], mac_input)[:8] != message_buffer[-8:]:
            raise SignalMessageError("Bad MAC")
        plaintext = aes_cbc_decrypt(keys[0], bytes(message.ciphertext), keys[2][:16])
        session.pending_pre_key = None
        return plaintext

    # -- ratchet internals ----------------------------------------------
    @staticmethod
    def _fill_message_keys(chain: Chain, counter: int) -> None:
        if chain.chain_key_counter >= counter:
            return
        if counter - chain.chain_key_counter > 2000:
            raise SignalMessageError("Over 2000 messages into the future!")
        if chain.chain_key is None:
            raise SignalMessageError("Chain closed")
        while chain.chain_key_counter < counter:
            chain.message_keys[chain.chain_key_counter + 1] = hmac_sha256(chain.chain_key, b"\x01")
            chain.chain_key = hmac_sha256(chain.chain_key, b"\x02")
            chain.chain_key_counter += 1

    def _maybe_step_ratchet(self, session: Session, remote_key: bytes, previous_counter: int) -> None:
        if session.get_chain(remote_key):
            return
        ratchet = session.current_ratchet
        previous = session.get_chain(ratchet.last_remote_ephemeral_key)
        if previous is not None:
            self._fill_message_keys(previous, previous_counter)
            previous.chain_key = None  # close

        self._calculate_ratchet(session, remote_key, sending=False)
        prev = session.get_chain(ratchet.ephemeral_key_pair.pub)
        if prev is not None:
            ratchet.previous_counter = prev.chain_key_counter
            session.delete_chain(ratchet.ephemeral_key_pair.pub)
        ratchet.ephemeral_key_pair = curve.generate_key_pair()
        self._calculate_ratchet(session, remote_key, sending=True)
        ratchet.last_remote_ephemeral_key = remote_key

    @staticmethod
    def _calculate_ratchet(session: Session, remote_key: bytes, *, sending: bool) -> None:
        ratchet = session.current_ratchet
        shared = curve.calculate_agreement(remote_key, ratchet.ephemeral_key_pair.priv)
        master = _derive(shared, ratchet.root_key, b"WhisperRatchet", 2)
        chain_pub = ratchet.ephemeral_key_pair.pub if sending else remote_key
        session.add_chain(
            chain_pub,
            Chain(
                chain_key_counter=-1,
                chain_key=master[1],
                chain_type=SENDING if sending else RECEIVING,
            ),
        )
        ratchet.root_key = master[0]
