"""End-to-end message encoding/decoding.

Builds and parses the WhatsApp ``<message>`` / ``<enc>`` node structure, wrapping
the Signal-encrypted ``Message`` protobuf. Plaintext is the protobuf padded with
``writeRandomPadMax16`` (1–16 trailing bytes, each equal to the pad length), as
Baileys does, before Signal encryption.

1:1 messages use the Double Ratchet (``pkmsg`` for the initial pre-key message,
``msg`` afterwards); group messages use Sender Keys (``skmsg``).
"""

from __future__ import annotations

import os

from .. import proto
from ..binary import BinaryNode
from ..crypto.double_ratchet import SessionCipher
from ..crypto.sender_key import GroupCipher
from ..models.message import MessageContent, extract_text, to_message_proto

# Signal ciphertext type -> WhatsApp <enc> type attribute
_ENC_TYPE = {1: "msg", 3: "pkmsg"}
_ENC_TYPE_REV = {"msg": 1, "pkmsg": 3}


def generate_message_id() -> str:
    """Generate a WhatsApp message id (``3EB0`` + 18 random bytes, upper hex)."""
    return "3EB0" + os.urandom(18).hex().upper()


def pad_message(data: bytes) -> bytes:
    """Append 1–16 pad bytes (each equal to the pad length); Baileys-compatible."""
    pad_len = (os.urandom(1)[0] & 0x0F) + 1
    return data + bytes([pad_len]) * pad_len


def unpad_message(data: bytes) -> bytes:
    """Strip ``writeRandomPadMax16`` padding."""
    if not data:
        raise ValueError("cannot unpad empty data")
    pad = data[-1]
    if pad > len(data):
        raise ValueError(f"invalid padding: {pad} > {len(data)}")
    return data[: len(data) - pad]


def encode_wa_message(message: "proto.Message") -> bytes:
    """Serialise + pad a ``Message`` protobuf, ready for Signal encryption."""
    return pad_message(message.SerializeToString())


# ----------------------------------------------------------------------
# 1:1 (Double Ratchet)
# ----------------------------------------------------------------------
def encrypt_dm_node(
    store, to_jid: str, content: "MessageContent | str", *, message_id: str | None = None
) -> tuple[str, BinaryNode]:
    """Encrypt a DM and build its ``<message>`` node. Returns (message_id, node)."""
    message_id = message_id or generate_message_id()
    plaintext = encode_wa_message(to_message_proto(content))
    cipher = SessionCipher(store, to_jid)
    enc_type, body = cipher.encrypt(plaintext)
    enc = BinaryNode(tag="enc", attrs={"v": "2", "type": _ENC_TYPE[enc_type]}, content=body)
    node = BinaryNode(
        tag="message",
        attrs={"id": message_id, "type": "text", "to": to_jid},
        content=[enc],
    )
    return message_id, node


def decrypt_dm_node(store, node: BinaryNode) -> "tuple[str, proto.Message]":
    """Decrypt an incoming DM ``<message>`` node. Returns (sender_jid, Message)."""
    sender = node.attrs.get("participant") or node.attrs.get("from")
    if not sender:
        raise ValueError("message node missing sender")
    enc = node.get_child("enc")
    if enc is None or enc.content_bytes is None:
        raise ValueError("message node missing <enc>")
    cipher = SessionCipher(store, sender)
    enc_type = enc.attrs.get("type", "msg")
    if _ENC_TYPE_REV.get(enc_type) == 3:
        plaintext = cipher.decrypt_prekey_message(enc.content_bytes)
    else:
        plaintext = cipher.decrypt_message(enc.content_bytes)
    return sender, proto.Message.FromString(unpad_message(plaintext))


# ----------------------------------------------------------------------
# Group (Sender Keys)
# ----------------------------------------------------------------------
def encrypt_group_node(
    store, group_jid: str, own_name: str, content: "MessageContent | str",
    *, message_id: str | None = None,
) -> tuple[str, BinaryNode]:
    """Encrypt a group message with the sender key. Returns (message_id, node).

    ``own_name`` is the sender-key name (``group::ownJid``). The caller is
    responsible for having distributed the Sender Key to participants.
    """
    message_id = message_id or generate_message_id()
    plaintext = encode_wa_message(to_message_proto(content))
    body = GroupCipher(store, own_name).encrypt(plaintext)
    enc = BinaryNode(tag="enc", attrs={"v": "2", "type": "skmsg"}, content=body)
    node = BinaryNode(
        tag="message",
        attrs={"id": message_id, "type": "text", "to": group_jid},
        content=[enc],
    )
    return message_id, node


def decrypt_group_node(store, sender_name: str, node: BinaryNode) -> "proto.Message":
    """Decrypt an incoming group ``<message>`` node via the sender's key."""
    enc = node.get_child("enc")
    if enc is None or enc.content_bytes is None:
        raise ValueError("group message node missing <enc>")
    plaintext = GroupCipher(store, sender_name).decrypt(enc.content_bytes)
    return proto.Message.FromString(unpad_message(plaintext))


def text_of(message: "proto.Message") -> str | None:
    """Convenience: extract displayable text from a decoded message."""
    return extract_text(message)
