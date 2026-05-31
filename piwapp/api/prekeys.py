"""Pre-key upload node building (Baileys-compatible ``encrypt`` IQs).

So that other devices can asynchronously establish Signal sessions with this
device, we publish one-time pre-keys (plus our identity + signed pre-key) to the
server. Mirrors Baileys' ``getNextPreKeysNode`` / ``xmppPreKey`` /
``xmppSignedPreKey``.

Newly generated pre-keys are inserted into the live ``SignalStore`` so inbound
``pkmsg`` sessions can be built immediately. (Cross-restart persistence of
one-time pre-keys is a separate follow-up.)
"""

from __future__ import annotations

from ..binary import BinaryNode
from ..crypto.pre_keys import generate_pre_keys
from ..utils import encode_big_endian

KEY_BUNDLE_TYPE = bytes([5])
S_WHATSAPP_NET = "@s.whatsapp.net"


def build_count_query(message_id: str) -> BinaryNode:
    """IQ that asks the server how many of our pre-keys remain."""
    return BinaryNode(
        tag="iq",
        attrs={"id": message_id, "xmlns": "encrypt", "type": "get", "to": S_WHATSAPP_NET},
        content=[BinaryNode(tag="count")],
    )


def parse_count(result: BinaryNode) -> int:
    """Extract the server pre-key count from a count-query result."""
    count = result.get_child("count")
    if count is None:
        return 0
    return int(count.attrs.get("value", "0") or "0")


def _xmpp_pre_key(public: bytes, key_id: int) -> BinaryNode:
    return BinaryNode(
        tag="key",
        content=[
            BinaryNode(tag="id", content=encode_big_endian(key_id, 3)),
            BinaryNode(tag="value", content=public),
        ],
    )


def _xmpp_signed_pre_key(key_id: int, public: bytes, signature: bytes) -> BinaryNode:
    return BinaryNode(
        tag="skey",
        content=[
            BinaryNode(tag="id", content=encode_big_endian(key_id, 3)),
            BinaryNode(tag="value", content=public),
            BinaryNode(tag="signature", content=signature),
        ],
    )


def build_upload_node(creds, signal_store, count: int, message_id: str) -> BinaryNode:
    """Generate ``count`` pre-keys, register them in the store, and build the IQ.

    Mutates ``creds.next_pre_key_id`` / ``creds.first_unuploaded_pre_key_id``;
    the caller should emit ``creds.update`` afterwards.
    """
    start_id = creds.next_pre_key_id
    pre_keys = generate_pre_keys(start_id, count)
    for pk in pre_keys:
        signal_store.add_pre_key_from_keypair(pk.key_id, pk.key_pair)

    creds.next_pre_key_id = start_id + count
    creds.first_unuploaded_pre_key_id = creds.next_pre_key_id

    spk = creds.signed_pre_key
    return BinaryNode(
        tag="iq",
        attrs={"id": message_id, "xmlns": "encrypt", "type": "set", "to": S_WHATSAPP_NET},
        content=[
            BinaryNode(tag="registration", content=encode_big_endian(creds.registration_id, 4)),
            BinaryNode(tag="type", content=KEY_BUNDLE_TYPE),
            BinaryNode(tag="identity", content=creds.signed_identity_key.public),
            BinaryNode(
                tag="list",
                content=[_xmpp_pre_key(pk.key_pair.public, pk.key_id) for pk in pre_keys],
            ),
            _xmpp_signed_pre_key(spk.key_id, spk.key_pair.public, spk.signature),
        ],
    )
