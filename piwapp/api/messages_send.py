"""Outbound 1:1 text send: USync device discovery, pre-key fetch, fan-out.

Ports the essential 1:1 path of Baileys' ``relayMessage``:

1. Enumerate the recipient's *and* our own devices via a USync ``devices`` query.
2. Ensure a Signal session exists for each target device, fetching pre-key
   bundles (``<iq xmlns=encrypt><key>``) and running X3DH where missing.
3. Encrypt the (padded) ``Message`` per device — the recipient gets the real
   message, our own other devices get a ``deviceSentMessage`` (DSM) wrapper.
4. Assemble ``<message><participants><to jid><enc>…`` and send, attaching the
   ``<device-identity>`` when any leg is an initial ``pkmsg``.

Group send (sender-key distribution) is layered on later.
"""

from __future__ import annotations

import base64

from .. import proto
from ..binary import BinaryNode, jid_decode, jid_encode
from ..crypto.double_ratchet import SessionBuilder, SessionCipher
from ..crypto import signal_curve as curve
from ..models.message import MessageContent, to_message_proto
from .messages import encode_wa_message, generate_message_id

S_WHATSAPP_NET = "@s.whatsapp.net"


# ----------------------------------------------------------------------
# USync device discovery
# ----------------------------------------------------------------------
def build_usync_query(jids: list[str], sid: str) -> BinaryNode:
    """Build a USync ``devices`` query for the given user JIDs."""
    users = [BinaryNode(tag="user", attrs={"jid": j}) for j in jids]
    return BinaryNode(
        tag="iq",
        attrs={"to": S_WHATSAPP_NET, "type": "get", "xmlns": "usync", "id": sid},
        content=[
            BinaryNode(
                tag="usync",
                attrs={"sid": sid, "mode": "query", "last": "true",
                       "index": "0", "context": "message"},
                content=[
                    BinaryNode(tag="query", content=[
                        BinaryNode(tag="devices", attrs={"version": "2"})]),
                    BinaryNode(tag="list", content=users),
                ],
            )
        ],
    )


def parse_usync_devices(result: BinaryNode) -> list[str]:
    """Parse a USync result into a flat list of device JIDs (user:device@server)."""
    out: list[str] = []
    usync = result.get_child("usync")
    lst = usync.get_child("list") if usync else None
    if lst is None:
        return out
    for user in lst.get_children("user"):
        jid = user.attrs.get("jid")
        if not jid:
            continue
        decoded = jid_decode(jid)
        if decoded is None:
            continue
        devices_node = user.get_child("devices")
        dlist = devices_node.get_child("device-list") if devices_node else None
        if dlist is None:
            out.append(jid_encode(decoded.user, decoded.server, 0))
            continue
        for dev in dlist.get_children("device"):
            dev_id = int(dev.attrs.get("id", "0") or "0")
            out.append(jid_encode(decoded.user, decoded.server, dev_id))
    return out


# ----------------------------------------------------------------------
# Pre-key fetch / session establishment
# ----------------------------------------------------------------------
def build_prekey_fetch(jids: list[str], sid: str) -> BinaryNode:
    """Build an ``encrypt/get`` IQ requesting pre-key bundles for ``jids``."""
    return BinaryNode(
        tag="iq",
        attrs={"xmlns": "encrypt", "type": "get", "to": S_WHATSAPP_NET, "id": sid},
        content=[BinaryNode(tag="key", content=[
            BinaryNode(tag="user", attrs={"jid": j}) for j in jids])],
    )


def _child_uint(node: BinaryNode, tag: str) -> int | None:
    child = node.get_child(tag)
    if child is None or child.content_bytes is None:
        return None
    return int.from_bytes(child.content_bytes, "big")


def parse_prekey_bundles(result: BinaryNode) -> dict[str, dict]:
    """Parse an ``encrypt/get`` result into ``{jid: bundle}`` for SessionBuilder."""
    bundles: dict[str, dict] = {}
    lst = result.get_child("list")
    if lst is None:
        return bundles
    for user in lst.get_children("user"):
        jid = user.attrs.get("jid")
        identity = user.get_child("identity")
        skey = user.get_child("skey")
        if not jid or identity is None or skey is None or identity.content_bytes is None:
            continue
        bundle = {
            "registrationId": _child_uint(user, "registration") or 0,
            "identityKey": curve.prefix(identity.content_bytes),
            "signedPreKey": {
                "keyId": _child_uint(skey, "id") or 0,
                "publicKey": curve.prefix(skey.get_child("value").content_bytes),
                "signature": skey.get_child("signature").content_bytes,
            },
        }
        key = user.get_child("key")
        if key is not None and key.get_child("value") is not None:
            bundle["preKey"] = {
                "keyId": _child_uint(key, "id") or 0,
                "publicKey": curve.prefix(key.get_child("value").content_bytes),
            }
        bundles[jid] = bundle
    return bundles


def inject_sessions(signal_store, bundles: dict[str, dict]) -> None:
    """Establish outgoing Signal sessions from fetched pre-key bundles."""
    for jid, bundle in bundles.items():
        SessionBuilder(signal_store, jid).init_outgoing(bundle)


# ----------------------------------------------------------------------
# Per-device encryption + stanza
# ----------------------------------------------------------------------
def create_participant_nodes(
    signal_store, message: "proto.Message", jids: list[str], extra_attrs: dict | None = None
) -> tuple[list[BinaryNode], bool]:
    """Encrypt ``message`` for each device JID; return (``<to>`` nodes, has_pkmsg)."""
    plaintext = encode_wa_message(message)
    nodes: list[BinaryNode] = []
    include_device_identity = False
    for jid in jids:
        try:
            enc_type, body = SessionCipher(signal_store, jid).encrypt(plaintext)
        except Exception:
            continue
        type_str = "pkmsg" if enc_type == 3 else "msg"
        if enc_type == 3:
            include_device_identity = True
        enc_attrs = {"v": "2", "type": type_str}
        if extra_attrs:
            enc_attrs.update(extra_attrs)
        nodes.append(BinaryNode(tag="to", attrs={"jid": jid},
                                content=[BinaryNode(tag="enc", attrs=enc_attrs, content=body)]))
    return nodes, include_device_identity


def device_identity_node(creds) -> BinaryNode | None:
    """Build the ``<device-identity>`` node from the persisted signed identity."""
    account = creds.account or {}
    signed = account.get("signed_identity")
    if not signed:
        return None
    return BinaryNode(tag="device-identity", content=base64.b64decode(signed))


def build_message_stanza(
    msg_id: str, to_jid: str, participant_nodes: list[BinaryNode],
    *, include_device_identity: bool, creds, extra_attrs: dict | None = None,
) -> BinaryNode:
    """Assemble the outgoing ``<message>`` stanza for a 1:1 send."""
    content: list[BinaryNode] = [BinaryNode(tag="participants", content=participant_nodes)]
    if include_device_identity:
        di = device_identity_node(creds)
        if di is not None:
            content.append(di)
    attrs = {"id": msg_id, "to": to_jid, "type": "text"}
    if extra_attrs:
        attrs.update(extra_attrs)
    return BinaryNode(tag="message", attrs=attrs, content=content)


def dsm_message(destination_jid: str, message: "proto.Message") -> "proto.Message":
    """Wrap a message as a deviceSentMessage so our own devices render it."""
    return proto.Message(
        deviceSentMessage=proto.Message.DeviceSentMessage(
            destinationJid=destination_jid, message=message
        )
    )


def text_message(text: str) -> "proto.Message":
    return to_message_proto(text)


def skdm_message(group_jid: str, skdm_bytes: bytes) -> "proto.Message":
    """Wrap a Sender-Key Distribution Message for 1:1 delivery to a participant."""
    return proto.Message(
        senderKeyDistributionMessage=proto.Message.SenderKeyDistributionMessage(
            groupId=group_jid, axolotlSenderKeyDistributionMessage=skdm_bytes
        )
    )


def build_group_stanza(
    msg_id: str, group_jid: str, skmsg_ciphertext: bytes,
    skdm_participant_nodes: list[BinaryNode], *,
    include_device_identity: bool, creds, addressing_mode: str = "pn",
    extra_attrs: dict | None = None, enc_attrs: dict | None = None,
) -> BinaryNode:
    """Assemble a group ``<message>``: the skmsg body + per-device SKDM fan-out."""
    skmsg_attrs = {"v": "2", "type": "skmsg"}
    if enc_attrs:
        skmsg_attrs.update(enc_attrs)
    content: list[BinaryNode] = [
        BinaryNode(tag="enc", attrs=skmsg_attrs, content=skmsg_ciphertext),
    ]
    if skdm_participant_nodes:
        content.append(BinaryNode(tag="participants", content=skdm_participant_nodes))
    if include_device_identity:
        di = device_identity_node(creds)
        if di is not None:
            content.append(di)
    attrs = {"id": msg_id, "to": group_jid, "type": "text", "addressing_mode": addressing_mode}
    if extra_attrs:
        attrs.update(extra_attrs)
    return BinaryNode(tag="message", attrs=attrs, content=content)
