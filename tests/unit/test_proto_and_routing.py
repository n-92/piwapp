"""Protobuf round-trips, registration payload shape, routing keys, QR string."""

from __future__ import annotations

import base64

from piwapp import proto
from piwapp.auth.creds import AuthenticationCreds
from piwapp.auth.qr import build_qr_payload
from piwapp.binary import BinaryNode
from piwapp.config import ConnectionConfig
from piwapp.socket.connection import Connection
from piwapp.socket.router import routing_keys


def test_handshake_message_roundtrip():
    hm = proto.HandshakeMessage(
        clientHello=proto.HandshakeMessage.ClientHello(ephemeral=b"\x02" * 32)
    )
    back = proto.HandshakeMessage.FromString(hm.SerializeToString())
    assert bytes(back.clientHello.ephemeral) == b"\x02" * 32


def test_registration_payload_structure():
    creds = AuthenticationCreds.initial()
    conn = Connection(creds, ConnectionConfig())
    cp = conn._registration_payload()
    rt = proto.ClientPayload.FromString(cp.SerializeToString())

    assert rt.passive is False
    assert rt.userAgent.platform == proto.ClientPayload.UserAgent.Platform.WEB
    dpd = rt.devicePairingData
    assert len(dpd.eRegid) == 4
    assert dpd.eKeytype == bytes([5])
    assert bytes(dpd.eIdent) == creds.signed_identity_key.public
    assert len(dpd.eSkeyId) == 3
    assert bytes(dpd.eSkeyVal) == creds.signed_pre_key.key_pair.public
    assert bytes(dpd.eSkeySig) == creds.signed_pre_key.signature
    assert len(dpd.buildHash) == 16  # md5 digest
    # deviceProps must itself be a valid DeviceProps message
    dp = proto.DeviceProps.FromString(dpd.deviceProps)
    assert dp.os == "Mac OS"


def test_routing_keys_for_iq_pair_device():
    node = BinaryNode(
        tag="iq",
        attrs={"id": "1", "type": "set", "from": "s.whatsapp.net"},
        content=[BinaryNode(tag="pair-device")],
    )
    keys = routing_keys(node)
    assert "iq,,pair-device" in keys
    assert "iq,type:set,pair-device" in keys
    assert "iq,type:set" in keys
    assert "iq" in keys


def test_qr_payload_assembly():
    payload = build_qr_payload("REF123", b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)
    ref, noise_b64, ident_b64, adv_b64 = payload.split(",")
    assert ref == "REF123"
    assert base64.b64decode(noise_b64) == b"\x01" * 32
    assert base64.b64decode(ident_b64) == b"\x02" * 32
    assert base64.b64decode(adv_b64) == b"\x03" * 32
