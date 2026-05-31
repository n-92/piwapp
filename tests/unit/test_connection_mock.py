"""End-to-end connection tests against an in-process mock WhatsApp server.

A real localhost WebSocket server plays the Noise XX *responder* and the WA
gateway across the full login lifecycle:

1. Connection #1: handshake → ``pair-device`` (QR) → ``pair-success`` → the
   server closes with ``<stream:error code="515">`` (restart required).
2. Connection #2: handshake (now a login) → ``<success>`` → online.

This exercises the whole client path — transport, Noise, framing, WABinary,
routing, QR, pairing verification, and the reconnect/login supervisor — without
the real service or a phone. The mock is built directly on the crypto
primitives so it cross-checks the implementation rather than mirroring it.
"""

from __future__ import annotations

import asyncio

import pytest
import websockets

from piwapp import proto
from piwapp.auth.creds import AuthenticationCreds
from piwapp.binary import BinaryNode, decode_binary_node, encode_binary_node
from piwapp.client import Client
from piwapp.config import ConnectionConfig
from piwapp.crypto import key_utils as kc
from piwapp.socket.connection import WA_ADV_ACCOUNT_SIG_PREFIX
from piwapp.transport.noise import NOISE_MODE, generate_iv

pytestmark = pytest.mark.asyncio

_HEADER = bytes([87, 65, 6, 3])


class _NoiseResponder:
    """Per-connection Noise XX responder + transport framing."""

    def __init__(self) -> None:
        self.hash = NOISE_MODE
        self.salt = self.enc = self.dec = self.hash
        self.counter = 0
        self.t_enc = self.t_dec = None
        self.r_ctr = self.w_ctr = 0

    def _auth(self, data: bytes) -> None:
        self.hash = kc.sha256(self.hash + data)

    def _mix(self, data: bytes) -> None:
        okm = kc.hkdf(data, 64, salt=self.salt, info=b"")
        self.salt = okm[:32]
        self.enc = self.dec = okm[32:]
        self.counter = 0

    def _e(self, pt: bytes) -> bytes:
        ct = kc.aes_gcm_encrypt(self.enc, pt, generate_iv(self.counter), self.hash)
        self.counter += 1
        self._auth(ct)
        return ct

    def _d(self, ct: bytes) -> bytes:
        pt = kc.aes_gcm_decrypt(self.dec, ct, generate_iv(self.counter), self.hash)
        self.counter += 1
        self._auth(ct)
        return pt

    def _finish(self) -> None:
        okm = kc.hkdf(b"", 64, salt=self.salt, info=b"")
        self.t_enc, self.t_dec = okm[32:], okm[:32]  # swapped vs initiator

    @staticmethod
    def _frame(payload: bytes) -> bytes:
        return len(payload).to_bytes(3, "big") + payload

    def send_node(self, node: BinaryNode) -> bytes:
        ct = kc.aes_gcm_encrypt(self.t_enc, encode_binary_node(node), generate_iv(self.w_ctr))
        self.w_ctr += 1
        return self._frame(ct)

    def recv_node(self, frame_payload: bytes) -> BinaryNode:
        pt = kc.aes_gcm_decrypt(self.t_dec, frame_payload, generate_iv(self.r_ctr))
        self.r_ctr += 1
        return decode_binary_node(pt)

    async def handshake(self, ws) -> None:
        first = await ws.recv()
        assert first[:4] == _HEADER
        size = int.from_bytes(first[4:7], "big")
        client_hello = proto.HandshakeMessage.FromString(first[7 : 7 + size])
        client_e = bytes(client_hello.clientHello.ephemeral)

        self._auth(_HEADER)
        self._auth(client_e)
        server_e = kc.generate_key_pair()
        server_s = kc.generate_key_pair()
        self._auth(server_e.public)
        self._mix(kc.shared_secret(server_e.private, client_e))
        static_enc = self._e(server_s.public)
        self._mix(kc.shared_secret(server_s.private, client_e))
        payload_enc = self._e(b"mock-cert")
        hello = proto.HandshakeMessage(
            serverHello=proto.HandshakeMessage.ServerHello(
                ephemeral=server_e.public, static=static_enc, payload=payload_enc
            )
        )
        await ws.send(self._frame(hello.SerializeToString()))

        cf_raw = await ws.recv()
        cf_size = int.from_bytes(cf_raw[:3], "big")
        client_finish = proto.HandshakeMessage.FromString(cf_raw[3 : 3 + cf_size])
        client_static = self._d(bytes(client_finish.clientFinish.static))
        self._mix(kc.shared_secret(server_e.private, client_static))
        self._finish()


class _MockWAServer:
    """Full mock gateway across the two-phase login lifecycle."""

    def __init__(self, client_identity_pub: bytes, client_adv_secret: bytes):
        self.client_identity_pub = client_identity_pub
        self.client_adv_secret = client_adv_secret
        self.jid = "15551234567:3@s.whatsapp.net"
        self.conn_count = 0
        self.prekey_count_queried = False
        self.prekey_uploaded = None

    async def handle(self, ws) -> None:
        self.conn_count += 1
        phase = self.conn_count
        resp = _NoiseResponder()
        await resp.handshake(ws)
        if phase == 1:
            await self._pairing_phase(ws, resp)
        else:
            await self._login_phase(ws, resp)

    async def _pairing_phase(self, ws, resp: _NoiseResponder) -> None:
        pair_device = BinaryNode(
            tag="iq",
            attrs={"id": "qr-1", "type": "set", "from": "@s.whatsapp.net"},
            content=[
                BinaryNode(
                    tag="pair-device",
                    content=[BinaryNode(tag="ref", content=b"REF-ABCDEF")],
                )
            ],
        )
        await ws.send(resp.send_node(pair_device))
        ack = resp.recv_node((await ws.recv())[3:])
        assert ack.tag == "iq" and ack.attrs.get("type") == "result"

        await ws.send(resp.send_node(self._pair_success()))
        reply = resp.recv_node((await ws.recv())[3:])
        assert reply.get_child("pair-device-sign") is not None

        # WhatsApp restarts the stream after pairing
        await ws.send(resp.send_node(BinaryNode(tag="stream:error", attrs={"code": "515"})))
        await asyncio.sleep(0.2)  # let the client process before we drop the socket

    async def _login_phase(self, ws, resp: _NoiseResponder) -> None:
        # client sends a login ClientFinish; we just welcome it
        await ws.send(
            resp.send_node(
                BinaryNode(tag="success", attrs={"lid": "15551234567:3@lid"})
            )
        )
        # respond to the client's post-login IQs (pre-key count + upload)
        try:
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                node = resp.recv_node(raw[3:])
                if node.tag != "iq":
                    continue
                mid = node.attrs.get("id", "")
                xmlns = node.attrs.get("xmlns")
                if xmlns == "encrypt" and node.attrs.get("type") == "get":
                    self.prekey_count_queried = True
                    await ws.send(resp.send_node(BinaryNode(
                        tag="iq", attrs={"id": mid, "type": "result"},
                        content=[BinaryNode(tag="count", attrs={"value": "0"})])))
                elif xmlns == "encrypt" and node.attrs.get("type") == "set":
                    self.prekey_uploaded = node  # capture the upload IQ
                    await ws.send(resp.send_node(BinaryNode(
                        tag="iq", attrs={"id": mid, "type": "result"})))
                    break
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.2)

    def _pair_success(self) -> BinaryNode:
        account_key = kc.generate_key_pair()
        device_details = proto.ADVDeviceIdentity(rawId=1, keyIndex=1).SerializeToString()
        account_msg = WA_ADV_ACCOUNT_SIG_PREFIX + device_details + self.client_identity_pub
        account = proto.ADVSignedDeviceIdentity(
            details=device_details,
            accountSignatureKey=account_key.public,
            accountSignature=kc.xeddsa_sign(account_key.private, account_msg),
        )
        details_bytes = account.SerializeToString()
        hmac_node = proto.ADVSignedDeviceIdentityHMAC(
            details=details_bytes,
            hmac=kc.hmac_sha256(self.client_adv_secret, details_bytes),
        )
        return BinaryNode(
            tag="iq",
            attrs={"id": "ps-1", "type": "result", "from": "@s.whatsapp.net"},
            content=[
                BinaryNode(
                    tag="pair-success",
                    content=[
                        BinaryNode(tag="device-identity", content=hmac_node.SerializeToString()),
                        BinaryNode(tag="device", attrs={"jid": self.jid}),
                        BinaryNode(tag="platform", attrs={"name": "android"}),
                    ],
                )
            ],
        )


async def test_full_login_with_reconnect_against_mock_server():
    creds = AuthenticationCreds.initial()
    server = _MockWAServer(creds.signed_identity_key.public, creds.adv_secret_key)

    async with websockets.serve(server.handle, "localhost", 0) as ws_server:
        port = ws_server.sockets[0].getsockname()[1]
        config = ConnectionConfig(ws_url=f"ws://localhost:{port}", verify_cert=False)

        saved: list = []
        client = Client(creds, config, on_creds_update=lambda c: saved.append(c.registered))

        updates: list[dict] = []
        online = asyncio.Event()

        async def on_update(u: dict) -> None:
            updates.append(u)
            if u.get("connection") == "open":
                online.set()

        client.on("connection.update", on_update)

        runner = asyncio.create_task(client.start())
        await asyncio.wait_for(online.wait(), timeout=15)
        # wait for the background pre-key upload to reach the server
        for _ in range(50):
            if server.prekey_uploaded is not None:
                break
            await asyncio.sleep(0.05)
        await client.stop()
        runner.cancel()

    # a QR was shown during the (first) registration connection
    qrs = [u for u in updates if "qr" in u]
    assert qrs and qrs[0]["qr"].startswith("REF-ABCDEF,")

    # we went online via the second (login) connection, flagged as a new login
    opens = [u for u in updates if u.get("connection") == "open"]
    assert opens
    assert opens[0]["is_new_login"] is True
    assert opens[0]["me"]["id"] == "15551234567:3@s.whatsapp.net"

    # pairing persisted creds (registered flag) and login required two connections
    assert server.conn_count == 2
    assert creds.registered is True
    assert any(saved)

    # after login the client queried the server pre-key count and uploaded keys
    assert server.prekey_count_queried is True
    assert server.prekey_uploaded is not None
    uploaded_keys = server.prekey_uploaded.get_child("list").get_children("key")
    assert len(uploaded_keys) == 30  # INITIAL upload when server reports 0
