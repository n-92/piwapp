"""End-to-end Noise XX handshake test.

The :class:`NoiseHandler` under test is the *initiator* (client). To exercise it
faithfully we implement an independent *responder* (server) directly on top of
the crypto primitives — deliberately NOT reusing ``NoiseHandler`` code — so the
test cross-checks the real implementation rather than comparing it to itself.
"""

from __future__ import annotations

from piwapp.crypto import key_utils as k
from piwapp.transport.noise import (
    NOISE_MODE,
    DEFAULT_NOISE_HEADER,
    NoiseHandler,
    ServerHello,
    generate_iv,
)


class _ResponderMirror:
    """Minimal, independent XX responder mirroring WhatsApp's server side."""

    def __init__(self, client_ephemeral_pub: bytes, header: bytes):
        self.hash = NOISE_MODE  # 32 bytes -> used directly as the initial hash
        self.salt = self.hash
        self.enc_key = self.hash
        self.dec_key = self.hash
        self.counter = 0
        self.transport_enc = None
        self.transport_dec = None
        self.read_counter = 0
        self.write_counter = 0
        # mirror the initiator's seeding: header then the client ephemeral key
        self._auth(header)
        self._auth(client_ephemeral_pub)

    def _auth(self, data: bytes) -> None:
        self.hash = k.sha256(self.hash + data)

    def _mix(self, data: bytes) -> None:
        okm = k.hkdf(data, 64, salt=self.salt, info=b"")
        self.salt = okm[:32]
        self.enc_key = self.dec_key = okm[32:]
        self.counter = 0

    def _encrypt(self, pt: bytes) -> bytes:
        ct = k.aes_gcm_encrypt(self.enc_key, pt, generate_iv(self.counter), self.hash)
        self.counter += 1
        self._auth(ct)
        return ct

    def _decrypt(self, ct: bytes) -> bytes:
        pt = k.aes_gcm_decrypt(self.dec_key, ct, generate_iv(self.counter), self.hash)
        self.counter += 1
        self._auth(ct)
        return pt

    def build_server_hello(self, client_ephemeral_pub: bytes, cert_payload: bytes):
        self.server_e = k.generate_key_pair()
        self.server_s = k.generate_key_pair()
        self._auth(self.server_e.public)
        self._mix(k.shared_secret(self.server_e.private, client_ephemeral_pub))
        static_enc = self._encrypt(self.server_s.public)
        self._mix(k.shared_secret(self.server_s.private, client_ephemeral_pub))
        payload_enc = self._encrypt(cert_payload)
        return ServerHello(
            ephemeral=self.server_e.public, static=static_enc, payload=payload_enc
        )

    def process_client_finish(self, key_enc: bytes) -> bytes:
        client_static_pub = self._decrypt(key_enc)
        self._mix(k.shared_secret(self.server_e.private, client_static_pub))
        return client_static_pub

    def finish_init(self) -> None:
        okm = k.hkdf(b"", 64, salt=self.salt, info=b"")
        write, read = okm[:32], okm[32:]
        # responder swaps relative to the initiator so the channel lines up
        self.transport_enc = read
        self.transport_dec = write

    def transport_encrypt(self, pt: bytes) -> bytes:
        ct = k.aes_gcm_encrypt(self.transport_enc, pt, generate_iv(self.write_counter))
        self.write_counter += 1
        return ct

    def transport_decrypt(self, ct: bytes) -> bytes:
        pt = k.aes_gcm_decrypt(self.transport_dec, ct, generate_iv(self.read_counter))
        self.read_counter += 1
        return pt


def test_full_handshake_and_transport():
    header = DEFAULT_NOISE_HEADER
    client_ephemeral = k.generate_key_pair()
    client_noise_key = k.generate_key_pair()
    cert_payload = b"certificate-chain-bytes"

    client = NoiseHandler(client_ephemeral, header=header)
    server = _ResponderMirror(client_ephemeral.public, header)

    server_hello = server.build_server_hello(client_ephemeral.public, cert_payload)

    seen_payload = {}

    def verify_cert(payload: bytes) -> bool:
        seen_payload["p"] = payload
        return payload == cert_payload

    key_enc = client.process_handshake(
        server_hello, client_noise_key, verify_cert=verify_cert
    )
    # the client correctly decrypted and verified the server certificate
    assert seen_payload["p"] == cert_payload

    recovered_static = server.process_client_finish(key_enc)
    # the server recovered exactly the client's static (noise) public key
    assert recovered_static == client_noise_key.public

    client.finish_init()
    server.finish_init()

    # bidirectional transport encryption works across the established channel
    for i in range(5):
        msg = f"client->server {i}".encode()
        frame = client.encode_frame(msg)
        if i == 0:
            # the very first frame carries the one-time intro (routing) header
            assert frame.startswith(DEFAULT_NOISE_HEADER)
            frame = frame[len(DEFAULT_NOISE_HEADER):]
        ct = frame[3:]  # strip the 3-byte length prefix
        assert server.transport_decrypt(ct) == msg

    s2c = server.transport_encrypt(b"server->client")
    frames = list(client.decode_frames(len(s2c).to_bytes(3, "big") + s2c))
    assert frames == [b"server->client"]


def test_cert_verification_failure_raises():
    from piwapp.transport.noise import NoiseError

    header = DEFAULT_NOISE_HEADER
    client_ephemeral = k.generate_key_pair()
    client = NoiseHandler(client_ephemeral, header=header)
    server = _ResponderMirror(client_ephemeral.public, header)
    server_hello = server.build_server_hello(client_ephemeral.public, b"real-cert")

    import pytest

    with pytest.raises(NoiseError):
        client.process_handshake(
            server_hello, k.generate_key_pair(), verify_cert=lambda p: False
        )
