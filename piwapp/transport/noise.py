"""WhatsApp's Noise_XX_25519_AESGCM_SHA256 handshake and transport encryption.

A faithful port of Baileys' ``Utils/noise-handler.ts``. WhatsApp uses a bespoke
(non-generic) Noise XX flavour:

* The handshake hash is seeded from the protocol-name string and advanced with
  ``MixHash`` (``authenticate``) over every wire element.
* ``MixKey`` (``mix_into_key``) runs HKDF-SHA256(len=64) keyed by the running
  ``salt`` to derive the next chaining key and cipher key.
* During the handshake, AES-GCM uses a per-message counter IV and the running
  handshake hash as AAD; after ``finish_init`` the connection switches to a
  :class:`TransportState` with independent read/write counters.

The protobuf-dependent pieces (parsing ``HandshakeMessage`` / ``CertChain`` and
verifying the server certificate chain) are injected via callbacks so this
module has no hard dependency on the compiled WAProto stubs. The certificate
verifier should use :func:`piwapp.crypto.key_utils.xeddsa_verify`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from ..crypto.key_utils import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    hkdf,
    sha256,
    shared_secret,
)

IV_LENGTH = 12
NOISE_MODE = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
# b"WA" + [protocol major, DICT_VERSION]. Matches Baileys NOISE_WA_HEADER.
DICT_VERSION = 3
DEFAULT_NOISE_HEADER = bytes([87, 65, 6, DICT_VERSION])


def generate_iv(counter: int) -> bytes:
    """12-byte IV with ``counter`` as a big-endian uint32 in the last 4 bytes."""
    iv = bytearray(IV_LENGTH)
    iv[8] = (counter >> 24) & 0xFF
    iv[9] = (counter >> 16) & 0xFF
    iv[10] = (counter >> 8) & 0xFF
    iv[11] = counter & 0xFF
    return bytes(iv)


class TransportState:
    """Post-handshake AES-GCM cipher with independent read/write counters."""

    __slots__ = ("_enc_key", "_dec_key", "_read_counter", "_write_counter")

    def __init__(self, enc_key: bytes, dec_key: bytes) -> None:
        self._enc_key = enc_key
        self._dec_key = dec_key
        self._read_counter = 0
        self._write_counter = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = generate_iv(self._write_counter)
        self._write_counter += 1
        return aes_gcm_encrypt(self._enc_key, plaintext, iv)

    def decrypt(self, ciphertext: bytes) -> bytes:
        iv = generate_iv(self._read_counter)
        self._read_counter += 1
        return aes_gcm_decrypt(self._dec_key, ciphertext, iv)


@dataclass(slots=True)
class ServerHello:
    """Fields extracted from the server's ``HandshakeMessage.serverHello``."""

    ephemeral: bytes
    static: bytes
    payload: bytes


# A verifier receives the decrypted cert payload and returns True if trusted.
CertVerifier = Callable[[bytes], bool]


class NoiseHandler:
    """Drives the WA Noise XX handshake and subsequent transport framing."""

    def __init__(
        self,
        key_pair,  # ephemeral KeyPair (piwapp.crypto.key_utils.KeyPair)
        *,
        header: bytes = DEFAULT_NOISE_HEADER,
        routing_info: bytes | None = None,
    ) -> None:
        self._private = key_pair.private
        self._public = key_pair.public
        self._header = header

        data = NOISE_MODE
        self._hash = data if len(data) == 32 else sha256(data)
        self._salt = self._hash
        self._enc_key = self._hash
        self._dec_key = self._hash
        self._counter = 0
        self._sent_intro = False
        self._transport: TransportState | None = None
        self._in = bytearray()

        if routing_info:
            intro = bytearray(7 + len(routing_info) + len(header))
            intro[0:2] = b"ED"
            intro[2] = 0
            intro[3] = 1
            intro[4] = (len(routing_info) >> 16) & 0xFF
            intro[5] = (len(routing_info) >> 8) & 0xFF
            intro[6] = len(routing_info) & 0xFF
            intro[7 : 7 + len(routing_info)] = routing_info
            intro[7 + len(routing_info) :] = header
            self._intro_header = bytes(intro)
        else:
            self._intro_header = bytes(header)

        # Seed the handshake hash with the header and our ephemeral public key.
        self.authenticate(header)
        self.authenticate(self._public)

    # -- Noise state transitions ----------------------------------------
    def authenticate(self, data: bytes) -> None:
        """MixHash: fold ``data`` into the handshake hash (handshake phase only)."""
        if self._transport is None:
            self._hash = sha256(self._hash + data)

    def mix_into_key(self, data: bytes) -> None:
        """MixKey: derive the next chaining key + cipher key from ``data``."""
        write, read = self._local_hkdf(data)
        self._salt = write
        self._enc_key = read
        self._dec_key = read
        self._counter = 0

    def _local_hkdf(self, data: bytes) -> tuple[bytes, bytes]:
        okm = hkdf(data, 64, salt=self._salt, info=b"")
        return okm[:32], okm[32:]

    def encrypt(self, plaintext: bytes) -> bytes:
        if self._transport is not None:
            return self._transport.encrypt(plaintext)
        result = aes_gcm_encrypt(self._enc_key, plaintext, generate_iv(self._counter), self._hash)
        self._counter += 1
        self.authenticate(result)
        return result

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self._transport is not None:
            return self._transport.decrypt(ciphertext)
        result = aes_gcm_decrypt(self._dec_key, ciphertext, generate_iv(self._counter), self._hash)
        self._counter += 1
        self.authenticate(ciphertext)
        return result

    def finish_init(self) -> None:
        """Transition from handshake to transport encryption."""
        write, read = self._local_hkdf(b"")
        self._transport = TransportState(write, read)

    @property
    def in_transport(self) -> bool:
        return self._transport is not None

    # -- handshake processing -------------------------------------------
    def process_handshake(
        self,
        server_hello: ServerHello,
        noise_key,  # persistent static KeyPair
        *,
        verify_cert: CertVerifier | None = None,
    ) -> bytes:
        """Process the server hello and return our encrypted static key.

        Steps (XX, from the initiator's perspective): ``e, ee, s(decrypt),
        es, [verify cert], send our s (encrypt), se``. ``verify_cert`` is
        called with the decrypted certificate payload; if it returns False a
        :class:`NoiseError` is raised.
        """
        self.authenticate(server_hello.ephemeral)
        self.mix_into_key(shared_secret(self._private, server_hello.ephemeral))

        dec_static = self.decrypt(server_hello.static)
        self.mix_into_key(shared_secret(self._private, dec_static))

        cert_payload = self.decrypt(server_hello.payload)
        if verify_cert is not None and not verify_cert(cert_payload):
            raise NoiseError("noise certificate verification failed")

        key_enc = self.encrypt(noise_key.public)
        self.mix_into_key(shared_secret(noise_key.private, server_hello.ephemeral))
        return key_enc

    # -- framing ---------------------------------------------------------
    def encode_frame(self, data: bytes) -> bytes:
        """Encrypt (if in transport) and wrap ``data`` in a WA length frame.

        The one-time intro header is prepended to the very first frame.
        """
        if self._transport is not None:
            data = self._transport.encrypt(data)

        intro = b"" if self._sent_intro else self._intro_header
        self._sent_intro = True
        length = len(data)
        prefix = bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
        return intro + prefix + data

    def decode_frames(self, new_data: bytes) -> Iterator[bytes]:
        """Feed inbound bytes; yield decrypted payloads for each complete frame.

        Before :meth:`finish_init`, yielded payloads are raw handshake bytes.
        After transport is established, payloads are decrypted node bytes ready
        for :func:`piwapp.binary.decode_binary_node`.
        """
        self._in.extend(new_data)
        while True:
            if len(self._in) < 3:
                return
            size = (self._in[0] << 16) | (self._in[1] << 8) | self._in[2]
            if len(self._in) < size + 3:
                return
            frame = bytes(self._in[3 : size + 3])
            del self._in[: size + 3]
            if self._transport is not None:
                frame = self._transport.decrypt(frame)
            yield frame


class NoiseError(Exception):
    """Raised on handshake / certificate verification failure."""
