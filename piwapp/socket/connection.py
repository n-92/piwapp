"""Connection orchestration: Noise handshake, registration, QR, pairing.

This drives the full Phase 1 login path against the WhatsApp gateway:

1. Open the WebSocket and run the Noise XX handshake (ClientHello → ServerHello
   → verify cert → ClientFinish), sending a registration ``ClientPayload``.
2. Switch to transport encryption and read decoded binary nodes.
3. Handle the ``pair-device`` IQ by emitting QR payloads for the phone to scan.
4. On ``pair-success`` verify the device identity, reply, and surface the new
   account (``Me``) via the ``connection.update`` event.

The orchestration mirrors Baileys' ``validateConnection`` and the
``CB:iq,,pair-device`` / ``CB:iq,,pair-success`` handlers.
"""

from __future__ import annotations

import asyncio
import base64
import enum
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

_DEBUG = os.environ.get("PIWAPP_DEBUG") == "1"

from .. import proto
from ..auth.creds import AuthenticationCreds, Me
from ..auth.qr import build_qr_payload
from ..binary import BinaryNode, decode_binary_node, encode_binary_node
from ..config import ConnectionConfig
from ..crypto.key_utils import (
    generate_key_pair,
    hmac_sha256,
    md5,
    xeddsa_sign,
    xeddsa_verify,
)
from ..transport.noise import DEFAULT_NOISE_HEADER, NoiseHandler, ServerHello
from ..transport.websocket import WATransport
from ..utils import encode_big_endian, generate_message_tag

S_WHATSAPP_NET = "@s.whatsapp.net"
WA_CERT_PUBLIC_KEY = bytes.fromhex(
    "142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b"
)
WA_ADV_ACCOUNT_SIG_PREFIX = bytes([6, 0])
WA_ADV_DEVICE_SIG_PREFIX = bytes([6, 1])
KEY_BUNDLE_TYPE = bytes([5])


class ConnectionState(str, enum.Enum):
    CLOSED = "close"
    CONNECTING = "connecting"
    OPEN = "open"


class DisconnectReason(enum.IntEnum):
    """WhatsApp disconnect status codes (subset, from Baileys)."""

    CONNECTION_CLOSED = 428
    CONNECTION_LOST = 408
    CONNECTION_REPLACED = 440
    LOGGED_OUT = 401
    BAD_SESSION = 500
    RESTART_REQUIRED = 515
    MULTIDEVICE_MISMATCH = 411
    FORBIDDEN = 403
    UNAVAILABLE_SERVICE = 503


# stream-error child tag -> status code (Baileys CODE_MAP subset)
_STREAM_ERROR_CODE_MAP = {
    "conflict": DisconnectReason.CONNECTION_REPLACED,
}


@dataclass
class _Emitter:
    """Tiny async-aware event emitter for connection lifecycle events."""

    _handlers: dict[str, list[Callable]] = field(default_factory=dict)

    def on(self, event: str, handler: Callable) -> None:
        self._handlers.setdefault(event, []).append(handler)

    async def emit(self, event: str, payload) -> None:
        # Isolate handler failures: a buggy/raising listener (e.g. a print
        # encoding error) must never kill the read loop / drop the connection.
        for handler in list(self._handlers.get(event, ())):
            try:
                result = handler(payload)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                if _DEBUG:
                    print(f"[debug] event handler for {event!r} raised: {exc!r}")


def _strip_key_prefix(key: bytes) -> bytes:
    """Strip the Signal ``0x05`` type byte if present (-> 32-byte Montgomery key)."""
    return key[1:] if len(key) == 33 and key[0] == 5 else key


class Connection:
    """Manages a single WhatsApp Web connection up to (and through) pairing."""

    def __init__(
        self,
        creds: AuthenticationCreds,
        config: ConnectionConfig | None = None,
        *,
        transport: WATransport | None = None,
        events=None,
        signal_store=None,
    ) -> None:
        self.creds = creds
        self.config = config or ConnectionConfig()
        self.ev = _Emitter()
        self.state = ConnectionState.CLOSED

        # WA-event emitter + Signal store (shared across reconnects by the Client)
        self.events = events
        self.signal_store = signal_store
        self._receiver = None
        if events is not None and signal_store is not None:
            from ..api.messages_recv import MessageReceiver

            self._receiver = MessageReceiver(signal_store, events)

        routing = bytes(creds.routing_info) if creds.routing_info else None
        self._ephemeral = generate_key_pair()
        self._noise = NoiseHandler(
            self._ephemeral, header=DEFAULT_NOISE_HEADER, routing_info=routing
        )
        self._transport = transport or WATransport(
            self.config.ws_url,
            self.config.origin,
            open_timeout=self.config.connect_timeout_ms / 1000,
        )
        self._read_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None
        self._bg_tasks: set[asyncio.Task] = set()
        self._write_lock = asyncio.Lock()
        self._pending: dict[str, asyncio.Future] = {}
        self._qr_refs: list[str] = []
        self._closed = asyncio.Event()
        self.close_reason: int | None = None
        self.is_new_login = False

    # -- connection lifecycle -------------------------------------------
    async def connect(self) -> None:
        """Open the socket and complete the Noise handshake."""
        self.state = ConnectionState.CONNECTING
        await self.ev.emit("connection.update", {"connection": self.state.value})
        await self._transport.connect()
        await self._handshake()
        self._read_task = asyncio.create_task(self._read_loop(), name="piwapp-reader")

    async def _handshake(self) -> None:
        hello = proto.HandshakeMessage(
            clientHello=proto.HandshakeMessage.ClientHello(
                ephemeral=self._ephemeral.public
            )
        )
        await self._transport.send(self._noise.encode_frame(hello.SerializeToString()))

        server_hello_bytes = await self._recv_handshake_frame()
        hm = proto.HandshakeMessage.FromString(server_hello_bytes)
        sh = ServerHello(
            ephemeral=bytes(hm.serverHello.ephemeral),
            static=bytes(hm.serverHello.static),
            payload=bytes(hm.serverHello.payload),
        )

        verifier = self._verify_certificate if self.config.verify_cert else None
        key_enc = self._noise.process_handshake(
            sh, self.creds.noise_key.to_key_pair(), verify_cert=verifier
        )

        payload = self._build_client_payload()
        payload_enc = self._noise.encrypt(payload.SerializeToString())
        finish = proto.HandshakeMessage(
            clientFinish=proto.HandshakeMessage.ClientFinish(
                static=key_enc, payload=payload_enc
            )
        )
        await self._transport.send(self._noise.encode_frame(finish.SerializeToString()))
        self._noise.finish_init()

    async def _recv_handshake_frame(self) -> bytes:
        # During the handshake, decode_frames yields raw (un-decrypted) bytes.
        while True:
            data = await self._transport.recv()
            for frame in self._noise.decode_frames(data):
                return frame

    def _verify_certificate(self, payload: bytes) -> bool:
        try:
            chain = proto.CertChain.FromString(payload)
            details = proto.CertChain.NoiseCertificate.Details.FromString(
                chain.intermediate.details
            )
            leaf_ok = xeddsa_verify(
                _strip_key_prefix(bytes(details.key)),
                bytes(chain.leaf.details),
                bytes(chain.leaf.signature),
            )
            inter_ok = xeddsa_verify(
                WA_CERT_PUBLIC_KEY,
                bytes(chain.intermediate.details),
                bytes(chain.intermediate.signature),
            )
            return bool(leaf_ok and inter_ok and details.issuerSerial == 0)
        except Exception:
            return False

    # -- client payload --------------------------------------------------
    def _base_payload(self) -> "proto.ClientPayload":
        cp = proto.ClientPayload()
        cp.connectType = proto.ClientPayload.ConnectType.WIFI_UNKNOWN
        cp.connectReason = proto.ClientPayload.ConnectReason.USER_ACTIVATED
        ua = cp.userAgent
        ua.appVersion.primary = self.config.version[0]
        ua.appVersion.secondary = self.config.version[1]
        ua.appVersion.tertiary = self.config.version[2]
        ua.platform = proto.ClientPayload.UserAgent.Platform.WEB
        ua.releaseChannel = proto.ClientPayload.UserAgent.ReleaseChannel.RELEASE
        ua.osVersion = "0.1"
        ua.device = "Desktop"
        ua.osBuildNumber = "0.1"
        ua.localeLanguageIso6391 = "en"
        ua.mnc = "000"
        ua.mcc = "000"
        ua.localeCountryIso31661Alpha2 = self.config.country_code
        cp.webInfo.webSubPlatform = proto.ClientPayload.WebInfo.WebSubPlatform.WEB_BROWSER
        if self.config.push_name:
            cp.pushName = self.config.push_name
        return cp

    def _build_client_payload(self) -> "proto.ClientPayload":
        if self.creds.me is not None:
            return self._login_payload()
        return self._registration_payload()

    def _registration_payload(self) -> "proto.ClientPayload":
        cp = self._base_payload()
        cp.passive = False
        cp.pull = False

        companion = proto.DeviceProps()
        companion.os = self.config.browser[0]
        companion.platformType = _platform_type(self.config.browser[1])
        companion.requireFullSync = self.config.sync_full_history
        companion.version.primary = 10
        companion.version.secondary = 15
        companion.version.tertiary = 7

        spk = self.creds.signed_pre_key
        dpd = cp.devicePairingData
        dpd.buildHash = md5(self.config.version_string.encode())
        dpd.deviceProps = companion.SerializeToString()
        dpd.eRegid = encode_big_endian(self.creds.registration_id, 4)
        dpd.eKeytype = KEY_BUNDLE_TYPE
        dpd.eIdent = self.creds.signed_identity_key.public
        dpd.eSkeyId = encode_big_endian(spk.key_id, 3)
        dpd.eSkeyVal = spk.key_pair.public
        dpd.eSkeySig = spk.signature
        return cp

    def _login_payload(self) -> "proto.ClientPayload":
        from ..binary import jid_decode

        cp = self._base_payload()
        cp.passive = True
        cp.pull = True
        decoded = jid_decode(self.creds.me.id)
        cp.username = int(decoded.user)
        cp.device = decoded.device or 0
        return cp

    # -- read loop & node handling --------------------------------------
    async def _read_loop(self) -> None:
        try:
            async for data in self._transport.messages():
                for frame in self._noise.decode_frames(data):
                    try:
                        node = decode_binary_node(frame)
                    except Exception as exc:
                        if _DEBUG:
                            print(f"[debug] frame decode FAILED: {exc!r} "
                                  f"len={len(frame)} head={frame[:24].hex()}")
                        continue
                    if _DEBUG:
                        kids = node.children()
                        first = kids[0].tag if kids else ""
                        print(f"[debug] node <{node.tag}> attrs={node.attrs} "
                              f"first_child={first!r}")
                    await self._on_node(node)
            if _DEBUG:
                print("[debug] read loop ended: transport messages() exhausted "
                      "(server closed the socket); "
                      f"ws_close_code={self._transport.close_code} "
                      f"ws_close_reason={self._transport.close_reason!r}")
        except Exception as exc:
            if _DEBUG:
                print(f"[debug] read loop EXCEPTION: {exc!r}")
        finally:
            if self.close_reason is None:
                self.close_reason = int(DisconnectReason.CONNECTION_CLOSED)
            self.state = ConnectionState.CLOSED
            self._closed.set()
            await self.ev.emit(
                "connection.update",
                {"connection": self.state.value, "reason": self.close_reason},
            )

    async def _on_node(self, node: BinaryNode) -> None:
        await self.ev.emit("frame", node)
        # resolve any pending query() awaiting this id
        msg_id = node.attrs.get("id")
        if msg_id and msg_id in self._pending:
            fut = self._pending.pop(msg_id)
            if not fut.done():
                fut.set_result(node)
            return
        children = node.children()
        first = children[0].tag if children else ""
        if node.tag == "iq" and first == "pair-device":
            await self._on_pair_device(node)
        elif node.tag == "iq" and first == "pair-success":
            await self._on_pair_success(node)
        elif node.tag == "iq" and node.attrs.get("type") == "get" and (
            node.attrs.get("xmlns") == "urn:xmpp:ping" or first == "ping"
        ):
            await self._on_server_ping(node)
        elif node.tag == "success":
            await self._on_success(node)
        elif node.tag == "failure":
            await self._on_failure(node)
        elif node.tag == "stream:error":
            await self._on_stream_error(node)
        elif node.tag == "message":
            await self._on_message(node)
        elif node.tag == "notification":
            await self._on_notification(node)
        elif node.tag == "receipt":
            await self._on_receipt(node)
        elif node.tag == "call":
            await self._on_call(node)
        elif node.tag == "ib":
            await self._on_ib(node, first)

    async def fetch_groups(self) -> list[dict]:
        """List groups this account participates in ({id, subject, ...})."""
        from ..api import groups as gmod
        result = await self.query(gmod.build_list_groups_query(generate_message_tag()))
        return gmod.parse_groups_list(result)

    async def send_group_text(self, group_jid: str, text: str) -> str:
        """Send a text message to a group (sender-key + SKDM fan-out). Requires login."""
        from ..api import messages_send as ms
        from ..api.messages import generate_message_id

        if self.creds.me is None:
            raise RuntimeError("not logged in")
        msg_id = generate_message_id()
        await self._relay_group(group_jid, ms.text_message(text), msg_id)
        return msg_id

    async def _relay_group(
        self, group_jid: str, message: "proto.Message", msg_id: str,
        *, stanza_attrs: dict | None = None, enc_attrs: dict | None = None,
    ) -> None:
        """Sender-key encrypt a group ``Message`` + fan out the SKDM, then send."""
        from ..api import groups as gmod
        from ..api import messages_send as ms
        from ..api.messages import encode_wa_message
        from ..binary import jid_decode, jids as _j
        from ..crypto.sender_key import GroupCipher, GroupSessionBuilder, sender_key_name

        # 1) group metadata -> participants + addressing mode
        meta = gmod.parse_group_metadata(
            await self.query(gmod.build_group_metadata_query(group_jid, generate_message_tag())))
        addressing = meta["addressing_mode"]
        if addressing == "lid" and self.creds.me.lid:
            sender_identity = _j.jid_normalized_user(self.creds.me.lid)
        else:
            sender_identity = _j.jid_normalized_user(self.creds.me.id)
        name = sender_key_name(group_jid, sender_identity)

        # 2) our sender key + SKDM, and the group-encrypted (skmsg) body
        skdm = GroupSessionBuilder(self.signal_store).create(name)
        skmsg = GroupCipher(self.signal_store, name).encrypt(encode_wa_message(message))

        # 3) enumerate participant devices; exclude our own device, hosted, dev 99
        devices = ms.parse_usync_devices(
            await self.query(ms.build_usync_query(meta["participants"], generate_message_tag())))
        me_id = self.creds.me.id
        me_lid = self.creds.me.lid
        targets = []
        for d in devices:
            if d in (me_id, me_lid):
                continue
            dec = jid_decode(d)
            if dec is None or dec.device == 99 or dec.server in ("hosted", "hosted.lid"):
                continue
            targets.append(d)

        # 4) ensure 1:1 sessions for SKDM delivery
        need = [d for d in targets if not self.signal_store.contains_session(d)]
        if need:
            bundles = ms.parse_prekey_bundles(
                await self.query(ms.build_prekey_fetch(need, generate_message_tag())))
            ms.inject_sessions(self.signal_store, bundles)
            targets = [d for d in targets if self.signal_store.contains_session(d)]

        # 5) distribute the SKDM to each participant device via their 1:1 session
        skdm_msg = ms.skdm_message(group_jid, skdm)
        part_nodes, di = ms.create_participant_nodes(self.signal_store, skdm_msg, targets, enc_attrs)

        stanza = ms.build_group_stanza(
            msg_id, group_jid, skmsg, part_nodes,
            include_device_identity=di, creds=self.creds, addressing_mode=addressing,
            extra_attrs=stanza_attrs, enc_attrs=enc_attrs,
        )
        await self._send_node(stanza)

    async def _on_server_ping(self, node: BinaryNode) -> None:
        """Reply to a server-initiated ``<iq xmlns=urn:xmpp:ping>`` so the
        connection (incl. the QR pairing window) isn't dropped for not answering."""
        try:
            await self._send_node(BinaryNode(
                tag="iq",
                attrs={"to": S_WHATSAPP_NET, "id": node.attrs.get("id", ""),
                       "type": "result"},
            ))
        except Exception:
            pass

    # -- outbound 1:1 send ----------------------------------------------
    async def send_text(self, to_jid: str, text: str) -> str:
        """Send a 1:1 text message; returns the message id. Requires login."""
        from ..api import messages_send as ms
        from ..api.messages import generate_message_id

        if self.creds.me is None:
            raise RuntimeError("not logged in")
        msg_id = generate_message_id()
        await self._relay_dm(to_jid, ms.text_message(text), msg_id)
        return msg_id

    async def _relay_dm(
        self, to_jid: str, message: "proto.Message", msg_id: str,
        *, stanza_attrs: dict | None = None, enc_attrs: dict | None = None,
    ) -> None:
        """Encrypt a 1:1 ``Message`` to all recipient + own devices and send it.

        Shared by text and media send. Media passes ``stanza_attrs={'type':'media'}``
        and ``enc_attrs={'mediatype':...}`` (the latter goes on every ``<enc>``).
        """
        from ..api import messages_send as ms
        from ..binary import jid_decode, jid_encode, jids as _j

        me_id = self.creds.me.id
        me_dec = jid_decode(me_id)
        recipient = _j.jid_normalized_user(to_jid)

        # 1) enumerate devices for us + the recipient
        me_user_jid = jid_encode(me_dec.user, "s.whatsapp.net")
        usync = await self.query(ms.build_usync_query([me_user_jid, recipient], generate_message_tag()))
        devices = ms.parse_usync_devices(usync)
        if _DEBUG:
            print(f"[debug] send: usync devices={devices}")

        # exclude our own current device; split own-other vs recipient devices
        targets = [d for d in devices if d != me_id]
        me_devs = [d for d in targets if (jid_decode(d) or me_dec).user == me_dec.user]
        other_devs = [d for d in targets if (jid_decode(d) or me_dec).user != me_dec.user]

        # 2) ensure sessions exist (fetch pre-key bundles for any missing)
        need = [d for d in targets if not self.signal_store.contains_session(d)]
        if need:
            bundles = ms.parse_prekey_bundles(
                await self.query(ms.build_prekey_fetch(need, generate_message_tag())))
            ms.inject_sessions(self.signal_store, bundles)

        # 3) encrypt: recipient devices get the message; our devices get a DSM
        other_nodes, di1 = ms.create_participant_nodes(self.signal_store, message, other_devs, enc_attrs)
        dsm = ms.dsm_message(recipient, message)
        me_nodes, di2 = ms.create_participant_nodes(self.signal_store, dsm, me_devs, enc_attrs)

        stanza = ms.build_message_stanza(
            msg_id, recipient, other_nodes + me_nodes,
            include_device_identity=di1 or di2, creds=self.creds, extra_attrs=stanza_attrs,
        )
        await self._send_node(stanza)

    async def _query_media_conn(self) -> dict:
        """Fetch upload hosts + auth token for media upload."""
        from ..api import media as md
        return md.parse_media_conn(await self.query(md.build_media_conn_query(generate_message_tag())))

    async def send_media(
        self, to_jid: str, data: bytes, *, mimetype: str, media_type: str | None = None,
        caption: str | None = None, file_name: str | None = None,
        width: int | None = None, height: int | None = None,
        seconds: int | None = None, ptt: bool | None = None,
    ) -> str:
        """Encrypt, upload, and send a media message (1:1 or group). Requires login."""
        from ..api import media as md
        from ..api.messages import generate_message_id

        if self.creds.me is None:
            raise RuntimeError("not logged in")
        mtype = media_type or md.guess_media_type(mimetype)
        enc = md.encrypt_media(data, mtype)
        conn = await self._query_media_conn()
        upload = await md.upload_media(enc["enc"], enc["fileEncSha256"], mtype, conn)
        message = md.build_media_message(
            mtype, upload=upload, enc=enc, mimetype=mimetype, caption=caption,
            file_name=file_name, width=width, height=height, seconds=seconds, ptt=ptt,
        )
        # Baileys: stanza type="media"; every <enc> carries mediatype=<specific>.
        mediatype = {"audio": "ptt" if ptt else "audio"}.get(mtype, mtype)
        stanza_attrs = {"type": "media"}
        enc_attrs = {"mediatype": mediatype}
        msg_id = generate_message_id()
        if to_jid.endswith("@g.us"):
            await self._relay_group(to_jid, message, msg_id,
                                    stanza_attrs=stanza_attrs, enc_attrs=enc_attrs)
        else:
            await self._relay_dm(to_jid, message, msg_id,
                                 stanza_attrs=stanza_attrs, enc_attrs=enc_attrs)
        return msg_id

    def _build_ack(self, node: BinaryNode, error: int | None = None) -> BinaryNode:
        """Build an ``<ack>`` for a received node (port of Baileys buildAckStanza)."""
        attrs = {
            "id": node.attrs.get("id", ""),
            "to": node.attrs.get("from", ""),
            "class": node.tag,
        }
        if error:
            attrs["error"] = str(error)
        if node.attrs.get("participant"):
            attrs["participant"] = node.attrs["participant"]
        if node.attrs.get("recipient"):
            attrs["recipient"] = node.attrs["recipient"]
        if node.attrs.get("type"):
            attrs["type"] = node.attrs["type"]
        if node.tag == "message" and self.creds.me is not None:
            attrs["from"] = self.creds.me.id
        return BinaryNode(tag="ack", attrs=attrs)

    async def _send_ack(self, node: BinaryNode, error: int | None = None) -> None:
        try:
            await self._send_node(self._build_ack(node, error))
        except Exception:
            pass

    async def _on_notification(self, node: BinaryNode) -> None:
        await self._send_ack(node)
        if self.events is not None:
            from ..events import WAEventType
            await self.events.emit(WAEventType.MESSAGES_UPDATE,
                                   {"notification": node.attrs.get("type"), "from": node.attrs.get("from")})

    async def _on_receipt(self, node: BinaryNode) -> None:
        await self._send_ack(node)
        if self.events is not None:
            from ..events import WAEventType
            await self.events.emit(WAEventType.MESSAGE_RECEIPT_UPDATE,
                                   {"from": node.attrs.get("from"), "type": node.attrs.get("type"),
                                    "id": node.attrs.get("id")})

    async def _on_call(self, node: BinaryNode) -> None:
        await self._send_ack(node)

    async def _on_ib(self, node: BinaryNode, first: str) -> None:
        if first == "dirty":
            await self._on_dirty(node)
            return
        if node.get_child("offline_preview") is not None:
            # request the offline batch so the server flushes queued notifications
            await self._send_node(BinaryNode(
                tag="ib", content=[BinaryNode(tag="offline_batch", attrs={"count": "100"})]))
            return
        offline = node.get_child("offline")
        if offline is not None:
            count = offline.attrs.get("count", "0")
            if _DEBUG:
                print(f"[debug] offline notifications done: count={count}")
            await self.ev.emit("connection.update", {"received_pending_notifications": True})

    async def _on_dirty(self, node: BinaryNode) -> None:
        """Acknowledge an ``<ib><dirty>`` sync notification with a clean IQ."""
        dirty = node.get_child("dirty")
        if dirty is None:
            return
        dtype = dirty.attrs.get("type", "")
        attrs = {"type": dtype}
        if dirty.attrs.get("timestamp"):
            attrs["timestamp"] = dirty.attrs["timestamp"]
        try:
            await self._send_node(BinaryNode(
                tag="iq",
                attrs={"to": S_WHATSAPP_NET, "type": "set",
                       "xmlns": "urn:xmpp:whatsapp:dirty",
                       "id": generate_message_tag()},
                content=[BinaryNode(tag="clean", attrs=attrs)],
            ))
        except Exception:
            pass

    async def _on_message(self, node: BinaryNode) -> None:
        if _DEBUG:
            enc = node.get_child("enc")
            print(f"[debug] _on_message from={node.attrs.get('from')} "
                  f"enc_type={enc.attrs.get('type') if enc else None} "
                  f"receiver={'yes' if self._receiver else 'NONE'}")
        if self._receiver is not None:
            try:
                await self._receiver.handle(node)
            except Exception as exc:
                if _DEBUG:
                    print(f"[debug] receiver.handle error: {exc!r}")
        # acknowledge so WhatsApp doesn't resend
        await self._send_ack(node)

    async def _on_success(self, node: BinaryNode) -> None:
        """Login complete: go online and run the post-login sequence."""
        self.creds.registered = True
        if node.attrs.get("lid") and self.creds.me is not None:
            self.creds.me.lid = node.attrs.get("lid")
        self.state = ConnectionState.OPEN
        self._start_keepalive()
        # go online immediately, then run post-login init in the background
        # (the read loop must keep delivering the IQ responses our query()
        # awaits — awaiting them inline here would deadlock)
        await self.ev.emit("creds.update", self.creds)
        await self.ev.emit(
            "connection.update",
            {"connection": "open", "is_new_login": self.is_new_login,
             "me": self.creds.me.model_dump() if self.creds.me else None},
        )
        self._spawn(self._post_login())

    async def _post_login(self) -> None:
        """Replicate Baileys' post-<success> sequence; the offline-queue flush
        follows. Order matters: prekeys -> passive 'active' -> digest -> init
        queries. We do NOT proactively request app-state sync here (Baileys
        triggers that later, from the history-sync notification)."""
        async def q(node: BinaryNode, timeout: float = 30.0):
            try:
                return await self.query(node, timeout)
            except Exception as exc:
                if _DEBUG:
                    print(f"[debug] post-login query <{node.attrs.get('xmlns')}> failed: {exc!r}")
                return None

        if self.signal_store is not None:
            await self._upload_prekeys_if_required()
        # passive 'active' — after prekeys, like Baileys; likely the offline trigger
        await q(BinaryNode(tag="iq",
                           attrs={"to": S_WHATSAPP_NET, "xmlns": "passive", "type": "set"},
                           content=[BinaryNode(tag="active")]))
        # digest key bundle
        await q(BinaryNode(tag="iq",
                           attrs={"to": S_WHATSAPP_NET, "xmlns": "encrypt", "type": "get"},
                           content=[BinaryNode(tag="digest")]))
        # init queries
        await q(BinaryNode(tag="iq", attrs={"to": S_WHATSAPP_NET, "xmlns": "abt", "type": "get"},
                           content=[BinaryNode(tag="props", attrs={"protocol": "1"})]))
        await q(BinaryNode(tag="iq", attrs={"to": S_WHATSAPP_NET, "xmlns": "blocklist", "type": "get"}))
        await q(BinaryNode(tag="iq", attrs={"to": S_WHATSAPP_NET, "xmlns": "privacy", "type": "get"},
                           content=[BinaryNode(tag="privacy")]))

    async def _on_failure(self, node: BinaryNode) -> None:
        reason = int(node.attrs.get("reason", "500") or "500")
        await self._fail(reason)

    async def _on_stream_error(self, node: BinaryNode) -> None:
        children = node.children()
        reason_tag = children[0].tag if children else "unknown"
        code = node.attrs.get("code")
        status = int(code) if code else int(
            _STREAM_ERROR_CODE_MAP.get(reason_tag, DisconnectReason.BAD_SESSION)
        )
        await self._fail(status)

    async def _fail(self, status: int) -> None:
        self.close_reason = status
        await self.close()

    async def _send_node(self, node: BinaryNode) -> None:
        # serialize encode+send so concurrent senders can't desync the transport
        # write counter / IV (which would make the server drop the connection)
        async with self._write_lock:
            framed = self._noise.encode_frame(encode_binary_node(node))
            await self._transport.send(framed)

    async def query(self, node: BinaryNode, timeout: float = 30.0) -> BinaryNode:
        """Send an IQ-style node and await the response with the matching id."""
        msg_id = node.attrs.get("id")
        if not msg_id:
            msg_id = generate_message_tag()
            node.attrs["id"] = msg_id
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[msg_id] = fut
        await self._send_node(node)
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(msg_id, None)

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)

    async def _upload_prekeys_if_required(self) -> None:
        """Ask the server how many pre-keys remain; upload more if low/missing."""
        from ..api import prekeys

        try:
            result = await self.query(prekeys.build_count_query(generate_message_tag()))
            server_count = prekeys.parse_count(result)
            # Re-upload if the server is low OR we hold no local pre-key privates
            # (e.g. a restart without key persistence orphaned the server batch).
            local_empty = self.signal_store.pre_key_count() == 0
            low_server = server_count <= (30 if server_count == 0 else 5)
            if not (low_server or local_empty):
                return
            upload_count = 30 if (server_count == 0 or local_empty) else 20
            node = prekeys.build_upload_node(
                self.creds, self.signal_store, upload_count, generate_message_tag()
            )
            await self.query(node)
            await self.ev.emit("creds.update", self.creds)
            await self.ev.emit("prekeys.uploaded", {"count": upload_count})
        except Exception as exc:  # non-fatal; connection continues
            await self.ev.emit("prekeys.error", {"error": str(exc)})

    async def _on_pair_device(self, stanza: BinaryNode) -> None:
        # ack the IQ
        await self._send_node(
            BinaryNode(
                tag="iq",
                attrs={
                    "to": S_WHATSAPP_NET,
                    "type": "result",
                    "id": stanza.attrs.get("id", ""),
                },
            )
        )
        pair_device = stanza.get_child("pair-device")
        refs = pair_device.get_children("ref") if pair_device else []
        self._qr_refs = [
            r.content_bytes.decode() for r in refs if r.content_bytes is not None
        ]
        await self._emit_next_qr()

    async def _emit_next_qr(self) -> None:
        if not self._qr_refs:
            return
        ref = self._qr_refs.pop(0)
        qr = build_qr_payload(
            ref,
            self.creds.noise_key.public,
            self.creds.signed_identity_key.public,
            self.creds.adv_secret_key,
        )
        await self.ev.emit("connection.update", {"qr": qr})

    async def _on_pair_success(self, stanza: BinaryNode) -> None:
        # The QR was scanned. Verify identity, reply, persist creds. WhatsApp
        # then closes the stream with code 515 (restart required); the client
        # reconnects and logs in with creds.me set. We do NOT emit "open" here.
        me, reply = self._configure_pairing(stanza)
        self.creds.me = me
        self.is_new_login = True
        await self._send_node(reply)
        await self.ev.emit("creds.update", self.creds)
        await self.ev.emit("pairing.success", {"me": me.model_dump()})

    def _configure_pairing(self, stanza: BinaryNode) -> tuple[Me, BinaryNode]:
        """Verify the device identity and build the pairing reply (Baileys parity)."""
        msg_id = stanza.attrs.get("id", "")
        pair_success = stanza.get_child("pair-success")
        device_identity_node = pair_success.get_child("device-identity")
        device_node = pair_success.get_child("device")
        biz_node = pair_success.get_child("biz")
        platform_node = pair_success.get_child("platform")
        if device_identity_node is None or device_node is None:
            raise ValueError("missing device-identity or device in pair-success")

        hmac_msg = proto.ADVSignedDeviceIdentityHMAC.FromString(
            device_identity_node.content_bytes or b""
        )
        adv_sign = hmac_sha256(self.creds.adv_secret_key, bytes(hmac_msg.details))
        if adv_sign != bytes(hmac_msg.hmac):
            raise ValueError("invalid account signature HMAC")

        account = proto.ADVSignedDeviceIdentity.FromString(bytes(hmac_msg.details))
        device_details = bytes(account.details)
        identity_pub = self.creds.signed_identity_key.public

        account_msg = WA_ADV_ACCOUNT_SIG_PREFIX + device_details + identity_pub
        if not xeddsa_verify(
            _strip_key_prefix(bytes(account.accountSignatureKey)),
            account_msg,
            bytes(account.accountSignature),
        ):
            raise ValueError("failed to verify account signature")

        device_msg = (
            WA_ADV_DEVICE_SIG_PREFIX
            + device_details
            + identity_pub
            + bytes(account.accountSignatureKey)
        )
        account.deviceSignature = xeddsa_sign(
            self.creds.signed_identity_key.private, device_msg
        )

        device_identity = proto.ADVDeviceIdentity.FromString(device_details)
        account_enc = self._encode_signed_identity(account, include_signature_key=False)

        # persist the signed device identity (with our deviceSignature) so we can
        # attach the <device-identity> node on outgoing pkmsg sends
        self.creds.account = {
            "signed_identity": base64.b64encode(
                self._encode_signed_identity(account, include_signature_key=True)
            ).decode()
        }

        reply = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "result", "id": msg_id},
            content=[
                BinaryNode(
                    tag="pair-device-sign",
                    content=[
                        BinaryNode(
                            tag="device-identity",
                            attrs={"key-index": str(device_identity.keyIndex)},
                            content=account_enc,
                        )
                    ],
                )
            ],
        )

        me = Me(
            id=device_node.attrs.get("jid", ""),
            name=biz_node.attrs.get("name") if biz_node else None,
            lid=device_node.attrs.get("lid"),
        )
        if platform_node is not None:
            self.creds.platform = platform_node.attrs.get("name")
        return me, reply

    @staticmethod
    def _encode_signed_identity(account, include_signature_key: bool) -> bytes:
        clone = proto.ADVSignedDeviceIdentity()
        clone.CopyFrom(account)
        if not include_signature_key or not clone.accountSignatureKey:
            clone.ClearField("accountSignatureKey")
        return clone.SerializeToString()

    # -- keepalive -------------------------------------------------------
    def _start_keepalive(self) -> None:
        if self._keepalive_task is None:
            self._keepalive_task = asyncio.create_task(
                self._keepalive_loop(), name="piwapp-keepalive"
            )

    async def _keepalive_loop(self) -> None:
        interval = self.config.keepalive_interval_ms / 1000
        try:
            while self.state == ConnectionState.OPEN:
                await asyncio.sleep(interval)
                if self.state != ConnectionState.OPEN:
                    break
                try:
                    await self._send_node(
                        BinaryNode(
                            tag="iq",
                            attrs={
                                "id": generate_message_tag(),
                                "to": S_WHATSAPP_NET,
                                "type": "get",
                                "xmlns": "w:p",
                            },
                            content=[BinaryNode(tag="ping")],
                        )
                    )
                except Exception:
                    self.close_reason = int(DisconnectReason.CONNECTION_LOST)
                    await self.close()
                    break
        except asyncio.CancelledError:
            pass

    # -- shutdown --------------------------------------------------------
    async def close(self) -> None:
        if self.close_reason is None:
            self.close_reason = int(DisconnectReason.CONNECTION_CLOSED)
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            self._keepalive_task = None
        for task in list(self._bg_tasks):
            task.cancel()
        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()
        await self._transport.close()
        if self._read_task is not None:
            self._read_task.cancel()
        self.state = ConnectionState.CLOSED
        self._closed.set()

    async def wait_closed(self) -> None:
        await self._closed.wait()

    @property
    def qr_b64_adv(self) -> str:
        return base64.b64encode(self.creds.adv_secret_key).decode()


def _platform_type(browser: str) -> int:
    name = browser.upper()
    enum_cls = proto.DeviceProps.PlatformType
    return getattr(enum_cls, name, enum_cls.CHROME)
