"""History-sync decode tests: media key/decrypt + inline parse + processing."""

from __future__ import annotations

import os
import zlib

import pytest

from piwapp import proto
from piwapp.api import history as H
from piwapp.api.media import decrypt_media, media_keys
from piwapp.crypto.key_utils import aes_cbc_encrypt, hmac_sha256


def _encrypt_media(plaintext: bytes, media_key: bytes, media_type: str) -> bytes:
    iv, cipher_key, mac_key = media_keys(media_key, media_type)
    ct = aes_cbc_encrypt(cipher_key, plaintext, iv)
    mac = hmac_sha256(mac_key, iv + ct)[:10]
    return ct + mac


def test_media_keys_shapes():
    iv, ck, mk = media_keys(os.urandom(32), "md-msg-hist")
    assert (len(iv), len(ck), len(mk)) == (16, 32, 32)


def test_media_decrypt_roundtrip():
    media_key = os.urandom(32)
    payload = b"the quick brown fox" * 50
    enc = _encrypt_media(payload, media_key, "md-msg-hist")
    assert decrypt_media(enc, media_key, "md-msg-hist") == payload


def test_media_decrypt_bad_mac_rejected():
    media_key = os.urandom(32)
    enc = bytearray(_encrypt_media(b"data", media_key, "md-msg-hist"))
    enc[-1] ^= 0x01
    with pytest.raises(ValueError):
        decrypt_media(bytes(enc), media_key, "md-msg-hist")


def _sample_history() -> "proto.HistorySync":
    T = proto.HistorySync.HistorySyncType
    hs = proto.HistorySync(syncType=T.INITIAL_BOOTSTRAP)
    c = hs.conversations.add()
    c.id = "447000000000@s.whatsapp.net"
    c.name = "Alice"
    c.conversationTimestamp = 1700000001
    wm = c.messages.add().message
    wm.key.remoteJid = "447000000000@s.whatsapp.net"
    wm.key.fromMe = True
    wm.key.id = "ABC123"
    wm.message.conversation = "hey there"
    wm.messageTimestamp = 1700000000
    wm.pushName = "Me"
    return hs


async def test_download_history_inline_payload():
    hs = _sample_history()
    notif = proto.Message().protocolMessage.historySyncNotification
    notif.initialHistBootstrapInlinePayload = zlib.compress(hs.SerializeToString())
    parsed = await H.download_history(notif)
    assert len(parsed.conversations) == 1
    assert parsed.conversations[0].id == "447000000000@s.whatsapp.net"


def test_process_history_extracts_messages_and_chats():
    data = H.process_history(_sample_history())
    assert data["syncType"] == int(proto.HistorySync.HistorySyncType.INITIAL_BOOTSTRAP)
    assert any(c["id"] == "447000000000@s.whatsapp.net" for c in data["chats"])
    assert data["contacts"][0]["name"] == "Alice"
    assert len(data["messages"]) == 1
    m = data["messages"][0]
    assert m["key"]["fromMe"] is True
    assert m["key"]["remoteJid"] == "447000000000@s.whatsapp.net"
    assert m["text"] == "hey there"


def test_process_history_pushnames():
    T = proto.HistorySync.HistorySyncType
    hs = proto.HistorySync(syncType=T.PUSH_NAME)
    pn = hs.pushnames.add()
    pn.id = "447111@s.whatsapp.net"
    pn.pushname = "Bob"
    data = H.process_history(hs)
    assert data["pushnames"][0] == {"id": "447111@s.whatsapp.net", "notify": "Bob"}
