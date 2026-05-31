"""Media: key expansion, encrypt/decrypt roundtrip, and proto extraction."""

from __future__ import annotations

import os

import pytest

from piwapp import proto
from piwapp.api import media
from piwapp.crypto.key_utils import aes_cbc_encrypt, hmac_sha256, sha256
from piwapp.models.message import extract_text


def _encrypt(plaintext: bytes, media_key: bytes, media_type: str) -> bytes:
    """Mirror WhatsApp media encryption: AES-CBC || HMAC(iv||ct)[:10]."""
    iv, cipher_key, mac_key = media.media_keys(media_key, media_type)
    ciphertext = aes_cbc_encrypt(cipher_key, plaintext, iv)
    mac = hmac_sha256(mac_key, iv + ciphertext)[:10]
    return ciphertext + mac


def test_media_keys_lengths():
    iv, ck, mk = media.media_keys(os.urandom(32), "image")
    assert (len(iv), len(ck), len(mk)) == (16, 32, 32)


@pytest.mark.parametrize("mtype", ["image", "video", "audio", "document"])
def test_encrypt_decrypt_roundtrip(mtype):
    key = os.urandom(32)
    plaintext = os.urandom(1234)  # arbitrary, non-block-aligned
    enc = _encrypt(plaintext, key, mtype)
    assert media.decrypt_media(enc, key, mtype) == plaintext


def test_decrypt_rejects_tampered_mac():
    key = os.urandom(32)
    enc = bytearray(_encrypt(b"hello world", key, "image"))
    enc[-1] ^= 0xFF  # corrupt the MAC
    with pytest.raises(ValueError):
        media.decrypt_media(bytes(enc), key, "image")


def _image_message(**kw):
    return proto.Message(imageMessage=proto.Message.ImageMessage(**kw))


def test_extract_media_info():
    mk, fsha, esha = os.urandom(32), sha256(b"plain"), sha256(b"enc")
    msg = _image_message(mediaKey=mk, directPath="/v/t62/abc", url="https://x/y",
                         mimetype="image/jpeg", caption="hi there",
                         fileSha256=fsha, fileEncSha256=esha, fileLength=4242)
    info = media.extract_media_info(msg)
    assert info["type"] == "image" and info["field"] == "imageMessage"
    assert info["mediaKey"] == mk and info["directPath"] == "/v/t62/abc"
    assert info["fileSha256"] == fsha and info["fileEncSha256"] == esha
    assert info["fileLength"] == 4242 and info["caption"] == "hi there"


def test_media_summary_is_json_safe():
    import json
    msg = _image_message(mediaKey=os.urandom(32), mimetype="image/png",
                         fileLength=10, caption="c")
    summary = media.media_summary(msg)
    json.dumps(summary)  # must not raise (no bytes leaked)
    assert summary["type"] == "image" and summary["mimetype"] == "image/png"


def test_extract_media_info_none_for_text():
    assert media.extract_media_info(proto.Message(conversation="hi")) is None


def test_caption_surfaces_as_text():
    msg = _image_message(mediaKey=os.urandom(32), caption="a caption")
    assert extract_text(msg) == "a caption"


def test_unwrap_view_once():
    inner = _image_message(mediaKey=os.urandom(32), caption="hidden")
    wrapped = proto.Message(viewOnceMessage=proto.Message.FutureProofMessage(message=inner))
    assert media.extract_media_info(wrapped)["caption"] == "hidden"


@pytest.mark.asyncio
async def test_download_media_no_media_raises():
    with pytest.raises(ValueError):
        await media.download_media(proto.Message(conversation="text only"))


def test_encrypt_media_roundtrip():
    plaintext = os.urandom(5000)
    enc = media.encrypt_media(plaintext, "document")
    assert enc["fileLength"] == 5000
    assert enc["fileEncSha256"] == sha256(enc["enc"])
    assert enc["fileSha256"] == sha256(plaintext)
    # decrypting what we encrypted yields the original
    assert media.decrypt_media(enc["enc"], enc["mediaKey"], "document") == plaintext


def test_guess_media_type():
    assert media.guess_media_type("image/png") == "image"
    assert media.guess_media_type("video/mp4") == "video"
    assert media.guess_media_type("audio/ogg") == "audio"
    assert media.guess_media_type("application/pdf") == "document"


def test_parse_media_conn():
    from piwapp.binary import BinaryNode
    result = BinaryNode(tag="iq", content=[
        BinaryNode(tag="media_conn", attrs={"auth": "AUTHTOKEN", "ttl": "300"}, content=[
            BinaryNode(tag="host", attrs={"hostname": "mmg.whatsapp.net"}),
            BinaryNode(tag="host", attrs={"hostname": "media-xyz.whatsapp.net"}),
        ]),
    ])
    conn = media.parse_media_conn(result)
    assert conn["auth"] == "AUTHTOKEN" and conn["ttl"] == 300
    assert conn["hosts"] == ["mmg.whatsapp.net", "media-xyz.whatsapp.net"]


def test_build_media_message_image():
    enc = media.encrypt_media(b"img-bytes", "image")
    upload = {"url": "https://mmg/x", "directPath": "/v/t62/x", "handle": None}
    msg = media.build_media_message("image", upload=upload, enc=enc,
                                    mimetype="image/jpeg", caption="hi", width=640, height=480)
    im = msg.imageMessage
    assert im.url == "https://mmg/x" and im.directPath == "/v/t62/x"
    assert im.mediaKey == enc["mediaKey"] and im.fileEncSha256 == enc["fileEncSha256"]
    assert im.caption == "hi" and im.width == 640 and im.height == 480
    assert im.fileLength == enc["fileLength"] and im.mediaKeyTimestamp > 0


def test_build_media_message_document():
    enc = media.encrypt_media(b"doc", "document")
    upload = {"url": "https://mmg/d", "directPath": "/v/d", "handle": None}
    msg = media.build_media_message("document", upload=upload, enc=enc,
                                    mimetype="application/pdf", file_name="report.pdf",
                                    page_count=3)
    dm = msg.documentMessage
    assert dm.fileName == "report.pdf" and dm.mimetype == "application/pdf" and dm.pageCount == 3


@pytest.mark.asyncio
async def test_upload_media_posts_and_parses(monkeypatch):
    enc = media.encrypt_media(b"payload", "image")
    captured = {}

    class _Resp:
        def raise_for_status(self): ...
        async def json(self): return {"url": "https://mmg/up", "direct_path": "/v/up"}
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    class _Sess:
        def __init__(self, *a, **k): ...
        def post(self, url, **kw):
            captured["url"] = url
            captured["params"] = kw.get("params")
            captured["data"] = kw.get("data")
            return _Resp()
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    monkeypatch.setattr(media.aiohttp, "ClientSession", _Sess)
    conn = {"auth": "AUTH", "ttl": 0, "hosts": ["mmg.whatsapp.net"]}
    out = await media.upload_media(enc["enc"], enc["fileEncSha256"], "image", conn)
    assert out == {"url": "https://mmg/up", "directPath": "/v/up", "handle": None}
    token = media._enc_sha_token(enc["fileEncSha256"])
    assert captured["url"] == f"https://mmg.whatsapp.net/mms/image/{token}"
    assert captured["params"] == {"auth": "AUTH", "token": token}
    assert captured["data"] == enc["enc"]


@pytest.mark.asyncio
async def test_download_media_decrypts(monkeypatch):
    """download_media wires the right keys/type into download_encrypted."""
    key = os.urandom(32)
    plaintext = b"the real bytes"
    enc = _encrypt(plaintext, key, "image")

    async def fake_get(url, **kw):  # not used; we stub the session below
        raise AssertionError("network should be stubbed")

    # stub the HTTP fetch at the aiohttp layer
    class _Resp:
        def raise_for_status(self): ...
        async def read(self): return enc
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    class _Sess:
        def __init__(self, *a, **k): ...
        def get(self, *a, **k): return _Resp()
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    monkeypatch.setattr(media.aiohttp, "ClientSession", _Sess)
    msg = _image_message(mediaKey=key, directPath="/v/t62/abc",
                         fileEncSha256=sha256(enc), fileSha256=sha256(plaintext))
    out = await media.download_media(msg)
    assert out == plaintext
