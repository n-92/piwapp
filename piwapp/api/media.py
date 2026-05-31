"""WhatsApp encrypted-media download/decrypt.

WA media (and the history-sync blob) is stored encrypted on media servers.
Decryption: expand the 32-byte ``mediaKey`` via HKDF-SHA256 to 112 bytes keyed
by a per-type app-info string, giving iv / cipherKey / macKey; the downloaded
body is ``AES-CBC(ciphertext) || HMAC-SHA256(iv||ciphertext)[:10]``.

Mirrors Baileys' ``getMediaKeys`` / ``downloadEncryptedContent``.
"""

from __future__ import annotations

import base64
import os
import time

import aiohttp

from ..binary import BinaryNode
from ..crypto.key_utils import aes_cbc_decrypt, aes_cbc_encrypt, hkdf, hmac_sha256, sha256

DEFAULT_MEDIA_HOST = "mmg.whatsapp.net"
DEFAULT_ORIGIN = "https://web.whatsapp.com"

# media type -> HKDF app-info infix (subset; from Baileys MEDIA_HKDF_KEY_MAPPING)
_HKDF_INFO = {
    "image": "Image",
    "video": "Video",
    "audio": "Audio",
    "document": "Document",
    "md-msg-hist": "History",
    "md-app-state": "App State",
    "sticker": "Image",
    "thumbnail-image": "Image Thumbnail",
    "thumbnail-video": "Video Thumbnail",
    "thumbnail-document": "Document Thumbnail",
    "thumbnail-link": "Link Thumbnail",
}


def hkdf_info(media_type: str) -> bytes:
    return f"WhatsApp {_HKDF_INFO[media_type]} Keys".encode()


def media_keys(media_key: bytes, media_type: str) -> tuple[bytes, bytes, bytes]:
    """Return (iv, cipher_key, mac_key) expanded from ``media_key``."""
    expanded = hkdf(media_key, 112, info=hkdf_info(media_type))
    return expanded[0:16], expanded[16:48], expanded[48:80]


def decrypt_media(enc: bytes, media_key: bytes, media_type: str, *, verify: bool = True) -> bytes:
    """Decrypt a full encrypted-media body (``ciphertext || mac10``)."""
    iv, cipher_key, mac_key = media_keys(media_key, media_type)
    ciphertext, mac = enc[:-10], enc[-10:]
    if verify:
        expected = hmac_sha256(mac_key, iv + ciphertext)[:10]
        if expected != mac:
            raise ValueError("media MAC verification failed")
    return aes_cbc_decrypt(cipher_key, ciphertext, iv)


def url_from_direct_path(direct_path: str, host: str = DEFAULT_MEDIA_HOST) -> str:
    return f"https://{host}{direct_path}"


async def download_encrypted(
    direct_path: str | None, url: str | None, media_key: bytes, media_type: str,
    *, file_enc_sha256: bytes | None = None,
) -> bytes:
    """Download and decrypt an encrypted-media blob; returns plaintext bytes."""
    download_url = url_from_direct_path(direct_path) if direct_path else url
    if not download_url:
        raise ValueError("no directPath or url for media download")
    async with aiohttp.ClientSession(headers={"Origin": DEFAULT_ORIGIN}) as s:
        async with s.get(download_url, timeout=aiohttp.ClientTimeout(total=120)) as r:
            r.raise_for_status()
            enc = await r.read()
    if file_enc_sha256 and sha256(enc) != file_enc_sha256:
        raise ValueError("downloaded media fileEncSha256 mismatch")
    return decrypt_media(enc, media_key, media_type)


# ----------------------------------------------------------------------
# Extracting media from a decoded Message + high-level download
# ----------------------------------------------------------------------
# WAProto message field (oneof) -> media type key used for HKDF / mms upload.
_MEDIA_FIELDS = {
    "imageMessage": "image",
    "videoMessage": "video",
    "audioMessage": "audio",
    "documentMessage": "document",
    "stickerMessage": "image",  # stickers share the "Image" HKDF info
}

# wrappers that nest the real content under ``.message``
_WRAPPERS = (
    "ephemeralMessage", "viewOnceMessage", "viewOnceMessageV2",
    "viewOnceMessageV2Extension", "documentWithCaptionMessage", "editedMessage",
)


def unwrap_message(message):
    """Descend through ephemeral/view-once/edited wrappers to the real content."""
    for w in _WRAPPERS:
        try:
            if message.HasField(w):
                return unwrap_message(getattr(message, w).message)
        except (ValueError, AttributeError):
            continue
    return message


def extract_media_info(message) -> dict | None:
    """Return media descriptor + keys from a Message, or ``None`` if not media."""
    message = unwrap_message(message)
    for field, mtype in _MEDIA_FIELDS.items():
        try:
            present = message.HasField(field)
        except ValueError:
            continue
        if not present:
            continue
        m = getattr(message, field)
        return {
            "type": mtype,
            "field": field,
            "mediaKey": bytes(m.mediaKey),
            "directPath": m.directPath or None,
            "url": m.url or None,
            "mimetype": m.mimetype or None,
            "fileSha256": bytes(m.fileSha256) or None,
            "fileEncSha256": bytes(m.fileEncSha256) or None,
            "fileLength": int(m.fileLength) if m.fileLength else None,
            "caption": getattr(m, "caption", "") or None,
            "fileName": getattr(m, "fileName", "") or None,
        }
    return None


def media_summary(message) -> dict | None:
    """A JSON-safe view of a message's media (no key/hash bytes)."""
    info = extract_media_info(message)
    if info is None:
        return None
    return {
        "type": info["type"],
        "mimetype": info["mimetype"],
        "fileName": info["fileName"],
        "fileLength": info["fileLength"],
        "caption": info["caption"],
    }


async def download_media(message, *, verify: bool = True) -> bytes:
    """Download + decrypt the media in a decoded ``Message``. Returns plaintext."""
    info = extract_media_info(message)
    if info is None:
        raise ValueError("message has no downloadable media")
    data = await download_encrypted(
        info["directPath"], info["url"], info["mediaKey"], info["type"],
        file_enc_sha256=info["fileEncSha256"] if verify else None,
    )
    if verify and info["fileSha256"] and sha256(data) != info["fileSha256"]:
        raise ValueError("decrypted media fileSha256 mismatch")
    return data


# ----------------------------------------------------------------------
# Uploading: encrypt -> media_conn -> POST -> build the media Message
# ----------------------------------------------------------------------
S_WHATSAPP_NET = "@s.whatsapp.net"

# media type -> mms upload path
_MEDIA_UPLOAD_PATH = {
    "image": "/mms/image", "video": "/mms/video", "audio": "/mms/audio",
    "document": "/mms/document", "sticker": "/mms/image",
}
# media type -> WAProto Message field
_MEDIA_MSG_FIELD = {
    "image": "imageMessage", "video": "videoMessage",
    "audio": "audioMessage", "document": "documentMessage",
}


def encrypt_media(plaintext: bytes, media_type: str, media_key: bytes | None = None) -> dict:
    """Encrypt media for upload. Returns enc bytes + key + hashes + length."""
    media_key = media_key or os.urandom(32)
    iv, cipher_key, mac_key = media_keys(media_key, media_type)
    ciphertext = aes_cbc_encrypt(cipher_key, plaintext, iv)
    mac = hmac_sha256(mac_key, iv + ciphertext)[:10]
    enc = ciphertext + mac
    return {
        "enc": enc,
        "mediaKey": media_key,
        "fileSha256": sha256(plaintext),
        "fileEncSha256": sha256(enc),
        "fileLength": len(plaintext),
    }


def build_media_conn_query(tag: str) -> BinaryNode:
    """IQ requesting upload hosts + auth token (Baileys ``refreshMediaConn``)."""
    return BinaryNode(
        tag="iq",
        attrs={"to": S_WHATSAPP_NET, "type": "set", "xmlns": "w:m", "id": tag},
        content=[BinaryNode(tag="media_conn")],
    )


def parse_media_conn(result: BinaryNode) -> dict:
    """Parse a ``media_conn`` result into ``{auth, ttl, hosts}``."""
    mc = result.get_child("media_conn")
    if mc is None:
        raise ValueError("no media_conn in result")
    hosts = [h.attrs["hostname"] for h in mc.get_children("host") if h.attrs.get("hostname")]
    return {"auth": mc.attrs.get("auth", ""),
            "ttl": int(mc.attrs.get("ttl", "0") or "0"),
            "hosts": hosts or [DEFAULT_MEDIA_HOST]}


def _enc_sha_token(file_enc_sha256: bytes) -> str:
    """URL-safe base64 of fileEncSha256, no padding (upload path + token)."""
    return base64.urlsafe_b64encode(file_enc_sha256).decode().rstrip("=")


async def upload_media(
    enc: bytes, file_enc_sha256: bytes, media_type: str, conn: dict, *, timeout: float = 120
) -> dict:
    """POST encrypted media to the first working host. Returns {url, directPath, handle}."""
    token = _enc_sha_token(file_enc_sha256)
    path = _MEDIA_UPLOAD_PATH[media_type]
    headers = {"Origin": DEFAULT_ORIGIN, "Content-Type": "application/octet-stream"}
    last_exc: Exception | None = None
    async with aiohttp.ClientSession(headers=headers) as s:
        for host in conn["hosts"]:
            url = f"https://{host}{path}/{token}"
            try:
                async with s.post(url, params={"auth": conn["auth"], "token": token},
                                  data=enc, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                    r.raise_for_status()
                    j = await r.json()
                return {"url": j.get("url"), "directPath": j.get("direct_path"),
                        "handle": j.get("handle")}
            except Exception as e:  # try the next host
                last_exc = e
    raise RuntimeError(f"media upload failed on all hosts: {last_exc}")


def build_media_message(
    media_type: str, *, upload: dict, enc: dict, mimetype: str | None = None,
    caption: str | None = None, file_name: str | None = None,
    width: int | None = None, height: int | None = None,
    seconds: int | None = None, ptt: bool | None = None, page_count: int | None = None,
):
    """Assemble a WAProto ``Message`` for uploaded media."""
    from .. import proto

    field = _MEDIA_MSG_FIELD[media_type]
    sub = getattr(proto.Message, {"imageMessage": "ImageMessage", "videoMessage": "VideoMessage",
                                  "audioMessage": "AudioMessage", "documentMessage": "DocumentMessage"}[field])
    kw = dict(
        url=upload["url"] or "", directPath=upload["directPath"] or "",
        mediaKey=enc["mediaKey"], fileEncSha256=enc["fileEncSha256"],
        fileSha256=enc["fileSha256"], fileLength=enc["fileLength"],
        mediaKeyTimestamp=int(time.time()),
    )
    if mimetype:
        kw["mimetype"] = mimetype
    if caption and media_type in ("image", "video", "document"):
        kw["caption"] = caption
    if file_name and media_type == "document":
        kw["fileName"] = file_name
    if media_type == "image":
        if width:
            kw["width"] = width
        if height:
            kw["height"] = height
    if media_type == "video":
        if seconds:
            kw["seconds"] = seconds
        if width:
            kw["width"] = width
        if height:
            kw["height"] = height
    if media_type == "audio":
        if seconds:
            kw["seconds"] = seconds
        if ptt is not None:
            kw["ptt"] = ptt
    if media_type == "document" and page_count:
        kw["pageCount"] = page_count
    return proto.Message(**{field: sub(**kw)})


def guess_media_type(mimetype: str) -> str:
    """Map a MIME type to a piwapp media type (default: document)."""
    if mimetype.startswith("image/"):
        return "image"
    if mimetype.startswith("video/"):
        return "video"
    if mimetype.startswith("audio/"):
        return "audio"
    return "document"
