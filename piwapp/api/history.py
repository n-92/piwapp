"""History-sync decode.

WhatsApp delivers chat history via a ``protocolMessage.historySyncNotification``:
either an inline zlib payload (initial bootstrap) or a reference to an encrypted
external blob. We download+decrypt (media scheme), zlib-inflate, and parse a
``HistorySync`` protobuf into chats / contacts / messages.

Mirrors Baileys' ``downloadHistory`` / ``processHistoryMessage``.
"""

from __future__ import annotations

import zlib
from typing import Any

from .. import proto
from .media import download_encrypted


def get_history_notification(message: "proto.Message"):
    """Return the ``historySyncNotification`` from a message, or None."""
    try:
        pm = message.protocolMessage
        if pm.HasField("historySyncNotification"):
            return pm.historySyncNotification
    except Exception:
        return None
    return None


async def download_history(notification) -> "proto.HistorySync":
    """Resolve a history notification into a parsed ``HistorySync``."""
    if notification.initialHistBootstrapInlinePayload:
        raw = zlib.decompress(bytes(notification.initialHistBootstrapInlinePayload))
        return proto.HistorySync.FromString(raw)
    plaintext = await download_encrypted(
        notification.directPath or None, None,
        bytes(notification.mediaKey), "md-msg-hist",
    )
    return proto.HistorySync.FromString(zlib.decompress(plaintext))


def process_history(item: "proto.HistorySync") -> dict[str, Any]:
    """Flatten a HistorySync into {chats, contacts, messages, lid_pn, pushnames, ...}."""
    chats: list[dict] = []
    contacts: list[dict] = []
    messages: list[dict] = []
    lid_pn: list[dict] = []
    pushnames: list[dict] = []

    for m in item.phoneNumberToLidMappings:
        if m.lidJid and m.pnJid:
            lid_pn.append({"lid": m.lidJid, "pn": m.pnJid})

    sync_type = item.syncType
    T = proto.HistorySync.HistorySyncType
    if sync_type in (T.INITIAL_BOOTSTRAP, T.RECENT, T.FULL, T.ON_DEMAND):
        for conv in item.conversations:
            cid = conv.id
            contacts.append({
                "id": cid,
                "name": conv.name or conv.displayName or None,
            })
            for hmsg in conv.messages:
                wm = hmsg.message  # WebMessageInfo
                key = wm.key
                text = _text_of_webmessage(wm)
                messages.append({
                    "key": {
                        "remoteJid": key.remoteJid,
                        "fromMe": key.fromMe,
                        "id": key.id,
                        "participant": key.participant or None,
                    },
                    "message": wm.message,
                    "text": text,
                    "messageTimestamp": int(wm.messageTimestamp) if wm.messageTimestamp else 0,
                    "pushName": wm.pushName or None,
                })
            chats.append({
                "id": cid,
                "name": conv.name or None,
                "conversationTimestamp": int(conv.conversationTimestamp) if conv.conversationTimestamp else 0,
                "unreadCount": conv.unreadCount,
            })
    elif sync_type == T.PUSH_NAME:
        for c in item.pushnames:
            pushnames.append({"id": c.id, "notify": c.pushname})
            contacts.append({"id": c.id, "notify": c.pushname})

    return {
        "syncType": int(sync_type),
        "progress": item.progress,
        "chats": chats,
        "contacts": contacts,
        "messages": messages,
        "lid_pn": lid_pn,
        "pushnames": pushnames,
    }


def _text_of_webmessage(wm) -> str | None:
    """Extract displayable text from a WebMessageInfo's nested Message."""
    try:
        msg = wm.message
        if msg.HasField("conversation"):
            return msg.conversation
        if msg.HasField("extendedTextMessage"):
            return msg.extendedTextMessage.text
    except Exception:
        pass
    return None
