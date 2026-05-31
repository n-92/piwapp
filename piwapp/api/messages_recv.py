"""Incoming message processing: decrypt ``<message>`` nodes and emit events.

Given a decrypted ``<message>`` node, decrypts its ``<enc>`` child with the
appropriate Signal cipher (Double Ratchet for ``pkmsg``/``msg``, Sender Key for
``skmsg``), builds a message dict, and emits ``messages.upsert``. Group sender
keys distributed in-band (``<enc type=skmsg>`` arrives only after the sender's
distribution message has been processed) are looked up by ``group::participant``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..binary import BinaryNode, jids
from ..crypto.sender_key import GroupSessionBuilder, sender_key_name
from ..events import MessagesUpsert, TypedEventEmitter, UpsertType, WAEventType
from .history import download_history, get_history_notification, process_history
from .media import media_summary
from .messages import (
    decrypt_dm_node,
    decrypt_group_node,
    text_of,
)


class MessageReceiver:
    """Decrypts inbound message nodes and emits ``messages.upsert``."""

    def __init__(self, signal_store, emitter: TypedEventEmitter) -> None:
        self._store = signal_store
        self._ev = emitter
        self._tasks: set[asyncio.Task] = set()

    async def handle(self, node: BinaryNode) -> dict[str, Any] | None:
        """Decrypt one ``<message>`` node, emit ``messages.upsert``, return the dict."""
        enc = node.get_child("enc")
        if enc is None:
            return None
        from_jid = node.attrs.get("from", "")
        is_group = jids.is_jid_group(from_jid)
        enc_type = enc.attrs.get("type", "msg")

        try:
            if enc_type == "skmsg":
                participant = node.attrs.get("participant") or ""
                name = sender_key_name(from_jid, participant)
                message = decrypt_group_node(self._store, name, node)
            else:
                _sender, message = decrypt_dm_node(self._store, node)
        except Exception as exc:  # decryption failed (e.g. no session/sender key)
            await self._ev.emit(
                WAEventType.MESSAGES_UPDATE,
                {"key": self._key(node, from_jid), "decryptError": str(exc)},
            )
            return None

        # Unwrap a deviceSentMessage: this is one of OUR OWN messages synced from
        # another device, so fromMe=True and the real chat is the destinationJid.
        from_me = False
        remote_jid = from_jid
        try:
            if message.HasField("deviceSentMessage"):
                dsm = message.deviceSentMessage
                remote_jid = dsm.destinationJid or from_jid
                message = dsm.message
                from_me = True
        except Exception:
            pass

        # Install an incoming Sender-Key Distribution Message so we can decrypt
        # this participant's future group (skmsg) messages. The author is the
        # group participant (or the 1:1 sender for direct SKDM delivery).
        try:
            if message.HasField("senderKeyDistributionMessage"):
                skdm = message.senderKeyDistributionMessage
                author = node.attrs.get("participant") or from_jid
                GroupSessionBuilder(self._store).process(
                    sender_key_name(skdm.groupId, author),
                    skdm.axolotlSenderKeyDistributionMessage,
                )
        except Exception:
            pass

        # history sync notification → download + parse in the background
        notification = get_history_notification(message)
        if notification is not None:
            task = asyncio.create_task(self._handle_history(notification))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

        key = self._key(node, remote_jid)
        key["fromMe"] = from_me
        msg_dict = {
            "key": key,
            "message": message,
            "text": text_of(message),
            "media": media_summary(message),  # None unless the message carries media
            "messageTimestamp": int(node.attrs.get("t", "0") or "0"),
            "pushName": node.attrs.get("notify"),
        }
        await self._ev.emit(
            WAEventType.MESSAGES_UPSERT,
            MessagesUpsert(messages=[msg_dict], type=UpsertType.NOTIFY),
        )
        return msg_dict

    async def _handle_history(self, notification) -> None:
        """Download + decode a history-sync blob, then emit + populate events."""
        try:
            sync = await download_history(notification)
            data = process_history(sync)
        except Exception as exc:
            await self._ev.emit(WAEventType.MESSAGES_UPDATE, {"historyError": str(exc)})
            return
        # feed the store via standard events, plus a structured summary
        if data["contacts"]:
            await self._ev.emit(WAEventType.CONTACTS_UPSERT, data["contacts"])
        if data["chats"]:
            await self._ev.emit(WAEventType.CHATS_UPSERT, data["chats"])
        if data["messages"]:
            await self._ev.emit(
                WAEventType.MESSAGES_UPSERT,
                MessagesUpsert(messages=data["messages"], type=UpsertType.APPEND),
            )
        await self._ev.emit(WAEventType.MESSAGING_HISTORY_SET, data)

    @staticmethod
    def _key(node: BinaryNode, from_jid: str) -> dict[str, Any]:
        return {
            "remoteJid": from_jid,
            "id": node.attrs.get("id", ""),
            "fromMe": False,
            "participant": node.attrs.get("participant"),
        }
