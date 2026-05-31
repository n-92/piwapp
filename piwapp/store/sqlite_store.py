"""SQLite-backed store: durable messages / chats / contacts.

Binds to the event emitter exactly like :class:`MemoryStore`, but writes to a
SQLite database so history and conversations survive restarts. Message protobufs
are stored as a blob alongside extracted columns (text, timestamp, sender) for
fast querying.

Implements the same query surface as ``MemoryStore`` plus a few archive helpers
(``recent_chats``, ``last_sent_message``, ``search_text``).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..events import MessagesUpsert, TypedEventEmitter, WAEventType

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    chat_jid   TEXT NOT NULL,
    msg_id     TEXT NOT NULL,
    from_me    INTEGER NOT NULL DEFAULT 0,
    participant TEXT,
    timestamp  INTEGER NOT NULL DEFAULT 0,
    push_name  TEXT,
    text       TEXT,
    proto      BLOB,
    PRIMARY KEY (chat_jid, msg_id)
);
CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_fromme ON messages(from_me, timestamp);

CREATE TABLE IF NOT EXISTS chats (
    jid TEXT PRIMARY KEY,
    name TEXT,
    conversation_timestamp INTEGER DEFAULT 0,
    unread_count INTEGER DEFAULT 0,
    data TEXT
);

CREATE TABLE IF NOT EXISTS contacts (
    jid TEXT PRIMARY KEY,
    name TEXT,
    notify TEXT,
    data TEXT
);

CREATE TABLE IF NOT EXISTS groups (
    jid TEXT PRIMARY KEY,
    data TEXT
);
"""


def _msg_proto_bytes(message: Any) -> bytes | None:
    try:
        return message.SerializeToString()
    except Exception:
        return None


class SqliteStore:
    """Durable store; bind to an emitter to persist the event stream."""

    def __init__(self, path: str = "piwapp.db") -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._db.commit()

    # -- binding ---------------------------------------------------------
    def bind(self, emitter: TypedEventEmitter) -> None:
        emitter.on(WAEventType.MESSAGES_UPSERT, self._on_messages)
        emitter.on(WAEventType.CHATS_UPSERT, self._on_chats)
        emitter.on(WAEventType.CHATS_UPDATE, self._on_chats)
        emitter.on(WAEventType.CONTACTS_UPSERT, self._on_contacts)
        emitter.on(WAEventType.GROUPS_UPSERT, self._on_groups)
        emitter.on(WAEventType.GROUPS_UPDATE, self._on_groups)

    # -- event handlers --------------------------------------------------
    def _on_messages(self, payload: Any) -> None:
        msgs = payload.messages if isinstance(payload, MessagesUpsert) else payload.get("messages", [])
        rows = []
        for m in msgs:
            key = m.get("key") or {}
            jid, mid = key.get("remoteJid"), key.get("id")
            if not jid or not mid:
                continue
            rows.append((
                jid, mid, 1 if key.get("fromMe") else 0, key.get("participant"),
                int(m.get("messageTimestamp") or 0), m.get("pushName"),
                m.get("text"), _msg_proto_bytes(m.get("message")),
            ))
        if rows:
            self._db.executemany(
                "INSERT OR REPLACE INTO messages "
                "(chat_jid,msg_id,from_me,participant,timestamp,push_name,text,proto) "
                "VALUES (?,?,?,?,?,?,?,?)", rows)
            self._db.commit()

    def _on_chats(self, payload: Any) -> None:
        rows = []
        for c in _as_list(payload):
            jid = c.get("id") or c.get("jid")
            if jid:
                rows.append((jid, c.get("name"),
                             int(c.get("conversationTimestamp") or 0),
                             int(c.get("unreadCount") or 0), json.dumps(c, default=str)))
        if rows:
            self._db.executemany(
                "INSERT OR REPLACE INTO chats (jid,name,conversation_timestamp,unread_count,data) "
                "VALUES (?,?,?,?,?)", rows)
            self._db.commit()

    def _on_contacts(self, payload: Any) -> None:
        rows = []
        for c in _as_list(payload):
            jid = c.get("id") or c.get("jid")
            if jid:
                rows.append((jid, c.get("name"), c.get("notify"), json.dumps(c, default=str)))
        if rows:
            self._db.executemany(
                "INSERT OR REPLACE INTO contacts (jid,name,notify,data) VALUES (?,?,?,?)", rows)
            self._db.commit()

    def _on_groups(self, payload: Any) -> None:
        rows = [(g.get("id") or g.get("jid"), json.dumps(g, default=str))
                for g in _as_list(payload) if (g.get("id") or g.get("jid"))]
        if rows:
            self._db.executemany("INSERT OR REPLACE INTO groups (jid,data) VALUES (?,?)", rows)
            self._db.commit()

    # -- queries (MemoryStore-compatible + archive helpers) -------------
    def load_message(self, jid: str, message_id: str) -> dict[str, Any] | None:
        r = self._db.execute(
            "SELECT * FROM messages WHERE chat_jid=? AND msg_id=?", (jid, message_id)).fetchone()
        return _row_to_msg(r) if r else None

    def get_chat_messages(self, jid: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT * FROM messages WHERE chat_jid=? ORDER BY timestamp DESC LIMIT ?",
            (jid, limit)).fetchall()
        return [_row_to_msg(r) for r in rows]

    def get_group_metadata(self, jid: str) -> dict[str, Any] | None:
        r = self._db.execute("SELECT data FROM groups WHERE jid=?", (jid,)).fetchone()
        return json.loads(r["data"]) if r else None

    def recent_chats(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT * FROM chats ORDER BY conversation_timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def last_sent_message(self) -> dict[str, Any] | None:
        r = self._db.execute(
            "SELECT * FROM messages WHERE from_me=1 AND text IS NOT NULL "
            "ORDER BY timestamp DESC LIMIT 1").fetchone()
        return _row_to_msg(r) if r else None

    def search_text(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT * FROM messages WHERE text LIKE ? ORDER BY timestamp DESC LIMIT ?",
            (f"%{query}%", limit)).fetchall()
        return [_row_to_msg(r) for r in rows]

    @property
    def message_count(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]

    def close(self) -> None:
        self._db.close()


def _row_to_msg(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "key": {"remoteJid": r["chat_jid"], "id": r["msg_id"],
                "fromMe": bool(r["from_me"]), "participant": r["participant"]},
        "text": r["text"],
        "messageTimestamp": r["timestamp"],
        "pushName": r["push_name"],
        "proto": bytes(r["proto"]) if r["proto"] is not None else None,
    }


def _as_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return [payload]
    return []
