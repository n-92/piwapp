"""High-level client with automatic reconnect.

A :class:`Connection` handles a single socket. :class:`Client` supervises a
sequence of connections: it reconnects after the post-pairing ``515`` restart
(re-attempting with the now-populated ``creds.me`` as a login), retries
transient drops with exponential backoff, and stops on a permanent logout.

Events from each underlying connection are re-emitted to the client's own
emitter, so a single set of handlers survives across reconnects.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from .auth.creds import AuthenticationCreds
from .config import ConnectionConfig
from .crypto.signal_store import SignalStore
from .events import TypedEventEmitter
from .socket.connection import Connection, DisconnectReason, _Emitter
from .store import MemoryStore, SqliteStore

_PERMANENT = {
    int(DisconnectReason.LOGGED_OUT),
    int(DisconnectReason.FORBIDDEN),
    int(DisconnectReason.MULTIDEVICE_MISMATCH),
}
_MAX_BACKOFF = 30.0


class Client:
    """Supervises connections to WhatsApp with automatic reconnection."""

    def __init__(
        self,
        creds: AuthenticationCreds,
        config: ConnectionConfig | None = None,
        *,
        on_creds_update=None,
        keys_path: "str | Path | None" = None,
        db_path: "str | Path | None" = None,
    ) -> None:
        self.creds = creds
        self.config = config or ConnectionConfig()
        self._on_creds_update = on_creds_update
        self.ev = _Emitter()
        self._running = False
        self._conn: Connection | None = None
        # a fresh pairing on one connection becomes a "new login" on the next
        self._pending_new_login = False

        # WA-event emitter + store + Signal store all persist across reconnects.
        # store: durable SQLite when db_path is given, else in-memory.
        self.events = TypedEventEmitter()
        self.store = SqliteStore(str(db_path)) if db_path else MemoryStore()
        self.store.bind(self.events)
        self.signal_store = SignalStore.from_creds(creds)

        # optional on-disk persistence of Signal keys (sessions, pre-keys,
        # sender-keys) so they survive a process restart, not just reconnects.
        self._keys_path = Path(keys_path) if keys_path else None
        if self._keys_path is not None:
            if self._keys_path.exists():
                try:
                    self.signal_store.load(json.loads(self._keys_path.read_text()))
                except Exception:
                    pass
            self.signal_store.on_change = self._save_keys

    def _save_keys(self) -> None:
        if self._keys_path is None:
            return
        try:
            tmp = self._keys_path.with_suffix(self._keys_path.suffix + ".tmp")
            tmp.write_text(json.dumps(self.signal_store.dump()))
            tmp.replace(self._keys_path)  # atomic on the same filesystem
        except Exception:
            pass

    # -- subscription ----------------------------------------------------
    def on(self, event: str, handler) -> None:
        self.ev.on(event, handler)

    # -- lifecycle -------------------------------------------------------
    async def start(self) -> None:
        """Run the connect/reconnect loop until logged out or stopped."""
        self._running = True
        backoff = 1.0
        while self._running:
            self._conn = Connection(
                self.creds,
                self.config,
                events=self.events,
                signal_store=self.signal_store,
            )
            self._wire(self._conn)
            try:
                await self._conn.connect()
            except Exception as exc:  # pragma: no cover - network failures
                await self.ev.emit(
                    "connection.update",
                    {"connection": "close", "reason": int(DisconnectReason.CONNECTION_LOST),
                     "error": str(exc)},
                )
                if not self._running:
                    break
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF)
                continue

            await self._conn.wait_closed()
            code = self._conn.close_reason
            if not self._running:
                break
            if code == int(DisconnectReason.RESTART_REQUIRED):
                backoff = 1.0
                continue  # reconnect immediately and log in
            if code in _PERMANENT:
                await self.ev.emit(
                    "connection.update",
                    {"connection": "close", "reason": code, "logged_out": True},
                )
                break
            # transient drop: backoff and retry
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, _MAX_BACKOFF)
        self._running = False

    async def stop(self) -> None:
        """Stop the supervisor and close the active connection."""
        self._running = False
        if self._conn is not None:
            await self._conn.close()

    @property
    def is_open(self) -> bool:
        return self._conn is not None and self._conn.state.value == "open"

    async def send_text(self, to_jid: str, text: str) -> str:
        """Send a text message via the active connection (1:1 or group)."""
        if not self.is_open or self._conn is None:
            raise RuntimeError("client is not online")
        if to_jid.endswith("@g.us"):
            return await self._conn.send_group_text(to_jid, text)
        return await self._conn.send_text(to_jid, text)

    async def send_group_text(self, group_jid: str, text: str) -> str:
        """Send a text message to a group."""
        if not self.is_open or self._conn is None:
            raise RuntimeError("client is not online")
        return await self._conn.send_group_text(group_jid, text)

    async def fetch_groups(self) -> list[dict]:
        """List groups this account participates in."""
        if not self.is_open or self._conn is None:
            raise RuntimeError("client is not online")
        return await self._conn.fetch_groups()

    async def download_media(self, message, *, verify: bool = True) -> bytes:
        """Download + decrypt the media in a received ``Message`` (no socket needed)."""
        from .api.media import download_media
        return await download_media(message, verify=verify)

    async def send_media(
        self, to_jid: str, data: bytes, *, mimetype: str, media_type: str | None = None,
        caption: str | None = None, file_name: str | None = None,
        width: int | None = None, height: int | None = None,
        seconds: int | None = None, ptt: bool | None = None,
    ) -> str:
        """Encrypt + upload + send media (image/video/audio/document), 1:1 or group."""
        if not self.is_open or self._conn is None:
            raise RuntimeError("client is not online")
        return await self._conn.send_media(
            to_jid, data, mimetype=mimetype, media_type=media_type, caption=caption,
            file_name=file_name, width=width, height=height, seconds=seconds, ptt=ptt,
        )

    async def send_file(self, to_jid: str, path: "str | Path", *, caption: str | None = None,
                        mimetype: str | None = None) -> str:
        """Send a file from disk; mimetype is guessed from the extension if omitted."""
        import mimetypes

        p = Path(path)
        mt = mimetype or mimetypes.guess_type(p.name)[0] or "application/octet-stream"
        return await self.send_media(
            to_jid, p.read_bytes(), mimetype=mt, caption=caption, file_name=p.name,
        )

    # -- event forwarding ------------------------------------------------
    def _wire(self, conn: Connection) -> None:
        conn.ev.on("connection.update", self._on_conn_update)
        conn.ev.on("pairing.success", self._on_pairing)
        conn.ev.on("frame", self._forward("frame"))
        conn.ev.on("creds.update", self._on_creds)
        conn.ev.on("prekeys.uploaded", self._forward("prekeys.uploaded"))
        conn.ev.on("prekeys.error", self._forward("prekeys.error"))

    def _forward(self, event: str):
        async def _handler(payload):
            await self.ev.emit(event, payload)
        return _handler

    async def _on_pairing(self, payload) -> None:
        # the next connection's <success> is therefore a brand-new login
        self._pending_new_login = True
        await self.ev.emit("pairing.success", payload)

    async def _on_conn_update(self, update: dict) -> None:
        if update.get("connection") == "open":
            update = {**update, "is_new_login": self._pending_new_login}
            self._pending_new_login = False
        await self.ev.emit("connection.update", update)

    async def _on_creds(self, creds: AuthenticationCreds) -> None:
        if self._on_creds_update is not None:
            result = self._on_creds_update(creds)
            if asyncio.iscoroutine(result):
                await result
        await self.ev.emit("creds.update", creds)
