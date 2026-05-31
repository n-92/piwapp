"""MCP server exposing piwapp (WhatsApp) to an LLM.

Two tiers of tools:

* **Archive (read-only)** — query the SQLite message archive. Always available,
  no WhatsApp connection required. Driven by ``PIWAPP_DB``.
* **Live** — ``send_message`` / ``list_groups`` / ``connection_status``. Only
  active when ``PIWAPP_AUTH`` points at an already-paired credentials file; the
  server then keeps a background connection online. This uses its **own**
  dedicated device so it never collides with your other piwapp sessions.

Run it (stdio transport, the default for Claude Desktop / Claude Code):

    PIWAPP_DB=piwapp_capture.json.db python -m piwapp.mcp_server          # read-only
    PIWAPP_AUTH=piwapp_mcp.json PIWAPP_DB=piwapp_mcp.json.db python -m piwapp.mcp_server   # live

Config (environment variables):
    PIWAPP_DB    SQLite archive path        (default: piwapp.db)
    PIWAPP_AUTH  paired creds json for live (default: unset -> read-only)
    PIWAPP_KEYS  Signal keys path           (default: <PIWAPP_AUTH>.keys)
"""

from __future__ import annotations

import asyncio
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP, Image

from .store.sqlite_store import SqliteStore


# --------------------------------------------------------------------------
# runtime state (filled by the lifespan)
# --------------------------------------------------------------------------
class _State:
    db_path: str = os.environ.get("PIWAPP_DB", "piwapp.db")
    auth_path: str | None = os.environ.get("PIWAPP_AUTH") or None
    keys_path: str | None = os.environ.get("PIWAPP_KEYS") or None

    store: SqliteStore | None = None        # read archive (own connection)
    client: Any = None                       # live piwapp Client, if PIWAPP_AUTH set
    runner: asyncio.Task | None = None
    online = asyncio.Event()
    me: dict | None = None

    # pairing-in-progress state (for chat-driven `start_pairing`)
    pairing_qr: str | None = None            # unicode QR for the current code
    pairing_png: str | None = None           # absolute path to the QR image

    # live incoming-message queue (powers `wait_for_messages`)
    incoming: "asyncio.Queue | None" = None


state = _State()


def _on_incoming(payload) -> None:
    """Enqueue incoming (not-from-me) messages for `wait_for_messages`."""
    if state.incoming is None:
        return
    for m in getattr(payload, "messages", None) or []:
        if (m.get("key") or {}).get("fromMe"):
            continue
        item = _fmt_msg(m)
        item["media"] = m.get("media")
        try:
            state.incoming.put_nowait(item)
        except Exception:
            pass


def _iso(ts: int | None) -> str | None:
    if not ts:
        return None
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _fmt_msg(m: dict) -> dict:
    """A JSON-friendly message view (drops the raw proto blob)."""
    key = m.get("key") or {}
    return {
        "chat": key.get("remoteJid"),
        "id": key.get("id"),
        "from_me": bool(key.get("fromMe")),
        "sender": key.get("participant") or key.get("remoteJid"),
        "timestamp": _iso(m.get("messageTimestamp")),
        "text": m.get("text"),
        "push_name": m.get("pushName"),
    }


def _normalize_jid(to: str) -> str:
    """Accept a full JID, or a bare phone number -> user JID."""
    to = to.strip()
    if "@" in to:
        return to
    digits = to.lstrip("+").replace(" ", "").replace("-", "")
    return f"{digits}@s.whatsapp.net"


# --------------------------------------------------------------------------
# live client startup (shared by the lifespan and chat-driven pairing)
# --------------------------------------------------------------------------
def _on_update(u: dict) -> None:
    """Connection-lifecycle handler: capture QR, track online state."""
    from .auth.qr import render_qr_terminal, save_qr_png

    if "qr" in u:
        png = save_qr_png(u["qr"], "piwapp_qr.png")
        state.pairing_qr = render_qr_terminal(u["qr"])
        state.pairing_png = str(Path(png).resolve())
    if u.get("connection") == "open":
        state.me = u.get("me") or (state.client.creds.me if state.client else None)
        state.pairing_qr = None  # paired; QR no longer needed
        state.online.set()
    elif u.get("connection") == "close":
        state.online.clear()


def _start_live_client(path: Path) -> None:
    """Create + start a live Client for `path`, creating fresh creds if absent."""
    from .auth.creds import AuthenticationCreds
    from .client import Client
    from .config import ConnectionConfig

    if path.exists():
        creds = AuthenticationCreds.from_json(path.read_text())
    else:
        creds = AuthenticationCreds.initial()
        path.write_text(creds.to_json())
    keys = state.keys_path or (str(path) + ".keys")
    state.client = Client(
        creds, ConnectionConfig(),
        on_creds_update=lambda c: path.write_text(c.to_json()),
        keys_path=keys,
        db_path=state.db_path,   # live messages flow into the same archive
    )
    state.client.on("connection.update", _on_update)
    from .events import WAEventType
    state.client.events.on(WAEventType.MESSAGES_UPSERT, _on_incoming)
    state.runner = asyncio.create_task(state.client.start())


# --------------------------------------------------------------------------
# lifespan: open the archive, and (if already paired) bring a client online
# --------------------------------------------------------------------------
@asynccontextmanager
async def _lifespan(_server: FastMCP):
    state.store = SqliteStore(state.db_path)
    state.incoming = asyncio.Queue()  # created in the running loop

    # Only auto-connect if creds already exist. If PIWAPP_AUTH is set but the file
    # is missing, we stay unpaired so the `start_pairing` tool can create it.
    if state.auth_path and Path(state.auth_path).exists():
        _start_live_client(Path(state.auth_path))

    try:
        yield
    finally:
        if state.client is not None:
            try:
                await state.client.stop()
            except Exception:
                pass
        if state.runner is not None:
            state.runner.cancel()
        if state.store is not None:
            state.store.close()


mcp = FastMCP("piwapp-whatsapp", lifespan=_lifespan)


async def _ensure_online(timeout: float = 20.0) -> None:
    if state.client is None:
        raise RuntimeError(
            "Not paired yet. Call `start_pairing` to link a WhatsApp device "
            "(or start the server with PIWAPP_AUTH pointing at a paired file)."
        )
    if state.client.is_open:
        return
    try:
        await asyncio.wait_for(state.online.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        raise RuntimeError("WhatsApp connection is not online yet; try again shortly.")


# --------------------------------------------------------------------------
# archive (read-only) tools
# --------------------------------------------------------------------------
@mcp.tool()
def list_chats(limit: int = 20) -> list[dict]:
    """List the most recent chats (groups and 1:1) from the local archive.

    Returns each chat's JID, display name, and last-activity time.
    """
    out = []
    for c in state.store.recent_chats(limit):
        out.append({
            "jid": c.get("jid"),
            "name": c.get("name"),
            "is_group": str(c.get("jid", "")).endswith("@g.us"),
            "last_activity": _iso(c.get("conversation_timestamp")),
            "unread": c.get("unread_count"),
        })
    return out


@mcp.tool()
def get_messages(chat_jid: str, limit: int = 30) -> list[dict]:
    """Get recent messages in a chat from the local archive, newest first.

    `chat_jid` is a full JID like `1234567890@s.whatsapp.net` or `...@g.us`.
    """
    return [_fmt_msg(m) for m in state.store.get_chat_messages(chat_jid, limit)]


@mcp.tool()
def search_messages(query: str, limit: int = 30) -> list[dict]:
    """Full-text search across all archived message text, newest first."""
    return [_fmt_msg(m) for m in state.store.search_text(query, limit)]


@mcp.tool()
def last_sent_message() -> dict | None:
    """The most recent message YOU sent (any chat), from the archive."""
    m = state.store.last_sent_message()
    return _fmt_msg(m) if m else None


@mcp.tool()
def group_info(group_jid: str) -> dict | None:
    """Stored metadata for a group (subject, participants), if archived."""
    return state.store.get_group_metadata(group_jid)


@mcp.tool()
def archive_stats() -> dict:
    """Summary of the local archive: message count and connection status."""
    return {
        "db_path": state.db_path,
        "messages": state.store.message_count,
        "live": state.client is not None,
        "online": bool(state.client and state.client.is_open),
        "me": (state.me or {}).get("id") if state.me else None,
    }


# --------------------------------------------------------------------------
# pairing (chat-driven device linking)
# --------------------------------------------------------------------------
@mcp.tool()
async def start_pairing() -> list:
    """Link a WhatsApp device by QR — do the whole pairing from chat.

    Starts a connection and returns the login QR code as an image (plus a file
    path to the same QR). Open WhatsApp on your phone -> Linked Devices ->
    Link a Device, and scan it. Then call `pairing_status` to confirm; once it
    reports online, the live tools (`send_message`, `list_groups`) are ready.
    """
    if state.client is not None and state.client.is_open:
        return [f"Already paired and online as {(state.me or {}).get('id')}."]

    if state.client is None:
        _start_live_client(Path(state.auth_path or "piwapp_mcp.json"))

    # wait briefly for the first QR (or an immediate login on existing creds)
    for _ in range(24):
        if state.pairing_qr or state.online.is_set():
            break
        await asyncio.sleep(0.5)

    if state.online.is_set():
        return [f"Paired and online as {(state.me or {}).get('id')}."]

    if state.pairing_qr and state.pairing_png:
        guidance = (
            "Scan this QR in WhatsApp -> Linked Devices -> Link a Device "
            "within ~60s, then call `pairing_status`. "
            f"(QR image also saved at: {state.pairing_png})"
        )
        try:
            data = Path(state.pairing_png).read_bytes()
            return [Image(data=data, format="png"), guidance]
        except Exception:
            return [guidance, state.pairing_qr]

    return ["Could not produce a QR yet — call start_pairing again in a moment."]


@mcp.tool()
async def pairing_status() -> dict:
    """Check the pairing/connection state: online yet, and as whom."""
    return {
        "client_started": state.client is not None,
        "online": bool(state.client and state.client.is_open),
        "qr_pending": state.pairing_qr is not None,
        "qr_png": state.pairing_png,
        "me": (state.me or {}).get("id") if state.me else None,
    }


# --------------------------------------------------------------------------
# live tools (require a paired device — via PIWAPP_AUTH or start_pairing)
# --------------------------------------------------------------------------
@mcp.tool()
async def send_message(to: str, text: str) -> dict:
    """Send a WhatsApp text message (live).

    `to` may be a full JID (`...@s.whatsapp.net` or `...@g.us`) or a bare phone
    number (digits, optionally with +) which is treated as a 1:1 chat.
    Requires the server to be running in live mode (PIWAPP_AUTH set).
    """
    await _ensure_online()
    jid = _normalize_jid(to)
    msg_id = await state.client.send_text(jid, text)
    return {"sent": True, "to": jid, "message_id": msg_id}


@mcp.tool()
async def send_file(to: str, path: str, caption: str | None = None) -> dict:
    """Send a local file (image/video/audio/document) to a chat (live).

    `to` is a full JID or a bare phone number. `path` is a local filesystem path;
    the media type and MIME are inferred from the file extension.
    """
    await _ensure_online()
    jid = _normalize_jid(to)
    msg_id = await state.client.send_file(jid, path, caption=caption)
    return {"sent": True, "to": jid, "path": path, "message_id": msg_id}


@mcp.tool()
async def download_media(chat_jid: str, message_id: str, save_path: str) -> dict:
    """Download media from an archived message to a local file.

    Looks up the stored message by (chat_jid, message_id), decrypts its media,
    and writes it to `save_path`. Works from the archive without a live socket.
    """
    from . import proto
    from .api.media import download_media as _dl

    row = state.store.load_message(chat_jid, message_id)
    if not row or not row.get("proto"):
        raise RuntimeError("message not found in archive, or it has no stored content")
    message = proto.Message.FromString(row["proto"])
    data = await _dl(message)
    Path(save_path).write_bytes(data)
    return {"saved": save_path, "bytes": len(data)}


@mcp.tool()
async def list_groups() -> list[dict]:
    """List the groups this account is in (live query). Requires live mode."""
    await _ensure_online()
    return await state.client.fetch_groups()


@mcp.tool()
async def connection_status() -> dict:
    """Whether the live WhatsApp connection is online, and as whom."""
    return {
        "live": state.client is not None,
        "online": bool(state.client and state.client.is_open),
        "me": (state.me or {}).get("id") if state.me else None,
    }


@mcp.tool()
async def wait_for_messages(chat_jid: str | None = None, timeout: float = 30.0) -> list[dict]:
    """Listen for incoming messages (live) and return them when they arrive.

    Blocks up to `timeout` seconds until at least one new incoming message
    (not sent by you) arrives, then returns the batch. Optionally filter to a
    single `chat_jid`. Returns `[]` if nothing arrives in time.

    This is the listening half of a conversation: loop
    `wait_for_messages` -> read -> `send_message`/`send_file` -> repeat.
    """
    if state.client is None or state.incoming is None:
        raise RuntimeError(
            "Not live. Call `start_pairing` (or start with PIWAPP_AUTH) first."
        )
    q = state.incoming
    end = time.monotonic() + max(0.0, timeout)
    out: list[dict] = []
    while True:
        while not q.empty():
            out.append(q.get_nowait())
        if chat_jid:
            out = [m for m in out if m.get("chat") == chat_jid]
        if out:
            return out
        remaining = end - time.monotonic()
        if remaining <= 0:
            return []
        try:
            out.append(await asyncio.wait_for(q.get(), timeout=remaining))
        except asyncio.TimeoutError:
            return []


async def _pair(auth_file: str, timeout: float = 120.0) -> int:
    """Pair a fresh device (render a QR), persist creds/keys/db, and exit.

    This is the one-time onboarding step for a new user: run it once, scan the
    QR, and you get ``<auth_file>`` (+ ``.keys`` + ``.db``) that the MCP server
    then reuses to reconnect silently (no further QR).
    """
    import sys
    from pathlib import Path

    from .auth.creds import AuthenticationCreds
    from .auth.qr import render_qr_terminal, save_qr_png
    from .client import Client
    from .config import ConnectionConfig

    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass

    path = Path(auth_file)
    if path.exists():
        creds = AuthenticationCreds.from_json(path.read_text())
    else:
        creds = AuthenticationCreds.initial()
        path.write_text(creds.to_json())
    keys = str(path) + ".keys"
    db = str(path) + ".db"

    client = Client(
        creds, ConnectionConfig(),
        on_creds_update=lambda c: path.write_text(c.to_json()),
        keys_path=keys, db_path=db,
    )
    online = asyncio.Event()
    holder: dict = {}

    def on_update(u: dict) -> None:
        if "qr" in u:
            png = save_qr_png(u["qr"], "piwapp_qr.png")
            print("\nScan with WhatsApp -> Linked Devices -> Link a Device:\n")
            print(render_qr_terminal(u["qr"]))
            print(f"(or open the image: {Path(png).resolve()})")
        if u.get("connection") == "open":
            holder["me"] = (u.get("me") or {}).get("id")
            online.set()

    client.on("connection.update", on_update)
    runner = asyncio.create_task(client.start())
    try:
        await asyncio.wait_for(online.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        print("\n✗ Pairing timed out (no scan). Re-run to try again.")
        await client.stop()
        runner.cancel()
        return 1

    await asyncio.sleep(2)  # let post-login persist the device-identity + keys
    await client.stop()
    runner.cancel()
    print(f"\n✓ Paired and online as {holder.get('me')}. Saved:")
    for f in (path, keys, db):
        print(f"    {Path(f).resolve()}")
    print("\nNow point your MCP client at these (env vars):")
    print(f"    PIWAPP_AUTH={Path(path).resolve()}")
    print(f"    PIWAPP_KEYS={Path(keys).resolve()}")
    print(f"    PIWAPP_DB={Path(db).resolve()}")
    return 0


def main() -> None:
    """Console-script entry point: run the stdio server, or ``--pair`` a device."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="piwapp-mcp",
        description="piwapp WhatsApp MCP server (stdio). Use --pair for one-time setup.",
    )
    parser.add_argument(
        "--pair", metavar="AUTH_FILE",
        help="pair a device via QR, save credentials, and exit (then configure your MCP client)",
    )
    args, _ = parser.parse_known_args()
    if args.pair:
        raise SystemExit(asyncio.run(_pair(args.pair)))
    mcp.run()


if __name__ == "__main__":
    main()
