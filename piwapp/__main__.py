"""``python -m piwapp`` — connect to WhatsApp Web, show a login QR, stay online.

Loads (or creates) credentials, opens a connection, prints the pairing QR, and
after a successful scan reconnects and remains logged in (responding to
keepalive) until interrupted. Credentials are persisted on every update.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from .auth.creds import AuthenticationCreds
from .auth.qr import render_qr_terminal, save_qr_png
from .binary import BinaryNode
from .client import Client
from .config import ConnectionConfig

_DEBUG = os.environ.get("PIWAPP_DEBUG") == "1"

# Ensure non-ASCII output (QR prompt arrows, status glyphs) never crashes on a
# legacy console codepage (e.g. Windows cp1252). UTF-8 with replacement is safe.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:
        pass


def _load_creds(path: Path) -> AuthenticationCreds:
    if path.exists():
        return AuthenticationCreds.from_json(path.read_text())
    creds = AuthenticationCreds.initial()
    path.write_text(creds.to_json())
    return creds


async def _run(creds_path: Path) -> int:
    creds = _load_creds(creds_path)

    def save(updated: AuthenticationCreds) -> None:
        creds_path.write_text(updated.to_json())

    # persist Signal keys alongside creds so sessions survive restarts
    keys_path = creds_path.with_suffix(creds_path.suffix + ".keys")
    client = Client(creds, ConnectionConfig(), on_creds_update=save, keys_path=keys_path)
    stop = asyncio.Event()
    attempts = {"n": 0}

    async def on_update(update: dict) -> None:
        if update.get("connection") == "connecting":
            attempts["n"] += 1
            if _DEBUG:
                print(f"[debug] connection attempt #{attempts['n']} "
                      f"(login={creds.me is not None})")
        if "qr" in update:
            png = save_qr_png(update["qr"], "piwapp_qr.png")
            print("\nScan with WhatsApp → Linked Devices → Link a Device:\n")
            print(render_qr_terminal(update["qr"]))
            print(f"(or open the image: {Path(png).resolve()})")
        if update.get("connection") == "open":
            me = (update.get("me") or {}).get("id")
            tag = " (new login)" if update.get("is_new_login") else ""
            print(f"\n✓ Online as {me}{tag} — staying connected. Press Ctrl+C to exit.")
        if update.get("connection") == "close" and update.get("logged_out"):
            reason = update.get("reason")
            had_me = creds.me is not None
            print(f"\n✗ Logged out (reason {reason}) "
                  f"on attempt #{attempts['n']} (had_me={had_me}).")
            if had_me and creds_path.exists():
                # Back up rather than delete, so a valid session is never lost
                # to a spurious failure. Re-running will pair fresh.
                backup = creds_path.with_suffix(creds_path.suffix + ".rejected")
                creds_path.replace(backup)
                print(f"  The saved session was rejected; it's been moved to {backup}\n"
                      f"  (not deleted). Re-run `python -m piwapp` to pair fresh.")
            stop.set()

    def on_frame(node: BinaryNode) -> None:
        if _DEBUG:
            print(f"[debug] << <{node.tag}> attrs={node.attrs}")
        if node.tag == "failure":
            print(f"\n[failure node] {node.to_debug()}")

    client.on("connection.update", on_update)
    client.on("frame", on_frame)
    client.on("pairing.success", lambda p: print(f"\n✓ Paired: {p['me']['id']} — finishing login…"))

    # incoming messages (decrypted) and decryption failures
    def on_messages(payload) -> None:
        for m in payload.messages:
            who = m["key"].get("participant") or m["key"]["remoteJid"]
            print(f"\n💬 [{who}] {m.get('text') or '<non-text message>'}")

    def on_msg_update(payload) -> None:
        if isinstance(payload, dict) and payload.get("decryptError"):
            print(f"\n⚠ could not decrypt a message ({payload['decryptError']})")

    from .events import WAEventType
    client.events.on(WAEventType.MESSAGES_UPSERT, on_messages)
    client.events.on(WAEventType.MESSAGES_UPDATE, on_msg_update)

    client.on("prekeys.uploaded", lambda p: print(
        f"  ↑ uploaded {p['count']} pre-keys — this device can now receive messages."))
    client.on("prekeys.error", lambda p: print(f"  ⚠ pre-key upload failed: {p['error']}"))

    runner = asyncio.create_task(client.start())
    try:
        await stop.wait()
    except asyncio.CancelledError:  # pragma: no cover
        pass
    finally:
        await client.stop()
        runner.cancel()
    return 0


def main() -> None:
    creds_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("piwapp_auth.json")
    try:
        raise SystemExit(asyncio.run(_run(creds_path)))
    except KeyboardInterrupt:  # pragma: no cover
        print("\nInterrupted.")


if __name__ == "__main__":
    main()
