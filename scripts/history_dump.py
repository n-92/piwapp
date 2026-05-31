"""Connect, collect history-sync, and report chats + your last sent message.

Usage: python scripts/history_dump.py [auth.json] [collect_seconds]
"""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import datetime
from pathlib import Path

from piwapp.auth.creds import AuthenticationCreds
from piwapp.client import Client
from piwapp.config import ConnectionConfig
from piwapp.events import WAEventType

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


async def main(path: Path, collect: float) -> int:
    from piwapp.auth.qr import save_qr_png
    if path.exists():
        creds = AuthenticationCreds.from_json(path.read_text())
    else:
        creds = AuthenticationCreds.initial()
        path.write_text(creds.to_json())
    db_path = str(path) + ".db"
    client = Client(creds, ConnectionConfig(),
                    on_creds_update=lambda c: path.write_text(c.to_json()),
                    keys_path=str(path) + ".keys",
                    db_path=db_path)  # persist messages/chats/contacts to SQLite
    log(f"persisting to {db_path}")
    online = asyncio.Event()
    history_sets: list[dict] = []
    all_messages: list[dict] = []

    def on_update(u: dict) -> None:
        if "qr" in u:
            save_qr_png(u["qr"], "piwapp_qr.png")
            log(f"SCAN QR: {Path('piwapp_qr.png').resolve()}")
        if u.get("connection") == "open":
            online.set()

    client.on("connection.update", on_update)
    client.events.on(WAEventType.MESSAGING_HISTORY_SET,
                     lambda d: (history_sets.append(d), all_messages.extend(d.get("messages", []))))
    client.events.on(WAEventType.MESSAGES_UPSERT, lambda p: all_messages.extend(p.messages))

    runner = asyncio.create_task(client.start())
    try:
        await asyncio.wait_for(online.wait(), timeout=60)
        log(f"online; collecting history for {collect:.0f}s…")
        await asyncio.sleep(collect)
    except asyncio.TimeoutError:
        log("could not get online"); return 1
    finally:
        await client.stop()
        runner.cancel()

    total_chats = sum(len(d.get("chats", [])) for d in history_sets)
    total_contacts = sum(len(d.get("contacts", [])) for d in history_sets)
    log(f"history sets: {len(history_sets)}  chats: {total_chats}  "
        f"contacts: {total_contacts}  messages collected: {len(all_messages)}")

    sent_text = [m for m in all_messages if m.get("key", {}).get("fromMe") and m.get("text")]
    if not sent_text:
        log("no sent text messages found "
            "(device may have already drained history — try a freshly paired device)")
        return 0
    last = max(sent_text, key=lambda m: m.get("messageTimestamp", 0))
    ts = last.get("messageTimestamp", 0)
    when = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "?"
    print("\n=== LAST MESSAGE YOU SENT ===")
    print(f"  to:   {last['key'].get('remoteJid')}")
    print(f"  when: {when}")
    print(f"  text: {last.get('text')!r}")

    # a few most-recent sent messages for context
    recent = sorted(sent_text, key=lambda m: m.get("messageTimestamp", 0), reverse=True)[:5]
    print("\n=== your 5 most recent sent texts ===")
    for m in recent:
        print(f"  -> {m['key'].get('remoteJid')}: {m.get('text')!r}")
    return 0


if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("piwapp_send.json")
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
    raise SystemExit(asyncio.run(main(p, secs)))
