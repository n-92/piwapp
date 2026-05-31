"""Connect, drain the offline queue, and report the most recent message YOU sent.

Reads messages that arrive (incl. the offline batch on login, which contains
your own device-synced sent messages) and prints the latest fromMe one.

Usage: python scripts/last_sent.py [auth.json] [collect_seconds]
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
    creds = AuthenticationCreds.from_json(path.read_text())
    client = Client(creds, ConnectionConfig(),
                    on_creds_update=lambda c: path.write_text(c.to_json()),
                    keys_path=str(path) + ".keys")
    online = asyncio.Event()
    sent: list[dict] = []
    received: list[dict] = []

    def on_update(u):
        if u.get("connection") == "open":
            online.set()

    def on_msgs(payload):
        for m in payload.messages:
            (sent if m["key"].get("fromMe") else received).append(m)

    client.on("connection.update", on_update)
    client.events.on(WAEventType.MESSAGES_UPSERT, on_msgs)

    runner = asyncio.create_task(client.start())
    try:
        await asyncio.wait_for(online.wait(), timeout=60)
        log(f"online; collecting messages for {collect:.0f}s (draining offline queue)…")
        await asyncio.sleep(collect)
    except asyncio.TimeoutError:
        log("could not get online"); return 1
    finally:
        await client.stop()
        runner.cancel()

    log(f"captured {len(sent)} sent, {len(received)} received messages")
    sent_text = [m for m in sent if m.get("text")]
    if not sent_text:
        log("no text messages from you in the offline queue "
            "(history sync would be needed for older ones)")
        return 0
    last = max(sent_text, key=lambda m: m.get("messageTimestamp", 0))
    ts = last.get("messageTimestamp", 0)
    when = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "?"
    print("\n=== LAST MESSAGE YOU SENT ===")
    print(f"  to:   {last['key'].get('remoteJid')}")
    print(f"  when: {when}")
    print(f"  text: {last.get('text')!r}")
    return 0


if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("piwapp_send.json")
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 25.0
    raise SystemExit(asyncio.run(main(p, secs)))
