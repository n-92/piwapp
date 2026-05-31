"""Live receive listener for debugging inbound messages.

Connects with an existing auth file, uploads pre-keys, and stays connected for a
fixed duration logging every frame and message. Does NOT persist creds (keeps
the on-disk session pristine). Run with PIWAPP_DEBUG=1 to also get read-loop
decode diagnostics. Output is line-flushed so the log can be tailed live.
"""

from __future__ import annotations

import asyncio
import sys
import time
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


def log(*args) -> None:
    print(f"[{time.strftime('%H:%M:%S')}]", *args, flush=True)


async def main(path: Path, duration: float) -> int:
    creds = AuthenticationCreds.from_json(path.read_text())
    client = Client(creds, ConnectionConfig())  # default 20s keepalive; pristine creds

    def on_update(u: dict) -> None:
        if u.get("connection") == "open":
            log("ONLINE as", (u.get("me") or {}).get("id"))
        if u.get("connection") == "close":
            log("CLOSED reason", u.get("reason"))

    def on_prekeys(p):
        log(f"PREKEYS UPLOADED ({p['count']}) — *** READY TO RECEIVE, SEND NOW ***")

    def on_prekeys_err(p):
        log("PREKEYS ERROR", p.get("error"))

    def on_frame(node):
        # every decoded node that reached routing
        kids = node.children()
        first = kids[0].tag if kids else ""
        log(f"FRAME <{node.tag}> attrs={node.attrs} first_child={first!r}")

    def on_msgs(p):
        for m in p.messages:
            who = m["key"].get("participant") or m["key"]["remoteJid"]
            log(f"💬 MESSAGE from {who}: {m.get('text')!r}")

    def on_msg_update(p):
        if isinstance(p, dict) and p.get("decryptError"):
            log("⚠ DECRYPT ERROR:", p.get("decryptError"))

    client.on("connection.update", on_update)
    client.on("prekeys.uploaded", on_prekeys)
    client.on("prekeys.error", on_prekeys_err)
    client.on("frame", on_frame)
    client.events.on(WAEventType.MESSAGES_UPSERT, on_msgs)
    client.events.on(WAEventType.MESSAGES_UPDATE, on_msg_update)

    log(f"connecting (listening for {duration:.0f}s)…")
    runner = asyncio.create_task(client.start())
    try:
        await asyncio.sleep(duration)
    finally:
        log("stopping…")
        await client.stop()
        runner.cancel()
    return 0


if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("piwapp_auth.json")
    d = float(sys.argv[2]) if len(sys.argv) > 2 else 300.0
    raise SystemExit(asyncio.run(main(p, d)))
