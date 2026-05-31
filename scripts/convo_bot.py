"""Live conversation relay for the Test group.

One socket (reuses the paired device). It:
  * appends incoming Test-group messages to convo_in.log
  * watches convo_out.txt; when non-empty, sends its contents to the group
    and clears it.

Usage: python scripts/convo_bot.py [auth.json] [group_jid]
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

TEST_GROUP = "120363425371857405@g.us"
IN_LOG = Path("convo_in.log")
OUT_FILE = Path("convo_out.txt")
OUT_IMG = Path("convo_out_img.txt")  # line1=file path, line2(optional)=caption


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


async def main(path: Path, group: str) -> int:
    creds = AuthenticationCreds.from_json(path.read_text())
    client = Client(creds, ConnectionConfig(),
                    on_creds_update=lambda c: path.write_text(c.to_json()),
                    keys_path=str(path) + ".keys", db_path=str(path) + ".db")
    online = asyncio.Event()
    OUT_FILE.write_text("")  # start with an empty outbox

    def on_update(u: dict) -> None:
        if u.get("connection") == "open":
            online.set()

    def on_msg(payload) -> None:
        for m in payload.messages:
            key = m.get("key", {})
            if key.get("remoteJid") != group or key.get("fromMe"):
                continue
            who = m.get("pushName") or key.get("participant") or "?"
            text = m.get("text")
            media = m.get("media")
            line = f"[{time.strftime('%H:%M:%S')}] {who}: " + (
                text if text else (f"<{media['type']}>" if media else "<non-text>"))
            with IN_LOG.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            log("IN ", line)

    client.on("connection.update", on_update)
    client.events.on(WAEventType.MESSAGES_UPSERT, on_msg)

    runner = asyncio.create_task(client.start())
    try:
        await asyncio.wait_for(online.wait(), timeout=60)
    except asyncio.TimeoutError:
        log("could not get online"); return 1
    log(f"online as {client.creds.me.id}; listening on {group}")
    log(f"  inbox  -> {IN_LOG.resolve()}")
    log(f"  outbox -> {OUT_FILE.resolve()} (write a line here to send it)")

    # outbox watcher: send any queued lines, then clear
    try:
        while True:
            await asyncio.sleep(1.0)
            try:
                content = OUT_FILE.read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                content = ""
            if content:
                OUT_FILE.write_text("")  # clear first to avoid double-send
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        mid = await client.send_text(group, line)
                        log("OUT", f"sent {mid}: {line}")
                    except Exception as e:
                        log("OUT-ERR", repr(e))

            # media outbox: line1 = path, line2 (optional) = caption
            try:
                img = OUT_IMG.read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                img = ""
            if img:
                OUT_IMG.write_text("")
                parts = img.splitlines()
                fpath = parts[0].strip()
                caption = parts[1].strip() if len(parts) > 1 else None
                try:
                    mid = await client.send_file(group, fpath, caption=caption)
                    log("OUT-IMG", f"sent {mid}: {fpath} ({caption})")
                except Exception as e:
                    log("OUT-IMG-ERR", repr(e))
    finally:
        await client.stop()
        runner.cancel()


if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("piwapp_mcp.json")
    g = sys.argv[2] if len(sys.argv) > 2 else TEST_GROUP
    raise SystemExit(asyncio.run(main(p, g)))
