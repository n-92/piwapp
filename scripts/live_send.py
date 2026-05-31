"""Live 1:1 send test: connect, wait online, send a text, report.

Usage: python scripts/live_send.py <auth.json> <recipient_number> <text>
  recipient_number: digits only, e.g. 447000000000
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

from piwapp.auth.creds import AuthenticationCreds
from piwapp.client import Client
from piwapp.config import ConnectionConfig

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


async def main(path: Path, number: str, text: str) -> int:
    from piwapp.auth.qr import save_qr_png
    if path.exists():
        creds = AuthenticationCreds.from_json(path.read_text())
    else:
        creds = AuthenticationCreds.initial()
        path.write_text(creds.to_json())
    keys_path = path.with_suffix(path.suffix + ".keys")
    client = Client(creds, ConnectionConfig(),
                    on_creds_update=lambda c: path.write_text(c.to_json()),
                    keys_path=keys_path)
    online = asyncio.Event()

    def on_update(u: dict) -> None:
        if "qr" in u:
            png = save_qr_png(u["qr"], "piwapp_qr.png")
            log(f"SCAN QR: {Path(png).resolve()}")
        if u.get("connection") == "open":
            online.set()
        if u.get("connection") == "close" and u.get("logged_out"):
            log("logged out", u.get("reason"))
            online.set()

    client.on("connection.update", on_update)
    runner = asyncio.create_task(client.start())
    try:
        await asyncio.wait_for(online.wait(), timeout=150)  # generous for QR scan
        if not client.is_open:
            log("not online; aborting")
            return 1
        # let post-login settle (pre-keys, init queries)
        await asyncio.sleep(3)
        to_jid = f"{number}@s.whatsapp.net"
        log(f"sending to {to_jid}: {text!r}")
        try:
            msg_id = await client.send_text(to_jid, text)
            log(f"SENT id={msg_id} — check the recipient device")
        except Exception as exc:
            log(f"SEND FAILED: {exc!r}")
            import traceback
            traceback.print_exc()
        await asyncio.sleep(4)  # allow server ack
    finally:
        await client.stop()
        runner.cancel()
    return 0


if __name__ == "__main__":
    p = Path(sys.argv[1])
    raise SystemExit(asyncio.run(main(p, sys.argv[2], sys.argv[3])))
