"""Live group send test: connect, list groups, send to one.

Usage:
  python scripts/live_group.py <auth.json>                 # just list groups
  python scripts/live_group.py <auth.json> <group_jid> <text>   # send to a group
  python scripts/live_group.py <auth.json> "<subject substr>" <text>  # match by name
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


async def main(path: Path, target: str | None, text: str | None) -> int:
    creds = AuthenticationCreds.from_json(path.read_text())
    client = Client(creds, ConnectionConfig(),
                    on_creds_update=lambda c: path.write_text(c.to_json()),
                    keys_path=str(path) + ".keys")
    online = asyncio.Event()
    client.on("connection.update",
              lambda u: online.set() if u.get("connection") in ("open", "close") else None)

    runner = asyncio.create_task(client.start())
    try:
        await asyncio.wait_for(online.wait(), timeout=60)
        if not client.is_open:
            log("not online"); return 1
        await asyncio.sleep(3)

        groups = await client.fetch_groups()
        log(f"found {len(groups)} groups:")
        for g in groups:
            log(f"   {g['id']}  subject={g.get('subject')!r}  mode={g.get('addressing_mode')}")

        if target and text:
            gid = target
            if not target.endswith("@g.us"):
                match = [g for g in groups if target.lower() in (g.get("subject") or "").lower()]
                if not match:
                    log(f"no group matching {target!r}"); return 1
                gid = match[0]["id"]
                log(f"matched group {gid} ({match[0].get('subject')!r})")
            log(f"sending to {gid}: {text!r}")
            try:
                msg_id = await client.send_group_text(gid, text)
                log(f"SENT id={msg_id} — check the group")
            except Exception as exc:
                log(f"SEND FAILED: {exc!r}")
                import traceback
                traceback.print_exc()
            await asyncio.sleep(4)
    finally:
        await client.stop()
        runner.cancel()
    return 0


if __name__ == "__main__":
    p = Path(sys.argv[1])
    tgt = sys.argv[2] if len(sys.argv) > 2 else None
    txt = sys.argv[3] if len(sys.argv) > 3 else None
    raise SystemExit(asyncio.run(main(p, tgt, txt)))
