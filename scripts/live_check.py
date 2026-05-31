"""Bounded live check against the real WhatsApp gateway.

Connects using an existing auth file, confirms login (<success>) and that the
pre-key upload IQ is accepted, then disconnects. Does NOT write creds back, so
the on-disk session is left untouched (the in-memory pre-keys are discarded;
the server-side batch is harmlessly overwritten on the next real run).

Usage:  python scripts/live_check.py [auth.json] [timeout_seconds]
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from piwapp.auth.creds import AuthenticationCreds
from piwapp.client import Client
from piwapp.config import ConnectionConfig
from piwapp.events import WAEventType


async def main(path: Path, timeout: float) -> int:
    creds = AuthenticationCreds.from_json(path.read_text())
    # NOTE: on_creds_update intentionally omitted -> nothing is persisted.
    client = Client(creds, ConnectionConfig())
    done = asyncio.Event()
    result = {"open": False, "prekeys": None, "msgs": 0, "closed": None}

    async def on_update(u: dict) -> None:
        if u.get("connection") == "open":
            result["open"] = True
            print(f"  online as {(u.get('me') or {}).get('id')}")
        if u.get("connection") == "close":
            result["closed"] = u.get("reason")
            done.set()

    def on_prekeys(p):
        result["prekeys"] = p.get("count")
        print(f"  pre-keys uploaded: {p.get('count')}")
        done.set()

    def on_prekeys_err(p):
        result["prekeys"] = f"ERROR: {p.get('error')}"
        print(f"  pre-key upload error: {p.get('error')}")
        done.set()

    def on_msgs(p):
        result["msgs"] += len(p.messages)
        for m in p.messages:
            print(f"  💬 {m['key'].get('participant') or m['key']['remoteJid']}: {m.get('text')}")

    client.on("connection.update", on_update)
    client.on("prekeys.uploaded", on_prekeys)
    client.on("prekeys.error", on_prekeys_err)
    client.events.on(WAEventType.MESSAGES_UPSERT, on_msgs)

    runner = asyncio.create_task(client.start())
    try:
        await asyncio.wait_for(done.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        print("  (timeout waiting for result)")
    finally:
        await client.stop()
        runner.cancel()

    print(f"\nRESULT: open={result['open']} prekeys={result['prekeys']} "
          f"msgs={result['msgs']} closed_reason={result['closed']}")
    return 0 if result["open"] else 1


if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("piwapp_auth.json")
    t = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
    raise SystemExit(asyncio.run(main(p, t)))
