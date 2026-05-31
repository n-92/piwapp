"""Weather bot: post current weather to a WhatsApp group on a fixed interval.

Uses wttr.in (no API key) for the weather and piwapp to send it.

Usage:
  python scripts/weather_bot.py [auth.json] [city] [group] [interval_seconds]

Defaults: piwapp_send.json, "Manchester", "Test group", 300 (5 min).
  - <group> may be a full JID (...@g.us) or a substring of the group's subject.
  - For a quick try, pass a smaller interval, e.g. 60.

Ctrl+C to stop.
"""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import datetime
from pathlib import Path

import aiohttp

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


async def get_weather(city: str) -> str:
    """Fetch a one-line weather summary from wttr.in (curl UA -> plain text)."""
    fmt = "%l:+%c+%C,+%t+(feels+%f),+humidity+%h,+wind+%w"
    url = f"https://wttr.in/{city}?format={fmt}"
    try:
        async with aiohttp.ClientSession(headers={"User-Agent": "curl/8"}) as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                text = (await r.text()).strip()
        # wttr returns the format string back on bad input; basic sanity check
        if not text or "Unknown location" in text:
            return f"{city}: weather unavailable right now"
        return text
    except Exception as exc:
        return f"{city}: weather fetch failed ({exc})"


async def resolve_group(client: Client, group: str) -> str | None:
    if group.endswith("@g.us"):
        return group
    groups = await client.fetch_groups()
    for g in groups:
        if group.lower() in (g.get("subject") or "").lower():
            log(f"matched group {g['id']} ({g.get('subject')!r})")
            return g["id"]
    log(f"no group matching {group!r}; available: "
        + ", ".join(repr(g.get("subject")) for g in groups))
    return None


async def wait_online(client: Client, online: asyncio.Event, timeout: float = 60) -> bool:
    if client.is_open:
        return True
    online.clear()
    try:
        await asyncio.wait_for(online.wait(), timeout)
    except asyncio.TimeoutError:
        return False
    return client.is_open


async def main(path: Path, city: str, group: str, interval: float) -> int:
    creds = AuthenticationCreds.from_json(path.read_text())
    client = Client(creds, ConnectionConfig(),
                    on_creds_update=lambda c: path.write_text(c.to_json()),
                    keys_path=str(path) + ".keys")
    online = asyncio.Event()

    def on_update(u: dict) -> None:
        if u.get("connection") == "open":
            online.set()
        if u.get("connection") == "close" and u.get("logged_out"):
            log("logged out:", u.get("reason"))

    client.on("connection.update", on_update)
    runner = asyncio.create_task(client.start())

    try:
        if not await wait_online(client, online):
            log("could not get online"); return 1
        await asyncio.sleep(3)  # let post-login settle

        group_jid = await resolve_group(client, group)
        if not group_jid:
            return 1
        log(f"weather bot running: city={city!r} group={group_jid} every {interval:.0f}s "
            f"(Ctrl+C to stop)")

        while True:
            if not await wait_online(client, online, timeout=120):
                log("offline; will retry next tick"); await asyncio.sleep(interval); continue
            weather = await get_weather(city)
            stamp = datetime.now().strftime("%H:%M")
            text = f"🌤️ Weather @ {stamp}\n{weather}"
            try:
                await client.send_text(group_jid, text)
                log("sent:", weather)
            except Exception as exc:
                log("send failed:", repr(exc))
            await asyncio.sleep(interval)
    except (KeyboardInterrupt, asyncio.CancelledError):
        log("stopping")
    finally:
        await client.stop()
        runner.cancel()
    return 0


if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("piwapp_send.json")
    city = sys.argv[2] if len(sys.argv) > 2 else "Aberdeen"
    grp = sys.argv[3] if len(sys.argv) > 3 else "Test group"
    iv = float(sys.argv[4]) if len(sys.argv) > 4 else 300.0
    raise SystemExit(asyncio.run(main(p, city, grp, iv)))
