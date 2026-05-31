"""Live-verify media send: pair (QR), then send a test image to a chat.

Usage: python scripts/live_media.py [auth.json] [target_jid] [image_path]
Defaults: piwapp_mcp.json, the Test group, an auto-generated PNG.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

from piwapp.auth.creds import AuthenticationCreds
from piwapp.auth.qr import render_qr_terminal, save_qr_png
from piwapp.client import Client
from piwapp.config import ConnectionConfig

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

TEST_GROUP = "120363425371857405@g.us"


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


def make_test_png(path: Path) -> None:
    """Generate a small labelled PNG so the send is visually identifiable."""
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (480, 240), (18, 140, 126))
    d = ImageDraw.Draw(img)
    d.rectangle([10, 10, 470, 230], outline=(255, 255, 255), width=4)
    d.text((40, 90), f"piwapp media test\n{time.strftime('%H:%M:%S')}", fill=(255, 255, 255))
    img.save(path, "PNG")


async def main(path: Path, target: str, img_path: Path) -> int:
    if not img_path.exists():
        make_test_png(img_path)
        log(f"generated test image: {img_path.resolve()}")

    if path.exists():
        creds = AuthenticationCreds.from_json(path.read_text())
    else:
        creds = AuthenticationCreds.initial()
        path.write_text(creds.to_json())

    client = Client(creds, ConnectionConfig(),
                    on_creds_update=lambda c: path.write_text(c.to_json()),
                    keys_path=str(path) + ".keys", db_path=str(path) + ".db")
    online = asyncio.Event()

    def on_update(u: dict) -> None:
        if "qr" in u:
            png = save_qr_png(u["qr"], "piwapp_qr.png")
            log("SCAN QR (terminal below, or open the image):", Path(png).resolve())
            print(render_qr_terminal(u["qr"]), flush=True)
        if u.get("connection") == "open":
            online.set()

    client.on("connection.update", on_update)
    runner = asyncio.create_task(client.start())
    try:
        await asyncio.wait_for(online.wait(), timeout=120)
        log(f"online as {client.creds.me.id if client.creds.me else '?'}")
        data = img_path.read_bytes()
        log(f"sending {len(data)} bytes to {target} …")
        mid = await client.send_media(target, data, mimetype="image/png",
                                      caption="📷 piwapp media test")
        log(f"SENT image, message id = {mid}")
        await asyncio.sleep(3)  # let the upload/relay settle
        return 0
    except asyncio.TimeoutError:
        log("could not get online (no scan?)")
        return 1
    finally:
        await client.stop()
        runner.cancel()


if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("piwapp_mcp.json")
    tgt = sys.argv[2] if len(sys.argv) > 2 else TEST_GROUP
    img = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("media_test.png")
    raise SystemExit(asyncio.run(main(p, tgt, img)))
