"""Live handshake against the real WhatsApp Web gateway.

Gated behind ``PIWAPP_TEST_REAL=1`` (and network access). Receiving a QR
``pair-device`` node proves the entire transport + Noise handshake +
certificate verification + registration ClientPayload path interoperates with
the real service. The only thing left for a full login is a phone scanning the
QR, which this test does not do.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from piwapp.auth.creds import AuthenticationCreds
from piwapp.config import ConnectionConfig
from piwapp.socket.connection import Connection

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        os.environ.get("PIWAPP_TEST_REAL") != "1",
        reason="set PIWAPP_TEST_REAL=1 to run live WhatsApp handshake",
    ),
]


async def test_real_handshake_receives_qr():
    creds = AuthenticationCreds.initial()
    conn = Connection(creds, ConnectionConfig())  # verify_cert=True by default

    got_qr = asyncio.Event()
    captured: dict = {}

    async def on_update(u: dict) -> None:
        if "qr" in u:
            captured["qr"] = u["qr"]
            got_qr.set()

    conn.ev.on("connection.update", on_update)

    await conn.connect()
    try:
        await asyncio.wait_for(got_qr.wait(), timeout=30)
    finally:
        await conn.close()

    # QR payload is "ref,noiseB64,identityB64,advB64"
    assert captured["qr"].count(",") == 3
