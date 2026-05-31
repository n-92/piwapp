"""Connection configuration.

Mirrors the relevant parts of Baileys' ``DEFAULT_CONNECTION_CONFIG``. Defaults
match Baileys so the client presents the same identity to WhatsApp's servers.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# Current WA web version (from Baileys baileys-version.json). WhatsApp rejects
# clients it considers too old; bump this if the gateway returns a 4xx failure.
DEFAULT_WA_VERSION: tuple[int, int, int] = (2, 3000, 1035194821)


class ConnectionConfig(BaseModel):
    """Tunable parameters for a WhatsApp connection."""

    version: tuple[int, int, int] = DEFAULT_WA_VERSION
    # (os, browser, os_version) — matches Baileys' Browsers.macOS('Chrome')
    browser: tuple[str, str, str] = ("Mac OS", "Chrome", "10.15.7")
    ws_url: str = "wss://web.whatsapp.com/ws/chat"
    origin: str = "https://web.whatsapp.com"
    country_code: str = "US"

    connect_timeout_ms: int = 20_000
    # WhatsApp's companion idle tolerance is ~30s; a 30s ping races the deadline
    # and the server drops us at ~60s. Ping well under that to stay connected.
    keepalive_interval_ms: int = 20_000
    default_query_timeout_ms: int = 60_000

    sync_full_history: bool = False
    push_name: str | None = None

    # Verify the server's Noise certificate chain during the handshake.
    verify_cert: bool = True

    # Cycle a new QR roughly every this many ms while waiting for a scan.
    qr_timeout_ms: int = 60_000

    @property
    def version_string(self) -> str:
        return ".".join(str(v) for v in self.version)
