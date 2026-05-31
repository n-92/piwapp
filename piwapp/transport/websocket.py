"""Async WebSocket transport to the WhatsApp Web gateway.

Thin wrapper over the :mod:`websockets` client that opens the connection with
the required ``Origin`` header and exposes raw binary send/receive. Protocol
framing and encryption live in :mod:`piwapp.transport.framing` and
:mod:`piwapp.transport.noise`; this layer only moves bytes.

Application-level keepalive (the WA ``?,,`` ping) is handled by the connection
layer, so the WebSocket's own ping is disabled to avoid interference.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import websockets
from websockets.asyncio.client import ClientConnection

DEFAULT_WA_WS_URL = "wss://web.whatsapp.com/ws/chat"
DEFAULT_ORIGIN = "https://web.whatsapp.com"


class TransportClosed(Exception):
    """Raised when sending on / receiving from a closed transport."""


class WATransport:
    """Minimal async WebSocket client for the WhatsApp gateway."""

    def __init__(
        self,
        url: str = DEFAULT_WA_WS_URL,
        origin: str = DEFAULT_ORIGIN,
        *,
        open_timeout: float = 20.0,
    ) -> None:
        self._url = url
        self._origin = origin
        self._open_timeout = open_timeout
        self._ws: ClientConnection | None = None

    async def connect(self) -> None:
        """Open the WebSocket connection."""
        self._ws = await websockets.connect(
            self._url,
            additional_headers={"Origin": self._origin},
            open_timeout=self._open_timeout,
            ping_interval=None,  # WA uses app-level keepalive instead
            max_size=2**24,
        )

    async def send(self, data: bytes) -> None:
        """Send a binary frame."""
        if self._ws is None:
            raise TransportClosed("transport not connected")
        try:
            await self._ws.send(data)
        except websockets.ConnectionClosed as exc:  # pragma: no cover - network
            raise TransportClosed(str(exc)) from exc

    async def recv(self) -> bytes:
        """Receive the next binary frame (raises :class:`TransportClosed` on EOF)."""
        if self._ws is None:
            raise TransportClosed("transport not connected")
        try:
            data = await self._ws.recv()
        except websockets.ConnectionClosed as exc:
            raise TransportClosed(str(exc)) from exc
        return data if isinstance(data, bytes) else data.encode()

    async def messages(self) -> AsyncIterator[bytes]:
        """Yield inbound binary frames until the socket closes."""
        if self._ws is None:
            raise TransportClosed("transport not connected")
        try:
            async for data in self._ws:
                yield data if isinstance(data, bytes) else data.encode()
        except websockets.ConnectionClosed:
            return

    async def close(self) -> None:
        """Close the WebSocket connection."""
        if self._ws is not None:
            await self._ws.close()
            self._ws = None

    @property
    def is_open(self) -> bool:
        return self._ws is not None

    @property
    def close_code(self) -> int | None:
        return getattr(self._ws, "close_code", None) if self._ws else None

    @property
    def close_reason(self) -> str | None:
        return getattr(self._ws, "close_reason", None) if self._ws else None
