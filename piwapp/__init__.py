"""piwapp — async Python reimplementation of the Baileys WhatsApp Web API.

The library is built bottom-up across protocol layers:

* :mod:`piwapp.transport` — WebSocket transport, Noise XX handshake, frame codec.
* :mod:`piwapp.binary` — WABinary node tree encode/decode.
* :mod:`piwapp.crypto` — key utilities, Signal double ratchet, sender keys.
* :mod:`piwapp.auth` — credential models, QR / pairing-code auth, persistence.
* :mod:`piwapp.models` — Pydantic data models (JID, messages, groups, ...).

The headline feature is first-class group chat support (see
:mod:`piwapp.api.groups_extended`).
"""

from __future__ import annotations

__version__ = "0.0.1"

from .auth.creds import AuthenticationCreds
from .client import Client
from .config import ConnectionConfig
from .models.jid import JID
from .socket.connection import Connection, ConnectionState, DisconnectReason

__all__ = [
    "__version__",
    "Client",
    "Connection",
    "ConnectionState",
    "DisconnectReason",
    "ConnectionConfig",
    "AuthenticationCreds",
    "JID",
]
