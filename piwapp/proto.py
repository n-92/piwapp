"""Convenience access to the compiled WhatsApp protobuf messages.

The full WAProto is compiled to :mod:`piwapp._proto.WAProto_pb2`. This module
re-exports the handful of messages and enums piwapp uses directly so callers can
write ``from piwapp.proto import HandshakeMessage`` rather than reaching into the
generated module.
"""

from __future__ import annotations

from ._proto import WAProto_pb2 as _wa

# Handshake / connection
HandshakeMessage = _wa.HandshakeMessage
ClientPayload = _wa.ClientPayload
DeviceProps = _wa.DeviceProps
CertChain = _wa.CertChain

# Multi-device pairing
ADVSignedDeviceIdentityHMAC = _wa.ADVSignedDeviceIdentityHMAC
ADVSignedDeviceIdentity = _wa.ADVSignedDeviceIdentity
ADVDeviceIdentity = _wa.ADVDeviceIdentity
ADVEncryptionType = _wa.ADVEncryptionType

# Signal protocol wire messages (libsignal-compatible)
SignalMessage = _wa.SignalMessage
PreKeySignalMessage = _wa.PreKeySignalMessage
SenderKeyMessage = _wa.SenderKeyMessage
SenderKeyDistributionMessage = _wa.SenderKeyDistributionMessage

# Message envelopes (used from Phase 2 onward)
Message = _wa.Message
WebMessageInfo = _wa.WebMessageInfo

# History sync
HistorySync = _wa.HistorySync
Conversation = _wa.Conversation

__all__ = [
    "HandshakeMessage",
    "ClientPayload",
    "DeviceProps",
    "CertChain",
    "ADVSignedDeviceIdentityHMAC",
    "ADVSignedDeviceIdentity",
    "ADVDeviceIdentity",
    "ADVEncryptionType",
    "SignalMessage",
    "PreKeySignalMessage",
    "SenderKeyMessage",
    "SenderKeyDistributionMessage",
    "Message",
    "WebMessageInfo",
    "HistorySync",
    "Conversation",
    "_wa",
]
