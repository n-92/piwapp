"""Event type identifiers and payload models.

``WAEventType`` mirrors Baileys' ``WAEventMap`` keys. Payloads are kept as
light Pydantic models (or plain dicts where flexibility matters) so handlers
get typed, documented data.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field


class WAEventType(str, enum.Enum):
    """Names of emitted events (string values match Baileys for familiarity)."""

    CONNECTION_UPDATE = "connection.update"
    CREDS_UPDATE = "creds.update"

    MESSAGES_UPSERT = "messages.upsert"
    MESSAGES_UPDATE = "messages.update"
    MESSAGES_DELETE = "messages.delete"
    MESSAGE_RECEIPT_UPDATE = "message-receipt.update"
    MESSAGES_REACTION = "messages.reaction"

    PRESENCE_UPDATE = "presence.update"

    CHATS_UPSERT = "chats.upsert"
    CHATS_UPDATE = "chats.update"
    CHATS_DELETE = "chats.delete"

    MESSAGING_HISTORY_SET = "messaging-history.set"

    CONTACTS_UPSERT = "contacts.upsert"
    CONTACTS_UPDATE = "contacts.update"

    GROUPS_UPSERT = "groups.upsert"
    GROUPS_UPDATE = "groups.update"
    GROUP_PARTICIPANTS_UPDATE = "group-participants.update"
    GROUP_JOIN_REQUEST = "group.join-request"

    # piwapp-exclusive group events (Phase 3)
    GROUP_ACTIVITY = "group.activity"
    GROUP_HISTORY_CHANGE = "group.history-change"


class MessageKey(BaseModel):
    """Identifies a single message within a chat."""

    remote_jid: str
    from_me: bool = False
    id: str
    participant: str | None = None


class UpsertType(str, enum.Enum):
    APPEND = "append"
    NOTIFY = "notify"


class MessagesUpsert(BaseModel):
    """Payload for ``messages.upsert``: new/updated messages plus their origin."""

    messages: list[dict[str, Any]] = Field(default_factory=list)
    type: UpsertType = UpsertType.NOTIFY


class GroupParticipantsUpdate(BaseModel):
    """Payload for ``group-participants.update``."""

    jid: str
    participants: list[str] = Field(default_factory=list)
    action: str  # add | remove | promote | demote
    author: str | None = None
