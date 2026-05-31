"""Message content models and conversions to/from the WAProto ``Message``.

Phase 2 covers text (the most common case); richer content types (media,
reactions, etc.) extend ``to_message_proto`` / ``extract_text`` later.
"""

from __future__ import annotations

from pydantic import BaseModel

from .. import proto


class TextContent(BaseModel):
    """A plain text message."""

    text: str


MessageContent = TextContent


def to_message_proto(content: "MessageContent | str") -> "proto.Message":
    """Convert a content model (or bare string) into a WAProto ``Message``."""
    if isinstance(content, str):
        content = TextContent(text=content)
    if isinstance(content, TextContent):
        return proto.Message(conversation=content.text)
    raise TypeError(f"unsupported message content: {type(content)}")


def extract_text(message: "proto.Message") -> str | None:
    """Pull displayable text from a decoded ``Message`` (text or media caption)."""
    if message.HasField("conversation"):
        return message.conversation
    if message.HasField("extendedTextMessage"):
        return message.extendedTextMessage.text
    # media captions (image/video/document carry a caption field)
    for field in ("imageMessage", "videoMessage", "documentMessage"):
        try:
            if message.HasField(field):
                return getattr(message, field).caption or None
        except ValueError:
            continue
    return None
