"""The :class:`BinaryNode` — the in-memory representation of a WABinary element.

WhatsApp's wire protocol is an XMPP-like tree of nodes. Each node has a string
``tag``, a string→string ``attrs`` map, and ``content`` that is either raw
``bytes``, a list of child nodes, or ``None``.

Mirrors Baileys' ``BinaryNode`` interface in ``WABinary/types.ts``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Union

NodeContent = Union[str, bytes, list["BinaryNode"], None]


@dataclass(slots=True)
class BinaryNode:
    """A single node in a WABinary tree."""

    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    content: NodeContent = None

    # -- attribute access ------------------------------------------------
    def attr(self, key: str, default: str | None = None) -> str | None:
        """Return attribute ``key`` or ``default`` when missing."""
        return self.attrs.get(key, default)

    # -- child access ----------------------------------------------------
    def children(self) -> list["BinaryNode"]:
        """Return child nodes, or an empty list when content is not a list."""
        return self.content if isinstance(self.content, list) else []

    def get_child(self, tag: str) -> "BinaryNode | None":
        """Return the first direct child with ``tag``, or ``None``."""
        for child in self.children():
            if child.tag == tag:
                return child
        return None

    def get_children(self, tag: str | None = None) -> list["BinaryNode"]:
        """Return direct children matching ``tag`` (all children if ``None``)."""
        kids = self.children()
        if tag is None:
            return list(kids)
        return [c for c in kids if c.tag == tag]

    def iter_children(self, tag: str | None = None) -> Iterator["BinaryNode"]:
        """Iterate over direct children, optionally filtered by ``tag``."""
        for child in self.children():
            if tag is None or child.tag == tag:
                yield child

    # -- content helpers -------------------------------------------------
    @property
    def content_bytes(self) -> bytes | None:
        """Return content as bytes when it is a byte payload, else ``None``."""
        return self.content if isinstance(self.content, bytes) else None

    def to_debug(self) -> dict:
        """Return a plain-dict view useful for logging and assertions."""
        if isinstance(self.content, list):
            content: object = [c.to_debug() for c in self.content]
        elif isinstance(self.content, (bytes, bytearray)):
            content = f"<{len(self.content)} bytes>"
        else:
            content = None
        return {"tag": self.tag, "attrs": dict(self.attrs), "content": content}
