"""The :class:`JID` Pydantic model — a typed wrapper over the low-level helpers.

This is the application-facing JID representation. It wraps the byte-exact
parsing/formatting in :mod:`piwapp.binary.jids` and adds convenience predicates
and validation.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from ..binary import jids as _j


class JID(BaseModel):
    """A parsed WhatsApp JID (``user`` [``:device``] ``@`` ``server``)."""

    model_config = ConfigDict(frozen=True)

    user: str
    server: str
    device: int | None = None
    domain_type: int = int(_j.WAJIDDomain.WHATSAPP)

    # -- construction ----------------------------------------------------
    @classmethod
    def parse(cls, jid: str) -> "JID":
        """Parse a JID string, raising :class:`ValueError` on malformed input."""
        decoded = _j.jid_decode(jid)
        if decoded is None:
            raise ValueError(f"invalid JID: {jid!r}")
        return cls(
            user=decoded.user,
            server=decoded.server,
            device=decoded.device,
            domain_type=decoded.domain_type,
        )

    @classmethod
    def try_parse(cls, jid: str | None) -> "JID | None":
        """Like :meth:`parse` but returns ``None`` instead of raising."""
        decoded = _j.jid_decode(jid)
        if decoded is None:
            return None
        return cls(
            user=decoded.user,
            server=decoded.server,
            device=decoded.device,
            domain_type=decoded.domain_type,
        )

    # -- formatting ------------------------------------------------------
    def __str__(self) -> str:
        return _j.jid_encode(self.user, self.server, self.device)

    @property
    def normalized(self) -> str:
        """Canonical ``user@server`` form (``c.us`` mapped to ``s.whatsapp.net``)."""
        return _j.jid_normalized_user(str(self))

    # -- predicates ------------------------------------------------------
    @property
    def is_group(self) -> bool:
        return self.server == "g.us"

    @property
    def is_user(self) -> bool:
        return self.server in ("s.whatsapp.net", "c.us")

    @property
    def is_lid(self) -> bool:
        return self.server == "lid"

    @property
    def is_broadcast(self) -> bool:
        return self.server == "broadcast"

    @property
    def is_newsletter(self) -> bool:
        return self.server == "newsletter"

    @property
    def is_status_broadcast(self) -> bool:
        return self.user == "status" and self.server == "broadcast"

    def same_user(self, other: "JID | str") -> bool:
        """True if ``other`` refers to the same user (ignoring device/server)."""
        other_str = other if isinstance(other, str) else str(other)
        return _j.are_jids_same_user(str(self), other_str)
