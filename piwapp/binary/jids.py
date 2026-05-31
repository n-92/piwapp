"""Low-level JID (Jabber ID) helpers.

Direct port of Baileys' ``WABinary/jid-utils.ts``. These functions are used by
the binary codec (to decide whether a string should be encoded as a JID pair)
and by the richer :class:`piwapp.models.jid.JID` Pydantic model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum

S_WHATSAPP_NET = "@s.whatsapp.net"
OFFICIAL_BIZ_JID = "16505361212@c.us"
SERVER_JID = "server@c.us"
PSA_WID = "0@c.us"
STORIES_JID = "status@broadcast"
META_AI_JID = "13135550002@c.us"


class WAJIDDomain(IntEnum):
    """Domain-type byte used in the AD_JID wire encoding."""

    WHATSAPP = 0
    LID = 1
    HOSTED = 128
    HOSTED_LID = 129


@dataclass(slots=True)
class FullJid:
    """Decomposed JID: ``user`` (+ optional ``device``) ``@`` ``server``."""

    user: str
    server: str
    device: int | None = None
    domain_type: int = WAJIDDomain.WHATSAPP


def server_from_domain_type(initial_server: str, domain_type: int | None) -> str:
    """Resolve the textual server for a numeric ``domain_type``."""
    if domain_type == WAJIDDomain.LID:
        return "lid"
    if domain_type == WAJIDDomain.HOSTED:
        return "hosted"
    if domain_type == WAJIDDomain.HOSTED_LID:
        return "hosted.lid"
    return initial_server


def jid_encode(
    user: str | int | None,
    server: str,
    device: int | None = None,
    agent: int | None = None,
) -> str:
    """Compose a JID string from its parts (mirror of ``jidEncode``)."""
    agent_part = f"_{agent}" if agent else ""
    device_part = f":{device}" if device else ""
    return f"{user or ''}{agent_part}{device_part}@{server}"


def jid_decode(jid: str | None) -> FullJid | None:
    """Parse a JID string into a :class:`FullJid` (mirror of ``jidDecode``)."""
    if not isinstance(jid, str):
        return None
    sep_idx = jid.find("@")
    if sep_idx < 0:
        return None

    server = jid[sep_idx + 1 :]
    user_combined = jid[:sep_idx]

    # mirror Baileys: split on ':' (device) and '_' (agent), taking the 2nd part
    ua_parts = user_combined.split(":")
    user_agent = ua_parts[0]
    device_str = ua_parts[1] if len(ua_parts) > 1 else ""
    u_parts = user_agent.split("_")
    user = u_parts[0]
    agent = u_parts[1] if len(u_parts) > 1 else ""

    domain_type = WAJIDDomain.WHATSAPP
    if server == "lid":
        domain_type = WAJIDDomain.LID
    elif server == "hosted":
        domain_type = WAJIDDomain.HOSTED
    elif server == "hosted.lid":
        domain_type = WAJIDDomain.HOSTED_LID
    elif agent:
        domain_type = _safe_int(agent, default=WAJIDDomain.WHATSAPP)

    return FullJid(
        user=user,
        server=server,
        device=_safe_int(device_str, default=None) if device_str else None,
        domain_type=int(domain_type),
    )


def _safe_int(value: str, default):
    """Parse ``value`` as int, returning ``default`` on non-numeric input (JS parseInt-ish)."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


# -- predicates ----------------------------------------------------------
def are_jids_same_user(jid1: str | None, jid2: str | None) -> bool:
    """True if both JIDs share the same ``user`` part."""
    d1, d2 = jid_decode(jid1), jid_decode(jid2)
    return d1 is not None and d2 is not None and d1.user == d2.user


def is_jid_meta_ai(jid: str | None) -> bool:
    return bool(jid) and jid.endswith("@bot")  # type: ignore[union-attr]


def is_pn_user(jid: str | None) -> bool:
    return bool(jid) and jid.endswith("@s.whatsapp.net")  # type: ignore[union-attr]


def is_lid_user(jid: str | None) -> bool:
    return bool(jid) and jid.endswith("@lid")  # type: ignore[union-attr]


def is_jid_broadcast(jid: str | None) -> bool:
    return bool(jid) and jid.endswith("@broadcast")  # type: ignore[union-attr]


def is_jid_group(jid: str | None) -> bool:
    return bool(jid) and jid.endswith("@g.us")  # type: ignore[union-attr]


def is_jid_status_broadcast(jid: str) -> bool:
    return jid == "status@broadcast"


def is_jid_newsletter(jid: str | None) -> bool:
    return bool(jid) and jid.endswith("@newsletter")  # type: ignore[union-attr]


def is_hosted_pn_user(jid: str | None) -> bool:
    return bool(jid) and jid.endswith("@hosted")  # type: ignore[union-attr]


def is_hosted_lid_user(jid: str | None) -> bool:
    return bool(jid) and jid.endswith("@hosted.lid")  # type: ignore[union-attr]


_BOT_RE = re.compile(r"^1313555\d{4}$|^131655500\d{2}$")


def is_jid_bot(jid: str | None) -> bool:
    if not jid:
        return False
    return bool(_BOT_RE.match(jid.split("@")[0])) and jid.endswith("@c.us")


def jid_normalized_user(jid: str | None) -> str:
    """Return the canonical ``user@server`` form (``c.us`` → ``s.whatsapp.net``)."""
    result = jid_decode(jid)
    if not result:
        return ""
    server = "s.whatsapp.net" if result.server == "c.us" else result.server
    return jid_encode(result.user, server)


def transfer_device(from_jid: str, to_jid: str) -> str:
    """Copy the device id of ``from_jid`` onto the user/server of ``to_jid``."""
    from_decoded = jid_decode(from_jid)
    device_id = from_decoded.device if from_decoded else 0
    to_decoded = jid_decode(to_jid)
    assert to_decoded is not None
    return jid_encode(to_decoded.user, to_decoded.server, device_id)
