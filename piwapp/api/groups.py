"""Group metadata query/parse (subset needed for group send).

Fetches a group's participant list and addressing mode via the ``w:g2``
interactive query. The full rich group-metadata model + management APIs are a
later phase; this provides what group send needs.
"""

from __future__ import annotations

from ..binary import BinaryNode

S_WHATSAPP_NET = "@s.whatsapp.net"


def build_group_metadata_query(group_jid: str, sid: str) -> BinaryNode:
    return BinaryNode(
        tag="iq",
        attrs={"to": group_jid, "type": "get", "xmlns": "w:g2", "id": sid},
        content=[BinaryNode(tag="query", attrs={"request": "interactive"})],
    )


def build_list_groups_query(sid: str) -> BinaryNode:
    """Query all groups this account participates in."""
    return BinaryNode(
        tag="iq",
        attrs={"to": "@g.us", "type": "get", "xmlns": "w:g2", "id": sid},
        content=[BinaryNode(tag="participating", content=[
            BinaryNode(tag="participants"), BinaryNode(tag="description")])],
    )


def parse_groups_list(result: BinaryNode) -> list[dict]:
    """Parse a participating-groups result into a list of group summaries."""
    groups_node = result.get_child("groups")
    if groups_node is None:
        return []
    out = []
    for g in groups_node.get_children("group"):
        gid = g.attrs.get("id", "")
        if gid and not gid.endswith("@g.us"):
            gid = gid + "@g.us"
        out.append({
            "id": gid,
            "subject": g.attrs.get("subject"),
            "addressing_mode": g.attrs.get("addressing_mode", "pn"),
            "size": g.attrs.get("size"),
        })
    return out


def parse_group_metadata(result: BinaryNode) -> dict:
    """Return ``{id, addressing_mode, subject, participants[], admins[]}``."""
    group = result.get_child("group")
    if group is None:
        raise ValueError("group metadata: missing <group> node")
    addressing = group.attrs.get("addressing_mode", "pn")
    participants: list[str] = []
    admins: list[str] = []
    for p in group.get_children("participant"):
        jid = p.attrs.get("jid")
        if not jid:
            continue
        participants.append(jid)
        if p.attrs.get("type") in ("admin", "superadmin"):
            admins.append(jid)
    return {
        "id": group.attrs.get("id", ""),
        "addressing_mode": addressing,
        "subject": group.attrs.get("subject"),
        "participants": participants,
        "admins": admins,
    }
