"""WABinary codec round-trip and token-table tests."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from piwapp.binary import (
    BinaryNode,
    WABinaryError,
    decode_binary_node,
    encode_binary_node,
)
from piwapp.binary.tokens import (
    DOUBLE_BYTE_TOKENS,
    SINGLE_BYTE_TOKENS,
    TOKEN_MAP,
)


def _normalize(node: BinaryNode):
    content = node.content
    if isinstance(content, (bytes, bytearray)):
        content = ("bytes", bytes(content))
    elif isinstance(content, list):
        content = [_normalize(c) for c in content]
    return (node.tag, dict(node.attrs), content)


def roundtrip(node: BinaryNode) -> BinaryNode:
    return decode_binary_node(encode_binary_node(node))


def test_token_table_shapes():
    # 236 single-byte tokens (indices 0..235; DICTIONARY_0 starts at 236).
    assert len(SINGLE_BYTE_TOKENS) == 236
    assert len(DOUBLE_BYTE_TOKENS) == 4
    assert all(len(d) == 256 for d in DOUBLE_BYTE_TOKENS)


def test_token_map_double_overwrites_single():
    # Matches Baileys: double-byte entries win on collision.
    for tok, (dict_idx, idx) in TOKEN_MAP.items():
        if dict_idx is None:
            assert SINGLE_BYTE_TOKENS[idx] == tok
        else:
            assert DOUBLE_BYTE_TOKENS[dict_idx][idx] == tok


def test_simple_node():
    node = BinaryNode(tag="iq", attrs={"type": "get", "id": "123"})
    assert _normalize(roundtrip(node)) == _normalize(node)


def test_nested_with_bytes_and_jids():
    node = BinaryNode(
        tag="iq",
        attrs={"to": "1234567890@s.whatsapp.net", "type": "set", "xmlns": "w:g2"},
        content=[
            BinaryNode(tag="create", attrs={"subject": "Group", "key": "9988"}),
            BinaryNode(tag="participant", attrs={"jid": "5511999999999@s.whatsapp.net"}),
            BinaryNode(tag="raw", content=b"\x00\x01\x02hello\xff"),
            BinaryNode(tag="dev", attrs={"jid": "5511999999999:7@s.whatsapp.net"}),
        ],
    )
    assert _normalize(roundtrip(node)) == _normalize(node)


def test_token_string_content_roundtrips_as_str():
    # a tokenised string content survives as a str
    node = BinaryNode(tag="value", content="composing")
    assert roundtrip(node).content == "composing"


def test_raw_string_content_decodes_as_bytes():
    # matches Baileys: non-token raw string *content* comes back as bytes
    # (only attribute values are always decoded as str)
    node = BinaryNode(tag="value", content="some-text-content")
    decoded = roundtrip(node)
    assert decoded.content == b"some-text-content"


def test_lid_and_device_jid():
    node = BinaryNode(tag="x", attrs={"a": "12345:3@lid", "b": "999@g.us"})
    assert _normalize(roundtrip(node)) == _normalize(node)


def test_nibble_and_hex_packing():
    # purely-numeric strings are nibble-packed; uppercase-hex are hex-packed
    node = BinaryNode(tag="x", attrs={"num": "0123456789", "hex": "ABCDEF0123"})
    assert _normalize(roundtrip(node)) == _normalize(node)


def test_large_binary_content_uses_binary20():
    payload = bytes(range(256)) * 10  # 2560 bytes -> BINARY_20 path
    node = BinaryNode(tag="blob", content=payload)
    assert _normalize(roundtrip(node)) == _normalize(node)


def test_single_and_double_byte_tokens_roundtrip():
    # 's.whatsapp.net' is single-byte; 'read-self' lives in double dict 0.
    node = BinaryNode(tag="message", attrs={"server": "s.whatsapp.net", "x": "read-self"})
    decoded = roundtrip(node)
    assert decoded.attrs["server"] == "s.whatsapp.net"
    assert decoded.attrs["x"] == "read-self"


def test_empty_buffer_raises():
    with pytest.raises(WABinaryError):
        decode_binary_node(b"")


def test_truncated_frame_raises():
    enc = encode_binary_node(BinaryNode(tag="iq", attrs={"id": "1"}, content=b"abcdef"))
    with pytest.raises(WABinaryError):
        decode_binary_node(enc[:-3])


# -- property-based: decoder must never crash on arbitrary input ----------
@settings(max_examples=300)
@given(st.binary(min_size=0, max_size=64))
def test_decoder_never_crashes_on_garbage(data: bytes):
    try:
        decode_binary_node(data)
    except WABinaryError:
        pass
    except UnicodeDecodeError:
        # malformed UTF-8 inside a raw string surfaces here; acceptable, not a crash
        pass


# exclude '@' so values are never interpreted as (possibly-degenerate) JIDs
_ATTR_VALUES = st.text(
    alphabet=st.characters(
        min_codepoint=32, max_codepoint=126, blacklist_characters="@"
    ),
    min_size=0,
    max_size=12,
)


@settings(max_examples=150)
@given(
    tag=st.sampled_from(["iq", "message", "presence", "receipt", "notification"]),
    attrs=st.dictionaries(
        st.sampled_from(["id", "type", "to", "from", "xmlns", "t"]),
        _ATTR_VALUES,
        max_size=5,
    ),
    payload=st.binary(min_size=0, max_size=300),
)
def test_roundtrip_property(tag, attrs, payload):
    node = BinaryNode(tag=tag, attrs=attrs, content=payload)
    decoded = roundtrip(node)
    assert decoded.tag == tag
    assert decoded.attrs == attrs
    assert decoded.content_bytes == payload
