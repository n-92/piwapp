"""WABinary encoder/decoder.

A faithful Python port of Baileys' ``WABinary/encode.ts`` and ``decode.ts``.
The wire format is a recursively-encoded node tree with token-dictionary string
compression, packed nibble/hex numerics, and compact JID encodings.

Public API:

* :func:`encode_binary_node` — ``BinaryNode`` → ``bytes`` (with 0x00 flag prefix).
* :func:`decode_binary_node` — ``bytes`` → ``BinaryNode`` (handles the flag byte
  and optional zlib decompression).
"""

from __future__ import annotations

import zlib

from .jids import FullJid, WAJIDDomain, jid_decode, jid_encode
from .node import BinaryNode, NodeContent
from .tokens import DOUBLE_BYTE_TOKENS, SINGLE_BYTE_TOKENS, TAGS, TOKEN_MAP


class WABinaryError(Exception):
    """Raised on malformed WABinary input or unencodable nodes."""


# ----------------------------------------------------------------------
# Encoder
# ----------------------------------------------------------------------
def encode_binary_node(node: BinaryNode) -> bytes:
    """Encode a node tree, prefixed with the 0x00 (uncompressed) flag byte."""
    buf = bytearray([0])
    _encode_inner(node, buf)
    return bytes(buf)


def _push_int(buf: bytearray, value: int, n: int, little_endian: bool = False) -> None:
    for i in range(n):
        shift = i if little_endian else n - 1 - i
        buf.append((value >> (shift * 8)) & 0xFF)


def _push_int20(buf: bytearray, value: int) -> None:
    buf.append((value >> 16) & 0x0F)
    buf.append((value >> 8) & 0xFF)
    buf.append(value & 0xFF)


def _write_byte_length(buf: bytearray, length: int) -> None:
    if length >= 4294967296:
        raise WABinaryError(f"string too large to encode: {length}")
    if length >= (1 << 20):
        buf.append(TAGS.BINARY_32)
        _push_int(buf, length, 4)
    elif length >= 256:
        buf.append(TAGS.BINARY_20)
        _push_int20(buf, length)
    else:
        buf.append(TAGS.BINARY_8)
        buf.append(length & 0xFF)


def _write_string_raw(buf: bytearray, s: str) -> None:
    data = s.encode("utf-8")
    _write_byte_length(buf, len(data))
    buf.extend(data)


def _pack_nibble(ch: str) -> int:
    if ch == "-":
        return 10
    if ch == ".":
        return 11
    if ch == "\0":
        return 15
    if "0" <= ch <= "9":
        return ord(ch) - ord("0")
    raise WABinaryError(f'invalid byte for nibble "{ch}"')


def _pack_hex(ch: str) -> int:
    if "0" <= ch <= "9":
        return ord(ch) - ord("0")
    if "A" <= ch <= "F":
        return 10 + ord(ch) - ord("A")
    if "a" <= ch <= "f":
        return 10 + ord(ch) - ord("a")
    if ch == "\0":
        return 15
    raise WABinaryError(f'invalid hex char "{ch}"')


def _write_packed_bytes(buf: bytearray, s: str, kind: str) -> None:
    if len(s) > TAGS.PACKED_MAX:
        raise WABinaryError("Too many bytes to pack")
    buf.append(TAGS.NIBBLE_8 if kind == "nibble" else TAGS.HEX_8)

    rounded = (len(s) + 1) // 2
    if len(s) % 2 != 0:
        rounded |= 128
    buf.append(rounded & 0xFF)

    pack = _pack_nibble if kind == "nibble" else _pack_hex
    half = len(s) // 2
    for i in range(half):
        buf.append((pack(s[2 * i]) << 4) | pack(s[2 * i + 1]))
    if len(s) % 2 != 0:
        buf.append((pack(s[-1]) << 4) | pack("\0"))


def _is_nibble(s: str) -> bool:
    if not s or len(s) > TAGS.PACKED_MAX:
        return False
    return all(("0" <= c <= "9") or c in "-." for c in s)


def _is_hex(s: str) -> bool:
    if not s or len(s) > TAGS.PACKED_MAX:
        return False
    return all(("0" <= c <= "9") or ("A" <= c <= "F") for c in s)


def _write_jid(buf: bytearray, jid: FullJid) -> None:
    if jid.device is not None:
        buf.append(TAGS.AD_JID)
        buf.append((jid.domain_type or 0) & 0xFF)
        buf.append((jid.device or 0) & 0xFF)
        _write_string(buf, jid.user)
    else:
        buf.append(TAGS.JID_PAIR)
        if jid.user:
            _write_string(buf, jid.user)
        else:
            buf.append(TAGS.LIST_EMPTY)
        _write_string(buf, jid.server)


def _write_string(buf: bytearray, s: str | None) -> None:
    if s is None:
        buf.append(TAGS.LIST_EMPTY)
        return
    if s == "":
        _write_string_raw(buf, s)
        return

    token = TOKEN_MAP.get(s)
    if token is not None:
        dict_idx, index = token
        if dict_idx is not None:
            buf.append(TAGS.DICTIONARY_0 + dict_idx)
        buf.append(index & 0xFF)
        return

    if _is_nibble(s):
        _write_packed_bytes(buf, s, "nibble")
        return
    if _is_hex(s):
        _write_packed_bytes(buf, s, "hex")
        return

    decoded = jid_decode(s)
    if decoded is not None:
        _write_jid(buf, decoded)
    else:
        _write_string_raw(buf, s)


def _write_list_start(buf: bytearray, size: int) -> None:
    if size == 0:
        buf.append(TAGS.LIST_EMPTY)
    elif size < 256:
        buf.append(TAGS.LIST_8)
        buf.append(size)
    else:
        buf.append(TAGS.LIST_16)
        buf.append((size >> 8) & 0xFF)
        buf.append(size & 0xFF)


def _encode_inner(node: BinaryNode, buf: bytearray) -> None:
    tag = node.tag
    attrs = node.attrs or {}
    content = node.content

    if not tag:
        raise WABinaryError("Invalid node: tag cannot be empty")

    valid_attrs = [k for k, v in attrs.items() if v is not None]
    has_content = content is not None
    _write_list_start(buf, 2 * len(valid_attrs) + 1 + (1 if has_content else 0))
    _write_string(buf, tag)

    for key in valid_attrs:
        value = attrs[key]
        if isinstance(value, str):
            _write_string(buf, key)
            _write_string(buf, value)

    if isinstance(content, str):
        _write_string(buf, content)
    elif isinstance(content, (bytes, bytearray)):
        _write_byte_length(buf, len(content))
        buf.extend(content)
    elif isinstance(content, list):
        valid = [
            c
            for c in content
            if isinstance(c, BinaryNode) or isinstance(c, (bytes, bytearray, str))
        ]
        _write_list_start(buf, len(valid))
        for item in valid:
            if isinstance(item, BinaryNode):
                _encode_inner(item, buf)
            else:  # pragma: no cover - defensive; lists are normally nodes
                raise WABinaryError("list content must contain BinaryNode items")
    elif content is None:
        pass
    else:
        raise WABinaryError(f'invalid children for header "{tag}": {type(content)}')


# ----------------------------------------------------------------------
# Decoder
# ----------------------------------------------------------------------
class _Reader:
    __slots__ = ("buf", "i")

    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.i = 0

    def _check_eos(self, length: int) -> None:
        if self.i + length > len(self.buf):
            raise WABinaryError("end of stream")

    def byte(self) -> int:
        self._check_eos(1)
        v = self.buf[self.i]
        self.i += 1
        return v

    def bytes(self, n: int) -> bytes:
        self._check_eos(n)
        v = self.buf[self.i : self.i + n]
        self.i += n
        return v

    def int(self, n: int, little_endian: bool = False) -> int:
        self._check_eos(n)
        val = 0
        for k in range(n):
            shift = k if little_endian else n - 1 - k
            val |= self.byte() << (shift * 8)
        return val

    def int20(self) -> int:
        self._check_eos(3)
        return ((self.byte() & 15) << 16) + (self.byte() << 8) + self.byte()


def _unpack_nibble(value: int) -> str:
    if 0 <= value <= 9:
        return chr(ord("0") + value)
    if value == 10:
        return "-"
    if value == 11:
        return "."
    if value == 15:
        return "\0"
    raise WABinaryError(f"invalid nibble: {value}")


def _unpack_hex(value: int) -> str:
    if 0 <= value < 16:
        return chr(ord("0") + value) if value < 10 else chr(ord("A") + value - 10)
    raise WABinaryError(f"invalid hex: {value}")


def _read_packed8(r: _Reader, tag: int) -> str:
    start = r.byte()
    unpack = _unpack_nibble if tag == TAGS.NIBBLE_8 else _unpack_hex
    out: list[str] = []
    for _ in range(start & 127):
        cur = r.byte()
        out.append(unpack((cur & 0xF0) >> 4))
        out.append(unpack(cur & 0x0F))
    value = "".join(out)
    if start >> 7 != 0:
        value = value[:-1]
    return value


def _is_list_tag(tag: int) -> bool:
    return tag in (TAGS.LIST_EMPTY, TAGS.LIST_8, TAGS.LIST_16)


def _read_list_size(r: _Reader, tag: int) -> int:
    if tag == TAGS.LIST_EMPTY:
        return 0
    if tag == TAGS.LIST_8:
        return r.byte()
    if tag == TAGS.LIST_16:
        return r.int(2)
    raise WABinaryError(f"invalid tag for list size: {tag}")


def _get_token_double(dict_idx: int, idx: int) -> str:
    try:
        d = DOUBLE_BYTE_TOKENS[dict_idx]
    except IndexError as exc:
        raise WABinaryError(f"Invalid double token dict ({dict_idx})") from exc
    try:
        return d[idx]
    except IndexError as exc:
        raise WABinaryError(f"Invalid double token ({idx})") from exc


def _read_string(r: _Reader, tag: int) -> str:
    if 1 <= tag < len(SINGLE_BYTE_TOKENS):
        return SINGLE_BYTE_TOKENS[tag] or ""

    if tag in (TAGS.DICTIONARY_0, TAGS.DICTIONARY_1, TAGS.DICTIONARY_2, TAGS.DICTIONARY_3):
        return _get_token_double(tag - TAGS.DICTIONARY_0, r.byte())
    if tag == TAGS.LIST_EMPTY:
        return ""
    if tag == TAGS.BINARY_8:
        return r.bytes(r.byte()).decode("utf-8")
    if tag == TAGS.BINARY_20:
        return r.bytes(r.int20()).decode("utf-8")
    if tag == TAGS.BINARY_32:
        return r.bytes(r.int(4)).decode("utf-8")
    if tag == TAGS.JID_PAIR:
        return _read_jid_pair(r)
    if tag == TAGS.FB_JID:
        return _read_fb_jid(r)
    if tag == TAGS.INTEROP_JID:
        return _read_interop_jid(r)
    if tag == TAGS.AD_JID:
        return _read_ad_jid(r)
    if tag in (TAGS.HEX_8, TAGS.NIBBLE_8):
        return _read_packed8(r, tag)
    raise WABinaryError(f"invalid string with tag: {tag}")


def _read_jid_pair(r: _Reader) -> str:
    i = _read_string(r, r.byte())
    j = _read_string(r, r.byte())
    if j:
        return f"{i or ''}@{j}"
    raise WABinaryError(f"invalid jid pair: {i}, {j}")


def _read_ad_jid(r: _Reader) -> str:
    domain_type = r.byte()
    device = r.byte()
    user = _read_string(r, r.byte())
    server = "s.whatsapp.net"
    if domain_type == WAJIDDomain.LID:
        server = "lid"
    elif domain_type == WAJIDDomain.HOSTED:
        server = "hosted"
    elif domain_type == WAJIDDomain.HOSTED_LID:
        server = "hosted.lid"
    return jid_encode(user, server, device)


def _read_fb_jid(r: _Reader) -> str:
    user = _read_string(r, r.byte())
    device = r.int(2)
    server = _read_string(r, r.byte())
    return f"{user}:{device}@{server}"


def _read_interop_jid(r: _Reader) -> str:
    user = _read_string(r, r.byte())
    device = r.int(2)
    integrator = r.int(2)
    server = "interop"
    before = r.i
    try:
        server = _read_string(r, r.byte())
    except WABinaryError:
        r.i = before
    return f"{integrator}-{user}:{device}@{server}"


def _decode_node(r: _Reader) -> BinaryNode:
    list_size = _read_list_size(r, r.byte())
    header = _read_string(r, r.byte())
    if not list_size or not header:
        raise WABinaryError("invalid node")

    attrs: dict[str, str] = {}
    content: NodeContent = None

    attributes_length = (list_size - 1) >> 1
    for _ in range(attributes_length):
        key = _read_string(r, r.byte())
        value = _read_string(r, r.byte())
        attrs[key] = value

    if list_size % 2 == 0:
        tag = r.byte()
        if _is_list_tag(tag):
            size = _read_list_size(r, tag)
            content = [_decode_node(r) for _ in range(size)]
        elif tag == TAGS.BINARY_8:
            content = r.bytes(r.byte())
        elif tag == TAGS.BINARY_20:
            content = r.bytes(r.int20())
        elif tag == TAGS.BINARY_32:
            content = r.bytes(r.int(4))
        else:
            content = _read_string(r, tag)

    return BinaryNode(tag=header, attrs=attrs, content=content)


def decompress_if_required(buffer: bytes) -> bytes:
    """Strip the flag byte and zlib-inflate the payload when the flag bit is set."""
    if not buffer:
        raise WABinaryError("empty buffer")
    if buffer[0] & 2:
        try:
            return zlib.decompress(buffer[1:])
        except zlib.error as exc:
            raise WABinaryError(f"zlib inflate failed: {exc}") from exc
    return buffer[1:]


def decode_binary_node(buffer: bytes) -> BinaryNode:
    """Decode a full frame payload (flag byte + optionally-compressed node)."""
    return _decode_node(_Reader(decompress_if_required(buffer)))
