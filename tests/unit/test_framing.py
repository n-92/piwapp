"""Frame codec tests: length-prefix round-trips and split/coalesced streams."""

from __future__ import annotations

import pytest

from piwapp.transport.framing import (
    FrameDecoder,
    FrameError,
    encode_frame,
    wa_routing_header,
)


def test_encode_decode_single_frame():
    payload = b"hello world"
    frame = encode_frame(payload)
    assert frame[:3] == len(payload).to_bytes(3, "big")
    out = list(FrameDecoder().feed(frame))
    assert out == [payload]


def test_first_frame_with_header():
    payload = b"\x01\x02\x03"
    frame = encode_frame(payload, with_header=True)
    assert frame.startswith(wa_routing_header())
    # the decoder is fed only post-header bytes in practice; verify length math
    body = frame[len(wa_routing_header()) :]
    assert list(FrameDecoder().feed(body)) == [payload]


def test_multiple_frames_coalesced():
    d = FrameDecoder()
    stream = encode_frame(b"aaa") + encode_frame(b"bbbb") + encode_frame(b"c")
    assert list(d.feed(stream)) == [b"aaa", b"bbbb", b"c"]


def test_split_frame_across_feeds():
    d = FrameDecoder()
    frame = encode_frame(b"abcdef")
    assert list(d.feed(frame[:2])) == []  # length prefix incomplete
    assert list(d.feed(frame[2:5])) == []  # body incomplete
    assert list(d.feed(frame[5:])) == [b"abcdef"]
    assert d.pending == 0


def test_empty_payload():
    assert list(FrameDecoder().feed(encode_frame(b""))) == [b""]


def test_oversized_frame_rejected():
    with pytest.raises(FrameError):
        encode_frame(b"\x00" * (1 << 24))
