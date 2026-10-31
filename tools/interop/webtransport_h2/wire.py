"""Independent draft-ietf-webtrans-http2-15 wire vectors and capsule reader.

Codepoints come from sections 6 and 11 of the July 2026 draft. This module
does not import, generate from, or invoke the Netz codec.
"""

DATAGRAM = 0x00
CLOSE = 0x2843
DRAIN = 0x78AE
PADDING = 0x190B4D38
RESET = 0x190B4D39
STOP = 0x190B4D3A
FIN = 0x190B4D3B
STREAM = 0x190B4D3C
MAX_DATA = 0x190B4D3D
MAX_STREAM_DATA = 0x190B4D3E
MAX_BIDI = 0x190B4D3F
MAX_UNI = 0x190B4D40
DATA_BLOCKED = 0x190B4D41
STREAM_BLOCKED = 0x190B4D42
BIDI_BLOCKED = 0x190B4D43
UNI_BLOCKED = 0x190B4D44

# The settings registry orders BIDI_REMOTE after the stream-count settings.
SETTINGS = {
    0x08: 1,       # RFC 8441 ENABLE_CONNECT_PROTOCOL
    0x2B60: 1,     # WT_ENABLED
    0x2B61: 64,    # INITIAL_MAX_DATA
    0x2B62: 24,    # INITIAL_MAX_STREAM_DATA_UNI
    0x2B63: 32,    # INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
    0x2B64: 8,     # INITIAL_MAX_STREAMS_UNI
    0x2B65: 8,     # INITIAL_MAX_STREAMS_BIDI
    0x2B66: 40,    # INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
}


def settings_frame(values: dict[int, int]) -> bytes:
    payload = b"".join(key.to_bytes(2, "big") + value.to_bytes(4, "big")
                       for key, value in values.items())
    return len(payload).to_bytes(3, "big") + b"\x04\x00\x00\x00\x00\x00" + payload


def varint(value: int) -> bytes:
    if not 0 <= value < 1 << 62:
        raise ValueError("QUIC integer outside 62-bit domain")
    for width, bits in ((1, 6), (2, 14), (4, 30), (8, 62)):
        if value < 1 << bits:
            return (value | ((width.bit_length() - 1) << (width * 8 - 2))).to_bytes(width, "big")
    raise AssertionError("unreachable integer width")


def integer(data: bytes | bytearray, offset: int = 0) -> tuple[int, int]:
    if offset >= len(data):
        raise EOFError("partial integer")
    width = 1 << (data[offset] >> 6)
    if offset + width > len(data):
        raise EOFError("partial integer")
    value = int.from_bytes(data[offset:offset + width], "big")
    return value & ((1 << (width * 8 - 2)) - 1), offset + width


def integers(data: bytes, count: int) -> tuple[int, ...]:
    values = []
    offset = 0
    for _ in range(count):
        value, offset = integer(data, offset)
        values.append(value)
    if offset != len(data):
        raise AssertionError("extra bytes in control capsule")
    return tuple(values)


def capsule(kind: int, payload: bytes = b"") -> bytes:
    return varint(kind) + varint(len(payload)) + payload


def control(kind: int, *values: int) -> bytes:
    return capsule(kind, b"".join(varint(value) for value in values))


def stream(stream_id: int, payload: bytes, fin: bool = False) -> bytes:
    return capsule(FIN if fin else STREAM, varint(stream_id) + payload)


class Reader:
    def __init__(self) -> None:
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        self.buffer.extend(data)
        output = []
        while self.buffer:
            try:
                kind, offset = integer(self.buffer)
                length, offset = integer(self.buffer, offset)
            except EOFError:
                break
            if length > 65536:
                raise AssertionError("peer capsule exceeds transcript budget")
            if offset + length > len(self.buffer):
                break
            output.append((kind, bytes(self.buffer[offset:offset + length])))
            del self.buffer[:offset + length]
        return output

    def finish(self) -> None:
        if self.buffer:
            raise AssertionError("CONNECT FIN inside capsule")


def check_vectors() -> None:
    # Fixed bytes, rather than a round trip through two copies of this codec.
    vectors = ((0, "00"), (63, "3f"), (64, "4040"), (16383, "7fff"),
               (16384, "80004000"), ((1 << 30) - 1, "bfffffff"),
               (1 << 30, "c000000040000000"), ((1 << 62) - 1, "ffffffffffffffff"))
    for value, encoded in vectors:
        assert varint(value).hex() == encoded
        assert integer(bytes.fromhex(encoded)) == (value, len(bytes.fromhex(encoded)))
    assert integer(bytes.fromhex("4001")) == (1, 2)  # non-minimal is legal
    assert settings_frame({0x2B60: 1}).hex() == "0000060400000000002b6000000001"
    encoded = bytes.fromhex("990b4d3b03046869")  # stream 4, 'hi', FIN
    assert stream(4, b"hi", True) == encoded
    for split in range(len(encoded) + 1):
        reader = Reader()
        assert reader.feed(encoded[:split]) + reader.feed(encoded[split:]) == [(FIN, b"\x04hi")]
        reader.finish()
    reader = Reader()
    reader.feed(encoded[:-1])
    try:
        reader.finish()
    except AssertionError:
        pass
    else:
        raise AssertionError("truncated capsule was accepted")
