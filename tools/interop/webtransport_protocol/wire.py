"""Bounded RFC 9204 static/literal field reader for independently captured heads."""
from hpack.huffman_table import decode_huffman


def quic_integer(data, offset):
    if offset >= len(data):
        raise ValueError("truncated QUIC integer")
    width = 1 << (data[offset] >> 6)
    end = offset + width
    if end > len(data):
        raise ValueError("truncated QUIC integer")
    return int.from_bytes(data[offset:end], "big") & ((1 << (8 * width - 2)) - 1), end


def prefixed(data, offset, bits):
    if offset >= len(data):
        raise ValueError("truncated QPACK integer")
    maximum = (1 << bits) - 1
    value = data[offset] & maximum
    offset += 1
    if value < maximum:
        return value, offset
    shift = 0
    while True:
        if offset >= len(data) or shift > 56:
            raise ValueError("invalid QPACK integer")
        byte = data[offset]
        offset += 1
        value += (byte & 0x7f) << shift
        if byte < 128:
            return value, offset
        shift += 7


def string(data, offset, bits, huffman_bit):
    if offset >= len(data):
        raise ValueError("truncated QPACK string")
    huffman = bool(data[offset] & huffman_bit)
    length, start = prefixed(data, offset, bits)
    end = start + length
    if end > len(data):
        raise ValueError("truncated QPACK string")
    value = data[start:end]
    if huffman:
        value = decode_huffman(value)
    return value.decode("ascii"), end


def fields(frame):
    kind, offset = quic_integer(frame, 0)
    length, offset = quic_integer(frame, offset)
    if kind != 1 or length > 65536 or offset + length != len(frame):
        raise ValueError("expected one complete bounded HEADERS frame")
    data = frame[offset:]
    required, offset = prefixed(data, 0, 8)
    negative_base = bool(data[offset] & 0x80) if offset < len(data) else False
    base, offset = prefixed(data, offset, 7)
    if required != 0 or base != 0 or negative_base:
        raise ValueError("fixture negotiated no dynamic QPACK table")
    result = []
    while offset < len(data):
        byte = data[offset]
        if byte & 0x80:
            if not byte & 0x40:
                raise ValueError("unexpected dynamic indexed field")
            index, offset = prefixed(data, offset, 6)
            # WT negotiation names are absent from the RFC 9204 static table.
            result.append((f"@static:{index}", None))
        elif byte & 0x40:
            if not byte & 0x10:
                raise ValueError("unexpected dynamic name reference")
            index, offset = prefixed(data, offset, 4)
            value, offset = string(data, offset, 7, 0x80)
            result.append((f"@static:{index}", value))
        elif byte & 0x20:
            name, offset = string(data, offset, 3, 0x08)
            value, offset = string(data, offset, 7, 0x80)
            result.append((name, value))
        else:
            raise ValueError("unexpected post-base/dynamic field")
    return result


def header(frame_hex, name):
    matches = [value for field, value in fields(bytes.fromhex(frame_hex)) if field == name]
    if len(matches) > 1:
        raise ValueError("duplicate negotiation header")
    return matches[0] if matches else None


def sanity():
    # QPACK zero table prefix + literal name "x" and raw/Huffman values.
    assert fields(bytes.fromhex("010700002178026f6b")) == [("x", "ok")]
    assert fields(bytes.fromhex("0111000021788cf1e3c2e5f23a6ba0ab90f4ff")) == [("x", "www.example.com")]
    for value in ("01", "010700002178026f", "010702002178026f6b"):
        try:
            fields(bytes.fromhex(value))
        except ValueError:
            pass
        else:
            raise AssertionError("invalid HEADERS accepted")
