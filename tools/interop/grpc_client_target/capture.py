#!/usr/bin/env python3
"""Decode raw backend HTTP/2 HEADERS before Node applies request validation."""
import argparse
import base64
import hashlib
import importlib.metadata
import json
from pathlib import Path

from hpack import Decoder

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_TCP_BYTES = 256 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def provenance():
    distribution = importlib.metadata.distribution("hpack")
    require(distribution.version == "4.1.0", f"Expected hpack 4.1.0; got {distribution.version}")
    hashes = {}
    for file in distribution.files or ():
        if str(file).endswith((".py", "/METADATA", "/WHEEL", "/RECORD")):
            hashes[str(file)] = sha256(Path(distribution.locate_file(file)).read_bytes())
    return {"hpack": distribution.version, "dependency_sha256": hashes}


def frames(data, client):
    require(len(data) <= MAX_TCP_BYTES, "TCP capture exceeded byte limit")
    if client:
        require(data.startswith(PREFACE), "captured client did not send the HTTP/2 preface")
        offset = len(PREFACE)
    else:
        offset = 0
    result = []
    while offset < len(data):
        require(len(data) - offset >= 9, "truncated captured HTTP/2 frame header")
        length = int.from_bytes(data[offset:offset + 3], "big")
        kind, flags = data[offset + 3:offset + 5]
        stream = int.from_bytes(data[offset + 5:offset + 9], "big") & 0x7fffffff
        offset += 9
        require(length <= len(data) - offset, "truncated captured HTTP/2 frame payload")
        result.append((kind, flags, stream, data[offset:offset + length]))
        require(len(result) <= 256, "HTTP/2 capture exceeded frame limit")
        offset += length
    return result


def decode(connection):
    client = base64.b64decode(connection["client_base64"], validate=True)
    server = base64.b64decode(connection["server_base64"], validate=True)
    decoder = Decoder(max_header_list_size=65536)
    requests, rejections = [], []
    pending = None
    # A reconnect can close before sending any HTTP/2 bytes. Preserve that
    # attempt explicitly; every nonempty capture still needs a full preface.
    startup = "http2-preface-received" if client else "closed-before-http2-preface"
    client_frames = frames(client, True) if client else []
    for kind, flags, stream, payload in client_frames:
        if pending is not None:
            require(kind == 9 and stream == pending[0], "interleaved captured HEADERS/CONTINUATION")
        if kind == 1:
            require(stream != 0 and pending is None, "invalid captured HEADERS stream")
            padding = 0
            if flags & 8:
                require(payload, "padded HEADERS has no pad length")
                padding, payload = payload[0], payload[1:]
            if flags & 32:
                require(len(payload) >= 5, "HEADERS priority field is truncated")
                payload = payload[5:]
            require(padding <= len(payload), "HEADERS padding exceeds payload")
            if padding:
                payload = payload[:-padding]
            pending = (stream, bytearray(payload))
        elif kind == 9:
            require(pending is not None, "CONTINUATION has no HEADERS")
            pending[1].extend(payload)
        if kind in (1, 9) and flags & 4:
            header_block = bytes(pending[1])
            headers = [[name.decode("ascii"), value.decode("utf-8")]
                       for name, value in decoder.decode(header_block, raw=True)]
            requests.append({"connection": connection["id"], "stream": pending[0], "headers": headers,
                             "hpack_sha256": sha256(header_block)})
            pending = None
    require(pending is None, "captured HEADERS block is incomplete")
    for kind, _flags, stream, payload in frames(server, False):
        if kind == 3:
            require(len(payload) == 4 and stream != 0, "invalid captured RST_STREAM")
            rejections.append({"connection": connection["id"], "kind": "RST_STREAM", "stream": stream,
                               "code": int.from_bytes(payload, "big")})
        elif kind == 7:
            require(len(payload) >= 8 and stream == 0, "invalid captured GOAWAY")
            rejections.append({"connection": connection["id"], "kind": "GOAWAY",
                               "last_stream": int.from_bytes(payload[:4], "big") & 0x7fffffff,
                               "code": int.from_bytes(payload[4:8], "big"),
                               "debug_base64": base64.b64encode(payload[8:]).decode()})
    return {"id": connection["id"], "client_sha256": sha256(client), "server_sha256": sha256(server),
            "client_bytes": len(client), "server_bytes": len(server), "startup": startup,
            "requests": requests, "rejections": rejections}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", nargs="?", type=Path)
    parser.add_argument("--metadata-only", action="store_true")
    args = parser.parse_args()
    result = {"status": "ok", **provenance(), "connections": [], "errors": []}
    if not args.metadata_only:
        require(args.capture is not None, "a TCP capture file is required")
        captures = json.loads(args.capture.read_text())["tcp_captures"]
        require(len(captures) <= 8, "TCP capture exceeded connection limit")
        for connection in captures:
            try:
                result["connections"].append(decode(connection))
            except Exception as error:
                result["errors"].append({"connection": connection["id"], "error": str(error)})
        if result["errors"]:
            result["status"] = "error"
    print(json.dumps(result))


if __name__ == "__main__":
    main()
