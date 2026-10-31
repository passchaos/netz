"""Independent HTTP peers: hashlib hashes and http-sfv parses generated fields."""
import gzip
import hashlib
import base64
import ssl
import http_sfv
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, DataReceived, StreamEnded, ConnectionTerminated

PAYLOAD = b"independent HTTP digest " * 12
PATHS = ("/header", "/trailer", "/corrupt", "/missing", "/unsupported", "/malformed", "/stream", "/generated")


def field(body: bytes, algorithm: str) -> str:
    names = {"sha-256": "sha256", "sha-512": "sha512", "md5": "md5"}
    value = hashlib.new(names[algorithm], body).digest()
    return f"{algorithm}=:{base64.b64encode(value).decode()}:"


def reply(path: str) -> tuple[bytes, list, list]:
    content = gzip.compress(PAYLOAD, mtime=0) if path == "/header" else PAYLOAD
    headers, trailers = [], []
    if path == "/header":
        headers += [("content-encoding", "gzip"), ("content-digest", field(content, "sha-256"))]
    elif path in ("/trailer", "/stream"):
        trailers += [("content-digest", field(content, "sha-512"))]
    elif path == "/corrupt":
        headers += [("content-digest", field(content, "sha-256") + ", " + field(b"different", "sha-512"))]
    elif path == "/unsupported":
        headers += [("content-digest", field(content, "md5"))]
    elif path == "/malformed":
        headers += [("content-digest", field(content, "sha-256") + ", future=?1")]
    elif path == "/generated":
        content = b"verified"
        headers += [("content-digest", field(content, "sha-512"))]
    elif path != "/missing":
        raise AssertionError(path)
    return content, headers, trailers


def verify_generated(headers: list, content: bytes) -> None:
    assert content == b'{"hello": "world"}'
    def dictionary(name: str):
        value = b", ".join(v.encode() for k, v in headers if k.lower() == name)
        parsed = http_sfv.Dictionary()
        parsed.parse(value)
        return parsed
    values = dictionary("content-digest")
    assert set(values) == {"sha-256", "sha-512"}
    assert values["sha-256"].value == hashlib.sha256(content).digest()
    assert values["sha-512"].value == hashlib.sha512(content).digest()
    preferences = dictionary("want-content-digest")
    assert preferences["sha-256"].value == 3 and preferences["sha-512"].value == 10


def recv_exact(stream, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise EOFError("incomplete HTTP request")
        result += part
    return bytes(result)


def h1_request(stream) -> tuple[str, list, bytes]:
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        head += recv_exact(stream, 1)
        if len(head) > 16384:
            raise AssertionError("request head budget")
    lines = bytes(head).decode("ascii").split("\r\n")
    method, path, version = lines[0].split()
    assert version == "HTTP/1.1"
    headers = [(k.lower(), v.strip()) for k, v in (line.split(":", 1) for line in lines[1:] if line)]
    content_length = dict(headers).get("content-length", "0")
    content = recv_exact(stream, int(content_length))
    assert method == ("POST" if path == "/generated" else "GET")
    return path, headers, content


def serve_h1(listener, context: ssl.SSLContext) -> dict:
    raw, _ = listener.accept()
    with raw, context.wrap_socket(raw, server_side=True) as stream:
        stream.settimeout(10)
        assert stream.version() == "TLSv1.3"
        for expected in PATHS:
            path, request_headers, body = h1_request(stream)
            assert path == expected
            if path == "/generated":
                verify_generated(request_headers, body)
            content, headers, trailers = reply(path)
            chunked = bool(trailers)
            fields = headers + ([('transfer-encoding', 'chunked'), ('trailer', 'Content-Digest')] if chunked else [('content-length', str(len(content)))])
            stream.sendall(b"HTTP/1.1 200 OK\r\n" + b"".join(f"{k}: {v}\r\n".encode() for k, v in fields) + b"\r\n")
            if chunked:
                for offset in range(0, len(content), 7):
                    part = content[offset:offset + 7]
                    stream.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                stream.sendall(b"0\r\n" + b"".join(f"{k}: {v}\r\n".encode() for k, v in trailers) + b"\r\n")
            else:
                stream.sendall(content)
        assert stream.recv(1) == b"", "unexpected request after transcript"
        return {"protocol": "http1", "paths": list(PATHS), "requests": len(PATHS), "tls": stream.version(), "generated_verified": True}


def serve_h2(listener, context: ssl.SSLContext) -> dict:
    raw, _ = listener.accept()
    with raw, context.wrap_socket(raw, server_side=True) as stream:
        stream.settimeout(10)
        assert stream.version() == "TLSv1.3" and stream.selected_alpn_protocol() == "h2"
        connection = H2Connection(H2Configuration(client_side=False, header_encoding="utf-8"))
        connection.initiate_connection()
        stream.sendall(connection.data_to_send())
        pending = {}
        completed = []
        while len(completed) < len(PATHS):
            data = stream.recv(65536)
            if not data:
                raise EOFError("missing HTTP2 request")
            for event in connection.receive_data(data):
                if isinstance(event, RequestReceived):
                    pending[event.stream_id] = [event.headers, bytearray()]
                elif isinstance(event, DataReceived):
                    pending[event.stream_id][1] += event.data
                    connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamEnded):
                    request_headers, body = pending.pop(event.stream_id)
                    path = dict(request_headers)[":path"]
                    assert path == PATHS[len(completed)]
                    if path == "/generated":
                        verify_generated(request_headers, bytes(body))
                    content, headers, trailers = reply(path)
                    connection.send_headers(event.stream_id, [(":status", "200"), *headers])
                    for offset in range(0, len(content), 7):
                        part = content[offset:offset + 7]
                        connection.send_data(event.stream_id, part, end_stream=not trailers and offset + 7 >= len(content))
                    if trailers:
                        connection.send_headers(event.stream_id, trailers, end_stream=True)
                    completed.append(path)
                elif isinstance(event, ConnectionTerminated):
                    raise AssertionError(event)
            wire = connection.data_to_send()
            if wire:
                stream.sendall(wire)
        # Allow final credit/control frames while the client finishes both
        # connections, then require transport shutdown without another request.
        while True:
            tail = stream.recv(65536)
            if not tail:
                break
            assert not any(isinstance(event, RequestReceived) for event in connection.receive_data(tail))
            wire = connection.data_to_send()
            if wire:
                stream.sendall(wire)
        return {"protocol": "http2", "paths": completed, "requests": len(completed), "tls": stream.version(), "alpn": stream.selected_alpn_protocol(), "generated_verified": True}
