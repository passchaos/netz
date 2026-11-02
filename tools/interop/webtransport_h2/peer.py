"""A scripted independent draft-15 endpoint using hyper-h2 for HTTP/2 only."""
from collections import deque
import ssl

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (DataReceived, RequestReceived, ResponseReceived,
                       TrailersReceived, StreamEnded, StreamReset,
                       RemoteSettingsChanged, SettingsAcknowledged,
                       ConnectionTerminated)
from h2.settings import Settings

from wire import (SETTINGS, Reader, DATAGRAM, CLOSE, DRAIN, PADDING, RESET, STOP,
                  FIN, STREAM, MAX_DATA, MAX_STREAM_DATA, MAX_BIDI, MAX_UNI,
                  DATA_BLOCKED, STREAM_BLOCKED, BIDI_BLOCKED, UNI_BLOCKED,
                  integer, integers, capsule, control, stream, settings_frame)


class Peer:
    def __init__(self, sock: ssl.SSLSocket, client: bool) -> None:
        assert sock.selected_alpn_protocol() == "h2"
        assert sock.version() == "TLSv1.3"
        sock.settimeout(8)
        self.sock = sock
        self.client = client
        self.h2 = H2Connection(H2Configuration(client_side=client, header_encoding="utf-8"))
        self.h2.local_settings = Settings(client=client, initial_values={
            **dict(self.h2.local_settings), **SETTINGS,
        })
        self.h2.initiate_connection()
        # hyperframe 6.1 serializes SETTINGS identifiers with an 8-bit mask.
        # Keep hyper-h2's state and ACK tracking, but encode the initial frame
        # independently with RFC 9113's 16-bit identifiers for this extension.
        self.h2.data_to_send()
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" if client else b""
        self.sock.sendall(preface + settings_frame(dict(self.h2.local_settings)))
        self.inbox = deque()
        self.readers = {}
        self.remote = False
        self.acknowledged = False
        self.flush()
        while not self.remote or not self.acknowledged:
            self.pump()

    def flush(self) -> None:
        data = self.h2.data_to_send()
        if data:
            self.sock.sendall(data)

    def pump(self) -> None:
        data = self.sock.recv(65536)
        if not data:
            raise EOFError("TLS closed before transcript completed")
        for event in self.h2.receive_data(data):
            if isinstance(event, RemoteSettingsChanged):
                settings = {key: value.new_value for key, value in event.changed_settings.items()}
                expected = {**SETTINGS, 0x2B62: 16, 0x2B63: 24, 0x2B66: 32}
                for key, value in expected.items():
                    assert settings.get(key) == value, (key, settings.get(key), value)
                self.remote = True
            elif isinstance(event, SettingsAcknowledged):
                self.acknowledged = True
            elif isinstance(event, DataReceived):
                self.h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                self.inbox.append(("data", event.stream_id, bytes(event.data)))
            elif isinstance(event, (RequestReceived, ResponseReceived, TrailersReceived)):
                self.inbox.append(("headers", event.stream_id, event.headers))
            elif isinstance(event, StreamEnded):
                self.inbox.append(("end", event.stream_id, None))
            elif isinstance(event, StreamReset):
                self.inbox.append(("reset", event.stream_id, event.error_code))
            elif isinstance(event, ConnectionTerminated):
                raise AssertionError(f"unexpected connection GOAWAY: {event}")
        self.flush()

    def event(self) -> tuple:
        while not self.inbox:
            self.pump()
        return self.inbox.popleft()

    def request(self, path: str, init: bool = False) -> int:
        sid = self.h2.get_next_available_stream_id()
        headers = [(":method", "CONNECT"), (":protocol", "webtransport"),
                   (":scheme", "https"), (":authority", "origin.internal"), (":path", path)]
        if init:
            headers += [("wt-available-protocols", '"interop", "other"'),
                        ("webtransport-init", "u=128, bl=132, br=136")]
        self.h2.send_headers(sid, headers)
        self.flush()
        return sid

    def establish(self) -> int:
        if self.client:
            rejected = self.request("/reject")
            self.h2.send_data(rejected, b"optimistic")
            self.flush()
            body = b""
            heads = []
            while True:
                kind, sid, data = self.event()
                assert sid == rejected
                if kind == "end":
                    break
                if kind == "data":
                    body += data
                elif kind == "headers":
                    heads.append(dict(data))
                else:
                    raise AssertionError((kind, data))
            assert heads[0][":status"] == "429" and body == b"retry"
            assert heads[-1]["x-retry"] == "1"
            kind, sid, code = self.event()
            assert (kind, sid, code) == ("reset", rejected, 0), (kind, sid, code)
            accepted = self.request("/interop", True)
            kind, sid, data = self.event()
            assert (kind, sid) == ("headers", accepted)
            headers = dict(data)
            assert headers[":status"] == "200" and headers["wt-protocol"] == '"interop"'
            assert headers["webtransport-init"] == "u=96, bl=100, br=104"
            return accepted
        rejected = None
        while True:
            kind, sid, data = self.event()
            if sid == rejected and kind in ("end", "reset"):
                continue
            assert kind == "headers", (kind, sid, data)
            headers = dict(data)
            assert headers[":method"] == "CONNECT"
            assert headers[":protocol"] == "webtransport"
            assert headers[":scheme"] == "https"
            assert headers[":authority"] == "origin.internal"
            if rejected is None:
                assert headers[":path"] == "/reject"
                rejected = sid
                self.h2.send_headers(sid, [(":status", "429")])
                self.h2.send_data(sid, b"retry")
                self.h2.send_headers(sid, [("x-retry", "1")], end_stream=True)
                self.flush()
                continue
            assert sid != rejected and headers[":path"] == "/interop"
            assert headers["wt-available-protocols"] == '"interop", "other"'
            assert headers["webtransport-init"] == "u=96, bl=100, br=104"
            self.h2.send_headers(sid, [(":status", "200"), ("wt-protocol", '"interop"'),
                                      ("webtransport-init", "u=128, bl=132, br=136")])
            self.flush()
            return sid

    def send(self, sid: int, data: bytes, fin: bool = False) -> None:
        # Separate DATA frames split the type, length, stream ID and payload.
        # The remaining payload is also split; this is real HTTP/2 framing,
        # independent of how TCP happens to segment or coalesce the writes.
        cuts = [data[i:i + 1] for i in range(min(12, len(data)))]
        cuts += [data[i:i + 7] for i in range(12, len(data), 7)]
        if not cuts:
            cuts = [b""]
        for index, part in enumerate(cuts):
            assert len(part) <= self.h2.local_flow_control_window(sid)
            self.h2.send_data(sid, part, end_stream=fin and index == len(cuts) - 1)
        self.flush()

    def capsules(self, sid: int):
        reader = Reader()
        while True:
            kind, event_sid, data = self.event()
            assert event_sid == sid, (kind, event_sid, sid)
            if kind == "end":
                reader.finish()
                return
            assert kind == "data", (kind, data)
            yield from reader.feed(data)

    def exchange(self, sid: int) -> dict:
        # Netz is the active sender in either role; initiator bits must change
        # with that role, while this independent transcript stays symmetric.
        remote_role = 1 if self.client else 0
        local_role = remote_role ^ 1
        local_bidi = remote_role
        reset_id = remote_role | 2
        stop_id = reset_id + 4
        steps = set()
        prefix = 0
        grants = set()
        for kind, payload in self.capsules(sid):
            if kind in (DATA_BLOCKED, BIDI_BLOCKED, UNI_BLOCKED):
                integers(payload, 1)
                continue
            if kind == STREAM_BLOCKED:
                integers(payload, 2)
                continue
            if kind in (STREAM, FIN):
                stream_id, offset = integer(payload)
                data = payload[offset:]
                if stream_id == local_bidi and "credit" not in steps:
                    assert kind == STREAM and data == b""
                    # DATAGRAM is exempt from WT data credit. The following
                    # unknown/padding capsules must not surface as data events.
                    self.send(sid, capsule(DATAGRAM, b"while-blocked") +
                              capsule(0x1234, b"ignored") + capsule(PADDING, b"\x01\x02") +
                              control(MAX_DATA, 4096) + control(MAX_STREAM_DATA, local_bidi, 256))
                    steps.add("credit")
                elif stream_id == local_bidi:
                    assert kind == FIN and data == b"x" * 200
                    steps.add("bidi")
                    self.send(sid, stream(local_bidi, b"reply", True))
                elif stream_id == reset_id:
                    assert kind == STREAM and data == b"prefix"
                    prefix += len(data)
                elif stream_id == stop_id:
                    assert kind == STREAM and data == b""
                    self.send(sid, control(STOP, stop_id, 0xFFFFFFFF))
                elif stream_id == local_role:
                    assert kind == FIN and data == b"local-reply"
                    steps.add("peer-streams")
                else:
                    raise AssertionError((stream_id, kind, data))
            elif kind == DATAGRAM:
                assert payload == b"ping"
                steps.add("datagram")
                self.send(sid, capsule(DATAGRAM, b"pong"))
            elif kind == RESET:
                stream_id, code, reliable = integers(payload, 3)
                if stream_id == reset_id:
                    assert (code, reliable, prefix) == (42, 6, 6)
                    steps.add("reset")
                else:
                    assert (stream_id, code, reliable) == (stop_id, 0xFFFFFFFF, 0)
                    steps.add("stop")
            elif kind in (MAX_DATA, MAX_BIDI, MAX_UNI):
                assert integers(payload, 1) == ((4096 if kind == MAX_DATA else 16),)
                grants.add(kind)
                if grants == {MAX_DATA, MAX_BIDI, MAX_UNI}:
                    self.send(sid, stream(local_role | 2, b"peer-uni", True) +
                              stream(local_role, b"peer-bidi", True))
            elif kind == DRAIN:
                assert payload == b"" and "peer-streams" in steps
                steps.add("drain")
                self.send(sid, capsule(DRAIN) + capsule(CLOSE, (17).to_bytes(4, "big") + "done ✓".encode()), True)
            else:
                raise AssertionError((kind, payload))
        expected = {"credit", "bidi", "datagram", "reset", "stop", "peer-streams", "drain"}
        assert steps == expected, (steps, expected)
        return {"role": "client" if self.client else "server", "steps": sorted(steps),
                "http2_stream": sid, "reliable_size": prefix, "stop_code": 0xFFFFFFFF,
                "capsule_data_fragmentation": True, "connect_fin": True}

    def additional(self, path: str) -> int:
        if self.client:
            sid = self.request(path, True)
            kind, actual_sid, data = self.event()
            assert (kind, actual_sid) == ("headers", sid)
            headers = dict(data)
            assert headers[":status"] == "200" and headers["wt-protocol"] == '"interop"'
            assert headers["webtransport-init"] == "u=96, bl=100, br=104"
        else:
            kind, sid, data = self.event()
            assert kind == "headers", (kind, sid, data)
            headers = dict(data)
            assert headers[":path"] == path and headers[":protocol"] == "webtransport"
            assert headers[":authority"] == "origin.internal" and headers[":scheme"] == "https"
            assert headers["webtransport-init"] == "u=96, bl=100, br=104"
            self.h2.send_headers(sid, [(":status", "200"), ("wt-protocol", '"interop"'),
                                      ("webtransport-init", "u=128, bl=132, br=136")])
            self.flush()
        return sid

    def run(self) -> dict:
        result = self.exchange(self.establish())
        bad = self.additional("/bad-reset")
        uni = 2 if self.client else 3
        self.send(bad, stream(uni, b"abc") + control(RESET, uni, 42, 2))
        kind, sid, code = self.event()
        assert (kind, sid) == ("reset", bad), (kind, sid, code)
        if not self.client:
            dropped = self.additional("/drop")
            kind, sid, code = self.event()
            assert (kind, sid, code) == ("reset", dropped, 8), (kind, sid, code)
            result.update(dropped_connect_cleanup=True, dropped_reset_code=8)
        good = self.additional("/reuse")
        incoming = self.capsules(good)
        assert next(incoming) == (DATAGRAM, b"after-error")
        self.send(good, capsule(DATAGRAM, b"still-healthy") + capsule(CLOSE, (18).to_bytes(4, "big")), True)
        assert list(incoming) == []
        result.update(invalid_reset_scoped=True, reuse_after_error=True, connect_requests=4 if self.client else 5)
        return result
