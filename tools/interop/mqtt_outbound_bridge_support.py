"""Wire parsing and fault proxies for the outbound bridge process gate."""

from __future__ import annotations

import socket
import threading
import time


def recv_exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise AssertionError("peer closed before complete MQTT packet")
        result.extend(part)
    return bytes(result)


def decode_remaining_length(data: bytes, offset: int = 1) -> tuple[int, int]:
    value = 0
    multiplier = 1
    for index in range(4):
        encoded = data[offset + index]
        value += (encoded & 0x7F) * multiplier
        if encoded & 0x80 == 0:
            return value, offset + index + 1
        multiplier *= 128
    raise AssertionError("malformed MQTT Remaining Length")


def read_packet(sock: socket.socket) -> bytes:
    packet = bytearray(recv_exact(sock, 1))
    remaining = 0
    multiplier = 1
    for _ in range(4):
        encoded = recv_exact(sock, 1)[0]
        packet.append(encoded)
        remaining += (encoded & 0x7F) * multiplier
        if encoded & 0x80 == 0:
            packet.extend(recv_exact(sock, remaining))
            return bytes(packet)
        multiplier *= 128
    raise AssertionError("malformed MQTT Remaining Length")


def parse_publish(packet: bytes, protocol: int) -> dict[str, object]:
    if packet[0] >> 4 != 3:
        raise AssertionError(f"expected PUBLISH, received {packet.hex()}")
    remaining, cursor = decode_remaining_length(packet)
    if cursor + remaining != len(packet):
        raise AssertionError("PUBLISH length mismatch")
    topic_len = int.from_bytes(packet[cursor : cursor + 2], "big")
    cursor += 2
    topic = packet[cursor : cursor + topic_len].decode("utf-8")
    cursor += topic_len
    qos = (packet[0] >> 1) & 0x03
    packet_id = None
    if qos != 0:
        packet_id = int.from_bytes(packet[cursor : cursor + 2], "big")
        cursor += 2
    if protocol == 5:
        properties_len, properties_start = decode_remaining_length(
            packet, cursor
        )
        cursor = properties_start + properties_len
    return {
        "topic": topic,
        "payload": packet[cursor:],
        "qos": qos,
        "retain": bool(packet[0] & 0x01),
        "packet_id": packet_id,
    }


def assert_publish(
    packet: bytes, protocol: int, *, qos: int, retain: bool, payload: bytes
) -> int | None:
    return assert_publish_on_topic(
        packet, protocol, topic="remote/sensors/room", qos=qos,
        retain=retain, payload=payload,
    )


def assert_publish_on_topic(
    packet: bytes, protocol: int, *, topic: str, qos: int,
    retain: bool, payload: bytes,
) -> int | None:
    publish = parse_publish(packet, protocol)
    if publish["topic"] != topic:
        raise AssertionError(f"wrong remapped topic: {publish['topic']}")
    if publish["payload"] != payload:
        raise AssertionError(f"wrong bridged payload: {publish['payload']!r}")
    if publish["qos"] != qos:
        raise AssertionError(f"wrong bridged QoS: {publish['qos']}")
    if publish["retain"] != retain:
        raise AssertionError(f"wrong RETAIN bit: {publish['retain']}")
    return publish["packet_id"]  # type: ignore[return-value]


class _SessionProxy:
    def __init__(self, listen_port: int, target_port: int, thread_name: str):
        self.target_port = target_port
        self.stop_requested = threading.Event()
        self.error: BaseException | None = None
        self.accepted_connection_count = 0
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", listen_port))
        self.listener.listen(2)
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self._run, name=thread_name)
        self.thread.start()

    def _accept(self) -> socket.socket:
        while not self.stop_requested.is_set():
            try:
                client, _ = self.listener.accept()
                client.settimeout(5)
                self.accepted_connection_count += 1
                return client
            except socket.timeout:
                continue
        raise RuntimeError("proxy stopped before bridge reconnect")

    def _connect_session(
        self, client: socket.socket, *, session_present: bool
    ) -> socket.socket:
        target = socket.create_connection(
            ("127.0.0.1", self.target_port), timeout=5
        )
        target.settimeout(5)
        connect_packet = read_packet(client)
        if connect_packet[0] >> 4 != 1:
            raise AssertionError(
                f"proxy expected CONNECT, received {connect_packet.hex()}"
            )
        target.sendall(connect_packet)
        connack = read_packet(target)
        _, cursor = decode_remaining_length(connack)
        if connack[0] >> 4 != 2 or bool(connack[cursor] & 0x01) != session_present:
            raise AssertionError(
                f"target Session Present mismatch: {connack.hex()}"
            )
        client.sendall(connack)
        return target

    @staticmethod
    def _packet_id(packet: bytes, packet_type: int) -> int:
        _, cursor = decode_remaining_length(packet)
        if packet[0] >> 4 != packet_type:
            raise AssertionError(
                f"expected packet type {packet_type}, got {packet.hex()}"
            )
        return int.from_bytes(packet[cursor : cursor + 2], "big")

    def _run_fallible(self) -> None:
        raise NotImplementedError

    def _wake_waiters(self) -> None:
        pass

    def _run(self) -> None:
        try:
            self._run_fallible()
        except BaseException as exc:
            if not self.stop_requested.is_set():
                self.error = exc
        finally:
            self._wake_waiters()

    def wait(self, event: threading.Event, label: str) -> None:
        if not event.wait(timeout=10):
            raise RuntimeError(f"timed out waiting for {label}")
        if self.error is not None:
            raise self.error

    def stop(self) -> None:
        self.stop_requested.set()
        self._wake_waiters()
        self.listener.close()
        self.thread.join(timeout=6)
        if self.thread.is_alive():
            raise RuntimeError("fault proxy did not stop")
        if self.error is not None:
            raise self.error


class AckDropProxy(_SessionProxy):
    def __init__(self, listen_port: int, target_port: int, payload: bytes):
        self.payload = payload
        self.allow_replay = threading.Event()
        self.retry_held = threading.Event()
        self.replay_complete = threading.Event()
        super().__init__(listen_port, target_port, "mqtt-ack-drop")

    def _read_publish(self, client: socket.socket) -> tuple[bytes, int]:
        packet = read_packet(client)
        packet_id = assert_publish(
            packet, 5, qos=1, retain=True, payload=self.payload
        )
        if packet_id is None:
            raise AssertionError("proxied QoS 1 PUBLISH has no packet id")
        return packet, packet_id

    def _run_fallible(self) -> None:
        with self._accept() as first:
            with self._connect_session(first, session_present=False) as target:
                original, packet_id = self._read_publish(first)
                if original[0] & 0x08:
                    raise AssertionError("initial target PUBLISH unexpectedly set DUP")
                target.sendall(original)
                puback = read_packet(target)
                if self._packet_id(puback, 4) != packet_id:
                    raise AssertionError("target PUBACK Packet Identifier changed")
                # Discard PUBACK and close only the bridge-facing connection.

        with self._accept() as resumed:
            with self._connect_session(resumed, session_present=True) as target:
                retry, retry_packet_id = self._read_publish(resumed)
                if retry[0] & 0x08 == 0:
                    raise AssertionError("resumed target PUBLISH omitted DUP")
                if retry_packet_id != packet_id:
                    raise AssertionError(
                        "resumed target PUBLISH changed Packet Identifier"
                    )
                self.retry_held.set()
                if not self.allow_replay.wait(timeout=5):
                    raise RuntimeError("timed out waiting to release retry")
                target.sendall(retry)
                puback = read_packet(target)
                if self._packet_id(puback, 4) != packet_id:
                    raise AssertionError("resumed target PUBACK mismatch")
                resumed.sendall(puback)
                self.replay_complete.set()
                self._forward_until_disconnect(resumed, target)

    def _forward_until_disconnect(
        self, client: socket.socket, target: socket.socket
    ) -> None:
        while not self.stop_requested.is_set():
            try:
                packet = read_packet(client)
            except socket.timeout:
                continue
            target.sendall(packet)
            if packet[0] >> 4 == 14:
                return
            client.sendall(read_packet(target))

    def _wake_waiters(self) -> None:
        self.allow_replay.set()
        self.retry_held.set()
        self.replay_complete.set()

    def finish(self) -> None:
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("ACK-drop proxy did not stop")
        if self.error is not None:
            raise self.error


class Qos2PubcompDropProxy(_SessionProxy):
    def __init__(self, listen_port: int, target_port: int, payload: bytes):
        self.payload = payload
        self.first_pubcomp_dropped = threading.Event()
        self.ready_for_recovery = threading.Event()
        self.recovery_pubrel_seen = threading.Event()
        self.publish_count = 0
        self.packet_id: int | None = None
        super().__init__(listen_port, target_port, "mqtt-qos2-pubcomp-drop")

    def _run_fallible(self) -> None:
        with self._accept() as first:
            with self._connect_session(first, session_present=False) as target:
                publish = read_packet(first)
                packet_id = assert_publish(
                    publish, 5, qos=2, retain=False, payload=self.payload
                )
                if packet_id is None:
                    raise AssertionError("QoS 2 target PUBLISH has no packet id")
                if publish[0] & 0x08:
                    raise AssertionError("initial QoS 2 target PUBLISH set DUP")
                self.publish_count += 1
                self.packet_id = packet_id
                target.sendall(publish)
                pubrec = read_packet(target)
                if self._packet_id(pubrec, 5) != packet_id:
                    raise AssertionError("target PUBREC Packet Identifier changed")
                first.sendall(pubrec)
                pubrel = read_packet(first)
                if self._packet_id(pubrel, 6) != packet_id:
                    raise AssertionError("target PUBREL Packet Identifier changed")
                target.sendall(pubrel)
                pubcomp = read_packet(target)
                if self._packet_id(pubcomp, 7) != packet_id:
                    raise AssertionError("target PUBCOMP Packet Identifier changed")
                self.first_pubcomp_dropped.set()
                self._forward_until_closed(first, target)
        self.ready_for_recovery.set()

        with self._accept() as resumed:
            with self._connect_session(resumed, session_present=True) as target:
                packet = read_packet(resumed)
                if packet[0] >> 4 == 3:
                    self.publish_count += 1
                    raise AssertionError(
                        "recovered bridge sent a second target PUBLISH"
                    )
                if self._packet_id(packet, 6) != self.packet_id:
                    raise AssertionError(
                        "recovered target PUBREL changed Packet Identifier"
                    )
                self.recovery_pubrel_seen.set()
                target.sendall(packet)
                pubcomp = read_packet(target)
                if self._packet_id(pubcomp, 7) != self.packet_id:
                    raise AssertionError("recovered target PUBCOMP mismatch")
                resumed.sendall(pubcomp)
                self._forward_until_disconnect(resumed, target)

    def _forward_until_closed(
        self, client: socket.socket, target: socket.socket
    ) -> None:
        while not self.stop_requested.is_set():
            try:
                packet = read_packet(client)
            except (AssertionError, ConnectionResetError, OSError):
                return
            target.sendall(packet)
            if packet[0] >> 4 == 14:
                return
            client.sendall(read_packet(target))

    def _forward_until_disconnect(
        self, client: socket.socket, target: socket.socket
    ) -> None:
        while not self.stop_requested.is_set():
            try:
                packet = read_packet(client)
            except socket.timeout:
                continue
            target.sendall(packet)
            if packet[0] >> 4 == 14:
                return
            client.sendall(read_packet(target))

    def _wake_waiters(self) -> None:
        self.first_pubcomp_dropped.set()
        self.ready_for_recovery.set()
        self.recovery_pubrel_seen.set()


class TargetPublishDropProxy(_SessionProxy):
    def __init__(
        self, listen_port: int, target_port: int, payload: bytes, *,
        recovery_session_present: bool = True,
    ):
        self.payload = payload
        self.recovery_session_present = recovery_session_present
        self.first_publish_dropped = threading.Event()
        self.ready_for_recovery = threading.Event()
        self.recovery_connected = threading.Event()
        self.replay_complete = threading.Event()
        self.bridge_publish_count = 0
        self.forwarded_publish_count = 0
        self.packet_id: int | None = None
        super().__init__(listen_port, target_port, "mqtt-target-publish-drop")

    def _run_fallible(self) -> None:
        with self._accept() as first:
            with self._connect_session(first, session_present=False) as target:
                publish = read_packet(first)
                packet_id = assert_publish(
                    publish, 5, qos=2, retain=False, payload=self.payload
                )
                if packet_id is None:
                    raise AssertionError("QoS 2 target PUBLISH has no packet id")
                if publish[0] & 0x08:
                    raise AssertionError("initial target PUBLISH unexpectedly set DUP")
                self.bridge_publish_count += 1
                self.packet_id = packet_id
                self.first_publish_dropped.set()
                self._wait_until_closed(first)
        self.ready_for_recovery.set()

        with self._accept() as resumed:
            with self._connect_session(
                resumed, session_present=self.recovery_session_present
            ) as target:
                self.recovery_connected.set()
                if not self.recovery_session_present:
                    self._expect_close_without_publish(resumed)
                    return
                publish = read_packet(resumed)
                packet_id = assert_publish(
                    publish, 5, qos=2, retain=False, payload=self.payload
                )
                self.bridge_publish_count += 1
                if publish[0] & 0x08 == 0:
                    raise AssertionError("restored target PUBLISH omitted DUP")
                if packet_id != self.packet_id:
                    raise AssertionError(
                        "restored target PUBLISH changed Packet Identifier"
                    )
                target.sendall(publish)
                self.forwarded_publish_count += 1
                pubrec = read_packet(target)
                if self._packet_id(pubrec, 5) != packet_id:
                    raise AssertionError("restored target PUBREC mismatch")
                resumed.sendall(pubrec)
                pubrel = read_packet(resumed)
                if self._packet_id(pubrel, 6) != packet_id:
                    raise AssertionError("restored target PUBREL mismatch")
                target.sendall(pubrel)
                pubcomp = read_packet(target)
                if self._packet_id(pubcomp, 7) != packet_id:
                    raise AssertionError("restored target PUBCOMP mismatch")
                resumed.sendall(pubcomp)
                self.replay_complete.set()
                self._forward_until_disconnect(resumed, target)

    def _wait_until_closed(self, client: socket.socket) -> None:
        while not self.stop_requested.is_set():
            try:
                read_packet(client)
            except (AssertionError, ConnectionResetError, OSError):
                return

    def _expect_close_without_publish(self, client: socket.socket) -> None:
        while not self.stop_requested.is_set():
            try:
                packet = read_packet(client)
            except (AssertionError, ConnectionResetError, OSError):
                return
            if packet[0] >> 4 == 3:
                raise AssertionError(
                    "bridge published after target Session loss"
                )

    def _forward_until_disconnect(
        self, client: socket.socket, target: socket.socket
    ) -> None:
        while not self.stop_requested.is_set():
            try:
                packet = read_packet(client)
            except socket.timeout:
                continue
            target.sendall(packet)
            if packet[0] >> 4 == 14:
                return
            client.sendall(read_packet(target))

    def _wake_waiters(self) -> None:
        self.first_publish_dropped.set()
        self.ready_for_recovery.set()
        self.recovery_connected.set()
        self.replay_complete.set()


class SourcePubcompDropProxy(_SessionProxy):
    def __init__(self, listen_port: int, source_port: int, payload: bytes):
        self.payload = payload
        self.first_pubcomp_dropped = threading.Event()
        self.ready_for_recovery = threading.Event()
        self.recovery_pubcomp_seen = threading.Event()
        self.publish_count = 0
        self.packet_id: int | None = None
        super().__init__(listen_port, source_port, "mqtt-source-pubcomp-drop")

    def _run_fallible(self) -> None:
        with self._accept() as first:
            with self._connect_session(first, session_present=False) as source:
                subscribe = read_packet(first)
                if subscribe[0] >> 4 != 8:
                    raise AssertionError(
                        f"expected bridge SUBSCRIBE, got {subscribe.hex()}"
                    )
                source.sendall(subscribe)
                first.sendall(read_packet(source))
                publish = read_packet(source)
                packet_id = assert_publish_on_topic(
                    publish, 5, topic="local/sensors/room", qos=2,
                    retain=False, payload=self.payload,
                )
                if packet_id is None:
                    raise AssertionError("source QoS 2 PUBLISH has no packet id")
                self.publish_count += 1
                self.packet_id = packet_id
                first.sendall(publish)
                pubrec = read_packet(first)
                if self._packet_id(pubrec, 5) != packet_id:
                    raise AssertionError("source PUBREC Packet Identifier changed")
                source.sendall(pubrec)
                pubrel = read_packet(source)
                if self._packet_id(pubrel, 6) != packet_id:
                    raise AssertionError("source PUBREL Packet Identifier changed")
                first.sendall(pubrel)
                pubcomp = read_packet(first)
                if self._packet_id(pubcomp, 7) != packet_id:
                    raise AssertionError("source PUBCOMP Packet Identifier changed")
                self.first_pubcomp_dropped.set()
                self._forward_until_closed(first, source)
        self.ready_for_recovery.set()

        with self._accept() as resumed:
            with self._connect_session(resumed, session_present=True) as source:
                packet = read_packet(source)
                if packet[0] >> 4 == 3:
                    self.publish_count += 1
                    raise AssertionError(
                        "source broker repeated PUBLISH instead of PUBREL"
                    )
                if self._packet_id(packet, 6) != self.packet_id:
                    raise AssertionError(
                        "recovered source PUBREL changed Packet Identifier"
                    )
                resumed.sendall(packet)
                pubcomp = read_packet(resumed)
                if self._packet_id(pubcomp, 7) != self.packet_id:
                    raise AssertionError("recovered source PUBCOMP mismatch")
                source.sendall(pubcomp)
                self.recovery_pubcomp_seen.set()
                self._forward_until_disconnect(resumed, source)

    def _forward_until_closed(
        self, client: socket.socket, source: socket.socket
    ) -> None:
        while not self.stop_requested.is_set():
            try:
                packet = read_packet(client)
            except (AssertionError, ConnectionResetError, OSError):
                return
            source.sendall(packet)
            if packet[0] >> 4 == 14:
                return
            client.sendall(read_packet(source))

    def _forward_until_disconnect(
        self, client: socket.socket, source: socket.socket
    ) -> None:
        while not self.stop_requested.is_set():
            try:
                packet = read_packet(client)
            except socket.timeout:
                continue
            source.sendall(packet)
            if packet[0] >> 4 == 14:
                return
            client.sendall(read_packet(source))

    def _wake_waiters(self) -> None:
        self.first_pubcomp_dropped.set()
        self.ready_for_recovery.set()
        self.recovery_pubcomp_seen.set()
