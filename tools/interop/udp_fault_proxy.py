#!/usr/bin/env python3
"""Loopback UDP relay with explicitly armed deterministic one-way faults."""

import argparse
import selectors
import socket


class FaultState:
    def __init__(self, mode: str, loss_pct: int, reorder_every: int) -> None:
        self.mode = mode
        self.loss_pct = loss_pct
        self.reorder_every = reorder_every
        self.random_state = 0x57544558544C4F53
        self.armed = False
        self.considered = 0
        self.dropped = 0
        self.corrupted = 0
        self.held = 0
        self.reordered = 0
        self.pending: tuple[bytes, tuple[str, int]] | None = None
        self.force_next = False
        self.single_shot = False

    def arm(self, force_next: bool = False, single_shot: bool = False) -> None:
        if self.armed:
            raise RuntimeError("proxy already armed")
        self.armed = True
        self.force_next = force_next
        self.single_shot = single_shot

    def xorshift(self) -> int:
        value = self.random_state
        mask = (1 << 64) - 1
        value = (value ^ (value << 13)) & mask
        value ^= value >> 7
        value = (value ^ (value << 17)) & mask
        self.random_state = value
        return self.random_state

    def forward(self, sock: socket.socket, payload: bytes, target: tuple[str, int]) -> None:
        if not self.armed:
            sock.sendto(payload, target)
            return
        self.considered += 1
        if self.mode == "loss":
            selected = self.force_next or self.xorshift() % 100 < self.loss_pct
            self.force_next = False
            if selected:
                self.dropped += 1
                if self.single_shot:
                    self.armed = False
                    self.single_shot = False
                return
            sock.sendto(payload, target)
            return
        if self.mode == "corrupt":
            selected = self.force_next or self.xorshift() % 100 < self.loss_pct
            self.force_next = False
            if selected:
                if not payload:
                    raise RuntimeError("cannot corrupt an empty UDP datagram")
                damaged = bytearray(payload)
                damaged[-1] ^= 0x01
                sock.sendto(bytes(damaged), target)
                self.corrupted += 1
                if self.single_shot:
                    self.armed = False
                    self.single_shot = False
                return
            sock.sendto(payload, target)
            return
        if self.pending is not None:
            sock.sendto(payload, target)
            held_payload, held_target = self.pending
            self.pending = None
            sock.sendto(held_payload, held_target)
            self.reordered += 1
            if self.single_shot:
                self.armed = False
                self.single_shot = False
            return
        if self.force_next or self.considered % self.reorder_every == 0:
            self.force_next = False
            self.pending = (bytes(payload), target)
            self.held += 1
            return
        sock.sendto(payload, target)

    def flush(self, sock: socket.socket) -> None:
        if self.pending is None:
            return
        payload, target = self.pending
        self.pending = None
        sock.sendto(payload, target)

    def summary(self) -> str:
        base = (
            f"considered={self.considered} dropped={self.dropped} "
            f"held={self.held} reordered={self.reordered}"
        )
        if self.mode == "corrupt":
            return base + f" corrupted={self.corrupted}"
        return base


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-port", type=int, required=True)
    parser.add_argument(
        "--fault", choices=("loss", "reorder", "corrupt"), required=True
    )
    parser.add_argument("--loss-pct", type=int, default=5)
    parser.add_argument("--reorder-every", type=int, default=5)
    parser.add_argument(
        "--direction", choices=("client", "server"), default="client"
    )
    parser.add_argument(
        "--scope",
        choices=(
            "wtransport-client-outbound",
            "netz-client-outbound",
            "quic-go-client-outbound",
            "netz-server-outbound",
            "quic-go-server-outbound",
            "netz-client-handshake-outbound",
            "quic-go-client-handshake-outbound",
            "netz-server-handshake-outbound",
            "quic-go-server-handshake-outbound",
        ),
        default="wtransport-client-outbound",
    )
    args = parser.parse_args()
    if not 1 <= args.server_port <= 65535:
        raise ValueError("invalid server port")
    if not 1 <= args.loss_pct <= 100 or args.reorder_every < 2:
        raise ValueError("invalid fault configuration")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    control.bind(("127.0.0.1", 0))
    control.listen(1)
    selector = selectors.DefaultSelector()
    selector.register(udp, selectors.EVENT_READ, "udp")
    selector.register(control, selectors.EVENT_READ, "listen")
    print(f"UDP_FAULT_PROXY_PORT={udp.getsockname()[1]}", flush=True)
    print(f"UDP_FAULT_CONTROL_PORT={control.getsockname()[1]}", flush=True)

    server = ("127.0.0.1", args.server_port)
    client: tuple[str, int] | None = None
    control_conn: socket.socket | None = None
    control_buffer = bytearray()
    fault = FaultState(args.fault, args.loss_pct, args.reorder_every)
    done = False
    while not done:
        for key, _ in selector.select(timeout=10):
            if key.data == "udp":
                payload, source = udp.recvfrom(65_535)
                if source == server:
                    if client is not None:
                        if args.direction == "server":
                            fault.forward(udp, payload, client)
                        else:
                            udp.sendto(payload, client)
                else:
                    if client is None:
                        client = source
                    elif source != client:
                        raise RuntimeError("proxy received a second client tuple")
                    if args.direction == "client":
                        fault.forward(udp, payload, server)
                    else:
                        udp.sendto(payload, server)
            elif key.data == "listen":
                control_conn, _ = control.accept()
                control_conn.setblocking(False)
                selector.register(control_conn, selectors.EVENT_READ, "control")
            else:
                assert control_conn is not None
                chunk = control_conn.recv(4096)
                if not chunk:
                    raise RuntimeError("proxy control connection closed early")
                control_buffer.extend(chunk)
                while b"\n" in control_buffer:
                    raw, _, remainder = control_buffer.partition(b"\n")
                    control_buffer = bytearray(remainder)
                    command = raw.decode("ascii")
                    if command in ("arm", "arm-next", "arm-once"):
                        fault.arm(
                            command in ("arm-next", "arm-once"),
                            command == "arm-once",
                        )
                        control_conn.sendall(b"armed\n")
                    elif command == "disarm":
                        fault.armed = False
                        fault.flush(udp)
                        fault.force_next = False
                        fault.single_shot = False
                        control_conn.sendall(("disarmed " + fault.summary() + "\n").encode())
                    elif command == "stop":
                        fault.armed = False
                        fault.flush(udp)
                        fault.force_next = False
                        fault.single_shot = False
                        control_conn.sendall(("stopped " + fault.summary() + "\n").encode())
                        done = True
                    else:
                        raise RuntimeError(f"unknown proxy command {command!r}")
    print(
        "udp fault proxy passed: "
        f"fault={args.fault} fault_direction={args.direction} "
        f"fault_scope={args.scope} "
        + fault.summary(),
        flush=True,
    )


if __name__ == "__main__":
    main()
