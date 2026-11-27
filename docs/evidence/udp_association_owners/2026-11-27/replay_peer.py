"""Replay the unchanged TUIC gate plus bounded, exactly accounted UDP bursts.

Run under zig-tree-guard with the built TUIC server and pinned sing-box paths.
Original assertions and budgets are retained; each extra wave is eight packets.
"""
from pathlib import Path
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[4]
GATE_SHA256 = "0a9cf4697033210b3610ffc97389c59dad6d52b500ae0726aabcec52e89f47d1"
PEER_SHA256 = "6546126c1759683fe85798da92409215d53c50e0f2b346b4f74a61babc8dbec2"
EXTRA = r'''import json
for wave, size in enumerate(((32, 64, 256, 512) * 3)[:9]):
    expected_burst = []
    for index in range(8):
        message = bytes([wave, index]) + bytes([index + 32]) * (size - 2)
        expected_burst.append(message)
        if wave % 2:
            host = b"127.0.0.1"
            header = b"\x00\x00\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", target[1])
        else:
            header = b"\x00\x00\x00\x01" + socket.inet_aton(target[0]) + struct.pack("!H", target[1])
        udp.sendto(header + message, relay)
    remaining = set(expected_burst)
    received_order = []
    for _ in expected_burst:
        data, _ = udp.recvfrom(65535)
        if len(data) < 10 or data[3] != 1 or data[10:] not in remaining:
            sys.exit("socks udp burst payload/duplicate mismatch: %r" % (data,))
        remaining.remove(data[10:])
        received_order.append(list(data[10:12]))
    if remaining:
        sys.exit("socks udp burst missing payloads: %r" % (remaining,))
    print(json.dumps({"burst_wave": wave, "received_order": received_order,
                      "exact_payloads": len(expected_burst)}), file=sys.stderr)
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def free_ports():
    for port, kind in ((18450, socket.SOCK_STREAM), (18451, socket.SOCK_STREAM),
                       (18452, socket.SOCK_DGRAM), (18453, socket.SOCK_DGRAM)):
        with socket.socket(socket.AF_INET, kind) as sock:
            if kind == socket.SOCK_STREAM:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            if kind == socket.SOCK_STREAM:
                sock.listen(1)


def main():
    server, peer = map(lambda p: str(Path(p).resolve()), sys.argv[1:3])
    gate = ROOT / "tools/interop/tuic_sing_box.sh"
    assert digest(gate) == GATE_SHA256, "original gate source changed"
    assert digest(peer) == PEER_SHA256, "pinned sing-box binary changed"
    source = gate.read_text()
    assert source.count('print("udp-ok")') == 1
    receipt = {"server_sha256": digest(server), "peer_sha256": digest(peer),
               "original_gate_sha256": GATE_SHA256,
               "original_udp_payload_bytes": len(b"netz-tuic-udp-ok"),
               "original_gate_reported_udp_bytes": 17, "checks": []}
    output = Path(__file__).with_name("peer.json")
    bursts_only = sys.argv[3:] == ["--bursts-only"]
    if bursts_only:
        previous = json.loads(output.read_text())
        assert previous["server_sha256"] == receipt["server_sha256"]
        assert previous["peer_sha256"] == receipt["peer_sha256"]
        receipt["checks"] = [row for row in previous["checks"] if not row["extra_bursts"]]
        assert len(receipt["checks"]) == 2 and all(row["exit_code"] == 0 for row in receipt["checks"])
        receipt["retained_order_assumption_failure"] = "failed_order_assumption.json"
    with tempfile.TemporaryDirectory(prefix="netz-udp-peer-") as directory:
        burst = Path(directory) / "burst.sh"
        burst.write_text(source.replace('print("udp-ok")', EXTRA + 'print("udp-ok")'))
        receipt["burst_gate_sha256"] = digest(burst)
        for extra in ((True,) if bursts_only else (False, True)):
            for mode in ("native", "quic"):
                free_ports()
                env = dict(os.environ, SING_BOX_BIN=peer, TUIC_UDP_RELAY_MODE=mode)
                command = ["bash", str(burst if extra else gate), server]
                start = time.monotonic()
                run = subprocess.run(command, cwd=ROOT, env=env,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                text = run.stdout.decode(errors="replace")
                record = {"mode": mode, "extra_bursts": extra, "exit_code": run.returncode,
                          "elapsed_seconds": time.monotonic() - start, "output": text,
                          "output_sha256": hashlib.sha256(run.stdout).hexdigest(),
                          "extra_packets": 72 if extra else 0,
                          "extra_payload_sizes": ([32, 64, 256, 512] * 3)[:9] if extra else []}
                receipt["checks"].append(record)
                output.write_text(json.dumps(receipt, indent=2) + "\n")
                print(json.dumps(record), flush=True)
                if run.returncode:
                    raise SystemExit(run.returncode)


if __name__ == "__main__":
    main()
