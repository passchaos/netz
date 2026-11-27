#!/usr/bin/env python3
"""Pinned shared/serveOne matrices and standalone cold admission checks.

Run under zig-tree-guard. An optional output path receives a fresh receipt;
omitting it preserves all checked-in historical records.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import tempfile
import time

root = Path(__file__).resolve().parents[4]
baseline = root / 'docs/evidence/udp_association_owners/2026-11-27/replay_peer.py'
spec = importlib.util.spec_from_file_location('baseline_peer', baseline)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('server', nargs='?', default=str(root / 'zig-out/bin/netz-tuic-server'))
parser.add_argument('peer', nargs='?', default='/tmp/netz-peer-sing-box-1.14.4/sing-box')
parser.add_argument('output', nargs='?')
parser.add_argument('--admission-rounds', type=int, default=0, help='Run this many unchanged standalone/native gates and retain server/client diagnostics')
args = parser.parse_args()
if not 0 <= args.admission_rounds <= 64:
    parser.error('admission rounds must be between 0 and 64')
server = str(Path(args.server).resolve())
peer = str(Path(args.peer).resolve())
output = Path(args.output) if args.output else None
if output is not None and output.exists():
    parser.error('choose a fresh receipt path')
assert base.digest(baseline) == 'cd6b4016e81d6799eeb34467824e757ec17bde7172e70ed56269481f34b9ae6c'
assert base.digest(peer) == base.PEER_SHA256
original_gate = root / 'tools/interop/tuic_sing_box.sh'
assert base.digest(original_gate) == base.GATE_SHA256
source = original_gate.read_text()

large = r'''if UDP_MODE == "quic":
    for wave, size in enumerate((2048, 4096), 9):
        remaining = set()
        for index in range(8):
            message = bytes([wave, index]) + bytes([index + 32]) * (size - 2)
            remaining.add(message)
            udp.sendto(b"\x00\x00\x00\x01" + socket.inet_aton(target[0]) + struct.pack("!H", target[1]) + message, relay)
        received = []
        for _ in range(8):
            data, _ = udp.recvfrom(65535)
            if len(data) < 10 or data[3] != 1 or data[10:] not in remaining:
                sys.exit("large TUIC packet payload/duplicate mismatch")
            remaining.remove(data[10:])
            received.append(list(data[10:12]))
        if remaining:
            sys.exit("large TUIC packet missing payloads")
        print(json.dumps({"large_wave": wave, "bytes": size, "received_order": received, "exact_payloads": 8}), file=sys.stderr)
'''
receipt = {
    'server_sha256': base.digest(server),
    'peer_sha256': base.digest(peer),
    'original_gate_sha256': base.GATE_SHA256,
    'baseline_bursts_source_sha256': base.digest(baseline),
    'admission_rounds': args.admission_rounds,
    'checks': [],
}
cases = [('single', 'native', False)] * args.admission_rounds if args.admission_rounds else [
    (owner, mode, extended)
    for owner in ('shared', 'single')
    for extended in (False, True)
    for mode in ('native', 'quic')
]
with tempfile.TemporaryDirectory(prefix='netz-tuic-packet-') as temporary:
    directory = Path(temporary)
    wrapper = directory / 'single-server.sh'
    wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(server) + ' --single "$@"\n')
    wrapper.chmod(0o755)
    for iteration, (owner, mode, extended) in enumerate(cases):
        base.free_ports()
        content = source
        if extended:
            content = content.replace('print("udp-ok")', 'UDP_MODE=' + repr(mode) + '\n' + base.EXTRA + large + 'print("udp-ok")')
        if args.admission_rounds:
            server_log = directory / 'server.log'
            client_log = directory / 'client.log'
            content = content.replace('--allow-all >/dev/null 2>&1 &', '--allow-all >' + shlex.quote(str(server_log)) + ' 2>&1 &')
            content = content.replace('run -c "$work/sing-box.json" >/dev/null 2>&1 &', 'run -c "$work/sing-box.json" >' + shlex.quote(str(client_log)) + ' 2>&1 &')
        gate = directory / 'gate.sh'
        gate.write_text(content)
        command = ['bash', str(gate), server if owner == 'shared' else str(wrapper)]
        env = dict(os.environ, SING_BOX_BIN=peer, TUIC_UDP_RELAY_MODE=mode)
        start = time.monotonic()
        run = subprocess.run(command, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        row = {
            'owner': owner, 'mode': mode, 'extended': extended,
            'exit_code': run.returncode, 'elapsed_seconds': time.monotonic() - start,
            'gate_sha256': base.digest(gate), 'output': run.stdout.decode(errors='replace'),
            'output_sha256': hashlib.sha256(run.stdout).hexdigest(),
            'small_packets': 72 if extended else 0,
            'large_packets': 16 if extended and mode == 'quic' else 0,
        }
        if args.admission_rounds:
            row.update(iteration=iteration, server_log=server_log.read_text(errors='replace'), client_log=client_log.read_text(errors='replace'))
        receipt['checks'].append(row)
        if output is not None:
            output.write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(row), flush=True)
        if run.returncode:
            raise SystemExit(run.returncode)
if output is None:
    print(json.dumps(receipt), flush=True)
