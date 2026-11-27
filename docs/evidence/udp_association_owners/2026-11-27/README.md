# UDP association owner qualification

Status: bounded shared-owner feature qualified; full R4-R9 and HTTP-family
acceptance remain active. Base: `adf90ce0048e02f3d82de1a70acef1d081be3e15`.
[`validation.json`](validation.json) records final source hashes, exact commands,
binary identity and the separate native/compilation/peer checkpoints.

Both shared QUIC pumps now publish target datagrams into 32-slot concurrent
resolvers/senders and collect raw replies from eight-slot concurrent receivers.
Hysteria reserves before enqueue and refunds uncommitted bytes on completion
or joined retirement. Both protocols retain encoded replies in one eight-slot
FIFO through refusal. Received packets queued before a later fatal receive
are encoded before association retirement. TUIC enforces the configured
association limit at the common creation boundary.

Final functional and platform qualification:

- 75 scoped macOS ARM64 tests passed, including the original TUIC concurrent
  TCP/large-body and Hysteria shared TCP/UDP, packetization and maximum-rate
  cases. Added cases cover immutable payload/host storage, full queues, exact
  committed prefixes, allocation rejection, zero/truncated/positive-count
  receives, blocked DNS deadline/cancellation, healthy siblings and exact
  shared credit retirement. The new fatal-next-receive case verifies the last
  queued payload, numeric reply host and separate port before cleanup.
- The TUIC parser case executes 128 split-command/FIN lifecycles and rejects
  an incomplete final command without retaining its parser slot. Both shared
  server test roots are explicitly reachable from narrow protocol filters.
- 58 separate standalone Hysteria tests passed after the numeric host formatter
  was applied to both shared and standalone reply paths. Original payload,
  rate and cancellation assertions remain.
- The selected shared/UDP Windows scope compiled in 8/8 steps. A separate
  standalone Hysteria Windows scope also compiled in 8/8 steps. These are
  compilation results, not native Windows execution.
- Final ReleaseSafe TUIC peer server build passed 9/9 steps. The unchanged
  sing-box gate passed native and QUIC UDP modes, retaining its exact 131072-byte
  TCP body comparison and original UDP checks. Additional nine waves of eight
  packets passed in each mode: all 72 payloads matched exactly, with no duplicate
  among the expected replies. Sizes cycle through 32/64/256/512 bytes, alternate
  IP/numeric-domain address encoding, and cross the original 64 parser-slot
  capacity. [`peer.json`](peer.json) retains per-wave observed reply order.
- Guarded final formatting, original-source identity and evidence audit passed.
  Audit reports three unresolved historical mappings within the unchanged
  limit of 24, with zero invalid or unreadable records. Historical stale hashes
  remain recorded.

Native datagram cases use POSIX Threaded with zero async capacity and the
application backend. Windows datagram execution is defined to use the
application backend; it was not executed locally on macOS. The initial 13-test
Session checkpoint and 72-test integration checkpoint remain separate historical
snapshots inside the validation record. Counts overlap and are not a distinct
test total.

The fixed sing-box 1.14.4 peer exposed response stream reuse: its pinned
`sing-quic@7e0a5869a5f4` reader consumes one Packet and returns with `CancelRead`
for each unidirectional stream. The shared server now sends one complete Packet
with FIN on a fresh stream, retaining that stream across refusal and clearing
it only after committed output. [`failed_quic_burst.json`](failed_quic_burst.json)
retains the pre-fix 32-packet QUIC-mode timeout. The corrected 72-packet matrix
includes the same first four waves plus five more waves.

An initial burst check incorrectly required a global UDP reply order and
stopped after its first out-of-order reply. That failed assumption remains in
[`failed_order_assumption.json`](failed_order_assumption.json). The final peer
check validates complete bytes, uniqueness and expected count; the native
sender and encoded-reply FIFO retain their exact ordering assertions. No cause
is attributed to a particular peer/network stage from the external order alone.

The original gate prints `udp_bytes=17`; its pinned payload literal contains
16 bytes. The original source, payload assertion and historical output remain
unchanged, while the final peer receipt records both values explicitly.

[`service.json`](service.json) records one actual service call over 32 idle
associations on each native backend, with zero new target receive callbacks.
The measured calls are diagnostic single-turn observations. There is no matched
UDP baseline, overall throughput/p99 comparison or RSS qualification. Raw
receive plus payload/host capacity is conservatively bounded by 72 times the
configured datagram limit: 288 KiB per association at the default 4096 bytes.
The observed Session metadata is 6000 bytes. Backend/task/kernel memory,
resolver allocations and encoded replies are separate costs.

Replay the unchanged gates and extra matrix under the guard:

```sh
/Users/bytedance/.local/share/traex-guard/zig-tree-guard -- \
  /usr/bin/python3 docs/evidence/udp_association_owners/2026-11-27/replay_peer.py \
  zig-out/bin/netz-tuic-server /tmp/netz-peer-sing-box-1.14.4/sing-box
```

Prior-commit [CI run 45916032300, attempt 1](https://github.com/passchaos/netz/actions/runs/45916032300)
is terminal. Portable compilation passed; the Windows native protocol step
exceeded its existing five-minute budget before combined test names appeared.
The complete gate ended with exit 137 and support/fuzz progress in its public
tail, which does not establish complete-library acceptance. CI commands,
budgets, pins and original named protocol assertions remain unchanged.

Finite QUIC input drains, fair ready scheduling, larger mixed workloads,
encoded-packet storage reuse and full acceptance remain open. Standalone TUIC
still has the association stream reuse source finding and needs a separate
native follow-up. Large UDP responses above negotiated peer MTU are also
unqualified by this small-packet matrix. See [the ownership design](../../../architecture/proxy-udp-ownership.md)
and [optimization backlog](../../../architecture/optimization-backlog.md).
