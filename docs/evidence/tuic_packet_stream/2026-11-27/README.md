# TUIC PacketStream and standalone owner qualification

Base: `3129606a525108628ddc2b598995f0ae9ceaaca9`. Status: the scoped feature,
including the authentication-order follow-up, is qualified. The full
HTTP/QUIC/WebSocket/WebTransport optimization goal remains active. The earlier
80-test and first eight-peer checkpoints remain historical records.
[`validation.json`](validation.json) records exact commands, final source
hashes, binary identity and separate execution/compilation checkpoints.

TUIC QUIC-mode replies use one stream per encoded Packet on both shared and
standalone paths. Shared sends attempt one packet-sized STREAM frame per call;
standalone sends retain the original 100-ms quantum and 100-attempt limit.
Both retain an immutable payload identity and committed cursor until final FIN.
Cancellation releases the payload borrow and retains its stream ID until reset
acceptance or connection destruction. A connection-owned queue has 64 reset
slots and attempts at most eight resets per turn; saturation stops the
connection. The TCP relay adapter and TUIC share the packet-budget primitive.

Both uni-parser pools have eight slots, reusing bounded storage through FIN.
Their byte limit includes the configured UDP payload plus a maximum 269-byte
Packet header. A valid 253-byte domain exposed the old 256-byte address scratch
bound: its encoded address needs 257 bytes. CONNECT and Packet now share a
259-byte wire bound. The older
[UDP ownership evidence](../../udp_association_owners/2026-11-27/README.md)
incorrectly described 64 parser slots; that prose is a historical error, and
its source/binary hashes remain unchanged.

Standalone TCP now uses the existing persistent relay queues. Target readers
and writers only access TCP, and the connection loop owns QUIC receive/send.
Outbound DATA retains its cursor through refusal; FIN follows complete DATA.
TCP send shutdown waits for all inbound bytes, and relay cleanup waits for the
committed QUIC FIN and drained input. Setup publishes the relay only after
concurrent admission and initial payload setup succeed.

Final functional qualification:

- The guarded native relay/TUIC scope passes 81 tests on macOS ARM64. Original
  relay FIFO, STREAM prefix, shared TUIC TCP/large-body and parser lifecycle
  cases remain. Added protected-packet cases cover 4-KiB splitting on one
  stream, final FIN, a fresh next-Packet stream, refused flow credit, exact
  positive-count prefixes with trailing errors, timed suffix continuation,
  expired admission, deferred reset ownership and retained parser allocation.
  The added standalone case forces a protected CONNECT/1024-byte payload/FIN
  packet to arrive before AUTH, then verifies the complete echo and final FIN
  after authentication on both native backends.
- The pinned sing-box 1.14.4 matrix passes all eight shared/`serveOne()` ×
  native/quic × original/extended gates in [`peer.json`](peer.json). Every gate
  keeps the original 131072-byte TCP comparison and UDP assertion. Each owner
  also passes 72 small replies in each mode; QUIC mode adds eight 2048-byte and
  eight 4096-byte replies. Each reply's complete payload, uniqueness and count
  are checked. External UDP order is recorded without an ordering assertion;
  internal FIFO assertions remain exact.
- Twenty separate unchanged standalone/native gates also pass in
  [`admission_peer.json`](admission_peer.json), each retaining the original
  131072-byte TCP and UDP assertions and its existing deadlines. The
  authentication-order failure is resolved by the bounded pending-input change.
- Windows selected test compilation and the explicit Windows server build
  each pass 8/8 steps; the native ReleaseSafe server builds 9/9. Guarded identity
  validation verifies the current sources/binary, original named cases and
  all peer rows. Evidence audit reports 349 source-bearing files, 11326 entries,
  three unresolved historical mappings within the unchanged limit of 24, and
  zero invalid or unreadable records. Historical stale hashes remain.
  Windows compilation does not establish native Windows execution.

Native protected-datagram cases run with POSIX Threaded at zero async capacity
and the application backend. The earlier 64-test integration and 58-test
PacketStream checkpoints overlap the final 81-test scope; they are not added
together. No throughput, p99, allocation-free encoding or RSS claim follows
from these functional gates.

The first standalone peer matrix failed SOCKS connect. Replacing inline-capable
reader admission with explicit `concurrent` alone failed again. The captured
phase trace then verified authentication (50 bytes and FIN), CONNECT (9 bytes)
and HTTP request input (86 bytes), while the peer still received no HTTP body.
The final owner-queue change passes all original gates. The old source held a
mutex across QUIC receive while the TCP reader also sent QUIC; the precise
attribution to mutex starvation is unqualified. Rejected runs, phase logs and
call graphs remain in the `failed_single_*` records. The long-domain
`BufferTooSmall` failure remains in `failed_address_scratch.*`.

A later documented replay failed standalone admission on the same binary after
the first complete passing matrix. A diagnostic rerun captured
`AuthenticationRequired` on its third cold connection. The deterministic
native case sends a protected, coalesced CONNECT plus 1024-byte payload and FIN
before AUTH, waiting for its ACK inside one five-second deadline. The unchanged
production path fails with `AuthenticationRequired` (57/58 scoped tests pass).
Standalone now retains bounded request input and FIN before authentication,
resumes target connection only after token verification, and uses the configured
pending-byte bound instead of a fixed 512-byte buffer. Final qualification
passes the ordered native case, complete eight-gate matrix and 20 cold gates.
Rejected results remain in
`failed_authentication_order_*` and `failed_single_documented_replay.*`.

The original gate prints `udp_bytes=17`; its unchanged payload literal contains
16 bytes. The final validation records that difference explicitly.

Replay with a fresh output path under the guard:

```sh
/Users/bytedance/.local/share/traex-guard/zig-tree-guard -- \
  /usr/bin/python3 docs/evidence/tuic_packet_stream/2026-11-27/replay_peer.py \
  zig-out/bin/netz-tuic-server /tmp/netz-peer-sing-box-1.14.4/sing-box \
  /tmp/netz-tuic-packet-replay.json
```

For the separate cold-admission sequence, append `--admission-rounds=20` and
choose another fresh receipt path. The same original TCP/UDP gates and budgets
apply. Each failed attempt would stop the sequence and retain its diagnostics.

The peer SHA256 is
`6546126c1759683fe85798da92409215d53c50e0f2b346b4f74a61babc8dbec2`;
the original gate SHA256 is
`0a9cf4697033210b3610ffc97389c59dad6d52b500ae0726aabcec52e89f47d1`.
The replay also pins the prior burst generator source. Omitting the output
argument prints results and preserves checked-in receipts.

Prior-base [CI run 45924108524, attempt 1](https://github.com/passchaos/netz/actions/runs/45924108524)
is terminal. Portable Windows/macOS/aarch64 Linux compilation and preflight
pass. Native x86_64 Linux and complete fail; the complete public annotation
reaches 6355/7515 tests and reports exit 137. Linux annotations include
`Resource temporarily unavailable` while creating a process and missing native
coverage markers. Those observations do not attribute a failure to TUIC or
establish full-library acceptance. [`prior_ci.json`](prior_ci.json) and
[`prior_complete_annotations.json`](prior_complete_annotations.json) retain
the actual attempt's terminal state. Original CI commands, pins and budgets
are unchanged.

Finite QUIC input drains, fair ready scheduling, mixed workloads, reusable
encoded blocks and full R4-R9 acceptance remain open in
[the backlog](../../../architecture/optimization-backlog.md).
