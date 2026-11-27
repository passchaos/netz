# TUIC receive parser retirement on RESET_STREAM

Base: `beebda64adcb0f7076a42643c259444725440a0d`. Status: parser retirement
is qualified; the full HTTP-family optimization goal remains active.

Both receive owners previously handled RESET_STREAM by closing matching relay
and association state, leaving an incomplete uni command's parser slot active.
Each parser pool has eight slots. Cancellation therefore retained a slot even
though QUIC had retired the receive stream.

The regression uses actual protected STREAM packets to deliver 3000 bytes of
an incomplete 4096-byte TUIC Packet, then receives a protected RESET_STREAM and
passes its decoded stream ID to the actual receive owner. Both unchanged
owners fail the assertion that the slot is inactive: 55/57 scoped tests pass,
with two owner failures. The failing native backend is POSIX Threaded at zero
async capacity; failure stops before the application-backend invocation.
[`before.json`](before.json) and [`before.log`](before.log) retain that
checkpoint. The initial test-fixture variable-shadowing compile failure is
preserved separately in `failed_compile.*`.

The fix gives each owner one reset entry point, which retires the matching
uni parser before its existing relay and association handling. Parser
cancellation clears active state and byte length while retaining allocation.
FIN uses the same slot release, and incomplete FIN still returns its original
protocol error. Pool count and byte limits are unchanged.

The shared assertion helper also checks that an unknown reset preserves both
active inputs, a reset leaves the sibling's exact byte intact, and the retired
slot retains its heap pointer and capacity. After warmup, 128 subsequent owner
cancel/reuse cycles run with an allocator rejecting every allocation. Those
reuse cycles invoke the real owner reset function directly; the initial
retirement is driven by the decoded protected-wire reset. Passing execution
must cover POSIX Threaded at zero async capacity and the application backend.

Final qualification is recorded in [`validation.json`](validation.json):

- 83 related native tests pass, including both protected-wire owner cases on
  POSIX Threaded at zero async capacity and the application backend. Original
  FIN, PacketStream, relay and ordered authentication cases remain.
- Selected Windows compilation passes 8/8; this is compilation, not native
  Windows execution. The native ReleaseSafe peer server builds 9/9.
- All eight pinned shared/standalone native/quic original/extended peer gates
  pass in [`peer.json`](peer.json), preserving the unchanged 131072-byte TCP
  comparison, UDP assertion, small-packet matrix and QUIC 2/4-KiB packets.
- Guarded identity validation checks current sources, native names and binary.
  Evidence audit reports 352 source-bearing files, 11337 entries, three
  unresolved historical mappings within the unchanged limit of 24, and zero
  invalid or unreadable records. Historical hashes remain unchanged.

Native execution, compilation and source findings remain separate evidence. No
throughput, p99 or overall RSS claim follows from these lifecycle assertions.
