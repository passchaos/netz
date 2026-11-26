# HTTP/2 inbound field-section boundary

Base revision: `4a25e2fb80e1364fd4cdf56a15dfda1f92fe2fb9`.
This change moves three existing inbound header operations out of the large
connection implementation and keeps their state with the original connection.

## Responsibility and ownership

[The stateless Reader](../../../../src/http2/runtime/headers/inbound.zig)
groups field-section decode, deferred-header completion and CONTINUATION
assembly. [Connection](../../../../src/http2/runtime/connection.zig) owns the
HPACK decoder, scratch allocation, pending duplex header slots, transport
reader mode and protocol-error state. It passes existing private operations
as compile-time callbacks instead of widening their public visibility.

The Reader retains these contracts:

- Complete single-frame HEADERS bypass continuation scratch. Collected
  CONTINUATION bytes use the original connection-owned scratch; no reader or
  mutable header state is added.
- Duplex/push continuations come from the already-selected transport owner.
  Older queued sibling frames do not precede that field section. Ordinary and
  raw reads retain their original queue policy and deadline.
- Deferred field sections drain their exact queued continuation count, resume
  the existing pending header, and release that slot after transferring owned
  fields. Existing frame cleanup and reader-mode restoration stay in place.
- A complete output-limit rejection still applies HPACK changes and records a
  stream-local error. Compression failure or incomplete excessive assembly
  preserves its original connection-fatal classification.

Existing public imports and Connection methods remain unchanged. Connection
shrinks from 16,093 to 15,982 lines, with a 154-line extracted module. This is a
responsibility split; runtime throughput, compilation speed and code-size
benefits were not measured.

## Verification and qualification

All checks ran serially under the shared Zig guard with Zig 0.16.0. The selected
native scope passes 62 tests: 27 named HTTP/2 behaviors and 35 imported support
or aggregator cases. Matching Windows selected tests compile, with all eight
build steps passing. Existing tests cover malformed/unterminated CONTINUATION,
single-frame scratch bypass, complete field/byte-limit rejection, HPACK reuse
across aggregate/callback/duplex/server/push modes, parent/sibling isolation,
deferred duplex heads and aggregate/streaming deadlines.

A source comparison also verifies that all three migrated control-flow bodies
retain their original tokens after callback conversion. The value receiver of
`maxContinuationFrames` uses an explicit dereference, matching the original
method-call coercion. This source comparison complements the real-socket tests;
it does not replace runtime ownership qualification.

[validation.json](validation.json) records source hashes, exact selected
commands and raw-log hashes. Local macOS results and Windows compilation do
not establish pinned native Windows/Linux or complete acceptance. The separate
Windows TCP completion experiment on the base revision is still awaiting its
native CI result; this extraction does not claim to repair that TLS failure.
