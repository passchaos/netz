# WebTransport CLOSE metadata lifetime

An event's CLOSE reason borrows its Control storage and remains valid until
that Control is deinitialized. A later flow-control rejection now retains
already committed metadata for both delivered and still-pending CLOSE events.

The lifecycle observer can apply a recognized stream-flow violation after a
valid CLOSE was decoded. Its generic Capsule rejection correctly resets the
affected CONNECT, but previously also cleared the reason storage. Inline
reasons were zeroed and heap reasons were freed even while the Session owner
and the borrowed event were still alive. The real UDP/QUIC regression fails
against the original implementation with `expected 24, found 0`.

Rejection now checks whether a complete CLOSE was committed before discarding
reason storage. A committed event keeps its original code, reason and heap
allocation; incomplete or uncommitted reasons are still released. Protocol
error selection, RESET_STREAM/STOP_SENDING and suppression of further
application operations are unchanged.

The regressions cover 24-byte inline and 512-byte heap reasons, delivered and
pending client events, shared-server events, the original flow-rejection code,
and healthy sibling progress. A separate negative test truncates a CLOSE,
rejects it, and proves its uncommitted heap storage is released. Test checks
verify the allocation remains present before reading a borrowed heap slice,
so a failure does not dereference freed memory.

```sh
zig build test-lib -Dtest-filter='CLOSE metadata' -Dtest-filter='uncommitted reason storage' -Dtest-filter='WebTransport reset after a decoded CLOSE' -Dtest-filter='WebTransport lightweight CONNECT reset aborts' --summary all
zig build test-lib -Dtest-filter='WebTransport' -Dtest-filter='Protected session control' --summary all
zig build interop-webtransport-wtransport -Doptimize=ReleaseFast --summary all
```

Verification passes 136 focused checks, 702 related WebTransport/protected
control checks and the independent wtransport client/server matrix.
[The verification record](evidence/webtransport_close_metadata/2026-10-28.json)
retains the original failure, source fingerprints and external role results.
These are lifetime and protocol checks, not performance measurements.
