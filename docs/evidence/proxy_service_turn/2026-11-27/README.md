# Finite shared proxy service turns

Base: `891d062f3148ac9049e0b73c1e331c9c7eed50e6`.

The shared TUIC and Hysteria QUIC owners previously drained stream events,
datagrams and worker inboxes until empty, and visited every connection in each
service call. A ready producer could keep a drain active before the pump
reached a sibling or the receive/timer path.

Both owners now use the same internal service budget. Each STREAM and
DATAGRAM stage admits at most 16 events and 64 KiB of payload, except that an admitted whole
datagram may cross the byte boundary by less than one maximum datagram.
Worker inboxes admit at most 16 commands. The pump visits at most 16
connections in each ordinary or completion turn. Each budget also checks
fresh awake-clock time after its first event and before admitting another,
using a two-millisecond quantum. This is cooperative admission: current
parsing, connection cleanup and target-owner retirement finish before a
yield. It is not a hard two-millisecond wall-time bound on those operations.

Unpolled STREAM/FIN/RESET state remains owned by QUIC and its existing
per-stream cursor. Datagram byte accounting includes malformed protocol
messages. Inbox commands leave the queue one at a time, so a later socket or
payload owner is never removed before its command can be applied. Input
budgets are independent, allowing DATAGRAM and cleanup service after a hot
STREAM stage. Ordinary and completion connection scans use independent
rotation cursors. Completion scans retain their remaining visit count after
the global notification is consumed; another notification extends the scan
without resetting its cursor. Swap removal preserves the next connection
identity. The existing cap of eight completion turns before receive/timer
service remains in place.

The new native cases run on Threaded and zio. They exercise the actual shared
owners with a protected 69,639-byte STREAM and FIN, 40 distinguishable invalid
datagrams, a deterministic 40-command inbox backlog, and 33 adopted connections
containing a hot datagram source, a closed middle slot and an expired
unauthenticated connection. Separate 33-connection completion scans verify
retained unvisited work, including a closed owner. With a configured 32-KiB
application buffer, eight 24,001-byte queued datagrams exercise the byte
boundary while retaining the full untouched packet suffix. The datagram and
inbox backlog is inserted directly into their real queues; the stream prefix is received from protected UDP
packets. Expanded inbox fixture storage models refilling without a timing race.
Protocol authentication is covered by the unchanged end-to-end tests.

The first focused qualification passed 63/63 runner tests, including eight
named service/rotation cases and import aggregators. Replaying the unchanged
production bodies with the new input/connection regressions failed all four
selected owner cases on Threaded: both STREAM drains delivered all 69,639 bytes in
one call and both connection scans reached the expired sibling in their first
call. The restored candidate passed 108 scoped runner tests, including the
unchanged TUIC, Hysteria shared, maximum-rate, relay ownership and UDP owner
cases. Windows test compilation and the ReleaseSafe TUIC server build passed.
The unchanged pinned eight-gate independent peer matrix passed, retaining the
full 128-KiB TCP assertion and all native/quic UDP payload, uniqueness and count
checks. See [validation](validation.json), [before](before.json), and
[peer](peer.json). The previous current-source CI completed with every platform
job successful, including the original native Linux CA reload step; the full
complete job exited 137 before any test name. Those CI facts qualify the
previous source and do not establish a runtime or resource cause.

Full mixed hot/idle/blocked process-level p50/p99, throughput, CPU and allocation measurements remain in
R4. This feature does not complete R4-R9 or the continuous HTTP-family goal.
