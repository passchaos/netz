# Complete HTTP/2 write-observer delegation

Sixteen HTTP/2 writer observers replace backend userdata while retaining its
callbacks. The affected fixtures cover partial HEADERS/DATA, request and
response batches, PUSH_PROMISE admission, connection credit, graceful shutdown
and refusal after reset. Two further observers retain backend userdata but
locate their writer through a mutable global pointer. These are source
contract findings; this batch does not claim eighteen independent native
crash reproductions.

All eighteen installations now use the shared typed observer constructor.
Their `delegate: std.Io` owns every callback not explicitly overridden. The
two global pointers are removed. The buffered sibling-drain fixture retains
its zero clock and write-failure sequence; it performs no timed wait through
that clock. Partial-write counts, staged/live HPACK behavior, stream capacity,
WINDOW_UPDATE bytes and fail-closed follow-up errors remain unchanged.

Each supported fixture runs through Threaded with zero async capacity and the
application backend with one executor. Stream coverage includes native
Windows. The internal-error GOAWAY fixture retains its existing Linux gate;
its macOS/Windows result is not native execution of that case. The actual TCP
batch-reset fixture restores original I/O before closing the connection. A
failed accept closes the untransferred sender, while later assertion failure
leaves sender cleanup exclusively with the connection.

[validation.json](validation.json) records source hashes, the original case
and assertion comparison, formatting, scoped native execution and Windows
cross-compilation. All eighteen original names and 103 selected assertion
statements remain; all 278 assertions across the seven changed files are
unchanged. The native scope passes 53 tests and Windows compilation completes
8/8 steps. A separate compilation of only the Linux GOAWAY case completes
8/8 steps. The scope also includes the shared native observer tests.
Artifact test counts include imported cases and do not represent eighteen
separate protocol exchanges.

The preceding `7a2e6bcc` CI run
[45890482581](https://github.com/passchaos/netz/actions/runs/45890482581)
completed its current attempt. Linux protocol, send-deadline and client CA
reload steps pass. Windows protocol and send-deadline steps pass in 3m26s and
2m04s respectively. Complete CI advances beyond the previous WebTransport
allocator crash to the last emitted `6355/7490` gRPC TLS health Watch result,
then reaches the unchanged 28-minute budget with exit 137. The public terminal
annotations contain no further allocator crash. A single CA reload success
does not causally resolve the earlier intermittent pre-SIGHUP failure.

That CI result precedes this HTTP/2 observer change. Delivered native Linux
qualification of the Linux-only case and complete acceptance remain open.
Remaining observer contexts, endpoint fairness, allocation profiles and
public-interface usability remain part of the active HTTP-family goal.
