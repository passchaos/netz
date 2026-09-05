# netz examples

These examples mirror the shape of the `~/Work/hyper` and
`~/Work/tungstenite-rs` examples: start a small local server, connect a client,
print the exchange, then exit. They are self-contained and do not require
external network access.

Run all example compile checks:

```sh
zig build examples
```

Run individual examples:

```sh
zig build run-http1-hello
zig build run-http2-h2c
zig build run-http3-handshake
zig build run-http3-fetch
zig build run-quic-echo
zig build run-quic-handshake-echo
zig build run-quic-datagram-echo
zig build run-quic-close
zig build run-websocket-echo
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast
taskset -c 0 zig build bench-http1-body -Doptimize=ReleaseFast -- \
  --mode=fixed --warmup=20 --iterations=200
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- \
  --mode=visitor --frame=stream --warmup=200 --iterations=5000
zig build bench-websocket-frame -Doptimize=ReleaseFast
zig build bench-websocket-receive-buffer -Doptimize=ReleaseFast
zig build run-webtransport-handshake-stream -Doptimize=ReleaseFast
```

The MQTT broker API exposes `Broker.saveSnapshot` and
`Broker.restoreSnapshot`. Snapshots use restricted temporary files, fsync,
atomic replacement, versioned sections and CRC validation. Save is a quiescent
shutdown/admin operation; restore is intended for startup before accepting
clients. See `docs/rumqtt_parity.md` for the persisted state surface and
current persisted surface, including inbound QoS 2 transactions awaiting
PUBREL, and remaining incremental-autosave exclusions.

The finite `run-mqtt-broker` example enables this with
`--persistence=netz-mqtt.db`; it restores on startup and snapshots after the
configured connection batch exits. Pass `--no-restore` to replace an existing
database with a fresh run.

`--autosave-change-count=N` additionally writes a live snapshot after `N`
broker operations that change snapshot-backed state, including durable Session,
subscription, queued-delivery, acknowledgement, inbound QoS 2, retained-message,
and Will lifecycle transitions. One operation counts once even when it changes
several stores or fans out to several durable Sessions. Periodic `$SYS` refreshes
are excluded so telemetry cannot force checkpoint churn. The option requires
`--persistence`, and `N` must be greater than zero. It may be combined with
`--autosave-interval-seconds=N`; both triggers target the same atomic snapshot
file, and whichever trigger becomes due writes the next checkpoint. Snapshot
autosave modes are intentionally incompatible with `--commit-log`, whose
fsynced records provide a separate durability policy. Change-triggered writes
are best effort after the corresponding broker mutation has committed; failures
remain pending for a later retry and are available through
`Broker.persistentChangeAutosaveError`.

Trusted reverse proxies can prepend HAProxy PROXY protocol metadata with
`--proxy-protocol=1` or `--proxy-protocol=2`. For v2,
`--proxy-v2-require-tls` and `--proxy-v2-require-client-certificate` reject
connections whose SSL TLV lacks the corresponding authenticated edge state.
`--proxy-header-timeout-ms=N` places one absolute deadline over the complete
preface.
Never expose such a listener directly to untrusted clients because PROXY
metadata is an assertion made by the connecting peer.

`--system-interval-seconds=N` periodically publishes the coherent broker
statistics snapshot as retained QoS 0 `$SYS` topics. Applications embedding
the library can call `Broker.stats()` or `Broker.publishSystemStats()` directly.

The URI helpers derive Host / `:authority` / `:scheme` from the URI. Host names,
IPv4 literals, and bracketed IPv6 literals such as `http://[::1]:8080/` are
supported by the HTTP/1, HTTP/2 h2c, and WebSocket client examples.

HTTP/1 WebSocket servers can stop after parsing the Upgrade request and make an
application decision before any 101 bytes are sent. The same API is available
on TCP, Unix-domain, and native TLS listeners:

```zig
var pending = try server.receiveUpgradeRequest(.{});
var pending_open = true;
defer if (pending_open) pending.deinit();

if (!std.mem.eql(u8, pending.target(), "/chat")) {
    try pending.notFound();
    pending_open = false;
    return;
}
if (!std.mem.eql(
    u8,
    pending.header("Authorization") orelse "",
    "Bearer example-token",
)) {
    try pending.reject(401, "Unauthorized", &.{
        .{ .name = "WWW-Authenticate", .value = "Bearer" },
    }, "authentication required\n");
    pending_open = false;
    return;
}

var ws = try pending.acceptWithHeaders(&.{
    .{ .name = "X-Admission", .value = "accepted" },
});
pending_open = false;
defer ws.close();
```

`PendingUpgrade` owns the accepted transport until acceptance, rejection, or
`deinit`. Header-validation and write errors do not consume that ownership. The
configured opening-handshake deadline remains the same absolute deadline while
the application checks routing or credentials. WSS pending requests also expose
the verified peer certificate chain and negotiated TLS cipher/hash metadata.

`bench-http1-pipeline` mirrors Hyper's `hello_world_16`: one persistent
loopback TCP connection carries batches of sixteen bodyless requests and
thirteen-byte bodies. The ordinary server path automatically generates the
same 29-byte IMF-fixdate as Hyper, so each response is 89 wire bytes without a
benchmark-only header. It performs untimed warmup batches before
measurement. Pin both reference executables to the same CPU when collecting
comparison evidence; see `docs/hyper_parity.md` for exact commands and captured
same-host results.

`bench-http1-body` sends and receives 1 MiB on one persistent HTTP/1
connection. `--mode=fixed` uses one Content-Length contribution in each
direction; `--mode=chunked` preserves 64 application chunks of 16 KiB.
Both peers consume bodies incrementally. The same-shape Hyper harness lives in
`tools/hyper_http1_body` and is run through:

```sh
taskset -c 0 tools/bench_hyper_http1_body.sh \
  --mode=fixed --warmup=20 --iterations=200
```

The wrapper uses the checked-in Cargo lockfile and offline mode, and expects the
reference checkout at `~/Work/hyper`.

`bench-http2-h2c` mirrors Hyper's `http2_consecutive_x1_empty`,
`http2_consecutive_x1_req_10b`, `http2_consecutive_x1_req_100kb`, and
`http2_parallel_x10_empty` on persistent prior-knowledge connections. It also
includes Hyper's `http2_parallel_x10_req_10kb_100_chunks_max_window`: ten
concurrent streams each carry 100 round-robin 10-KiB contributions under max
connection/stream windows. The
`http2_parallel_x10_res_1mb` scenario sends ten bodyless requests and streams a
1-MiB response on every stream without client-side body aggregation. The
benchmark uses the runtime's default automatic Date and Hyper-style receive
windows so steady-state wire sizes and flow-control shape match the reference. The 100-KiB
server path consumes DATA through `readRequestStreaming` without aggregation.

`bench-http2-flow` exercises the same ten 1-MiB responses with an 8-KiB stream
window and the RFC default 65,535-byte connection window. The server's batch
scheduler advances streams round-robin, waits for WINDOW_UPDATE only when every
unfinished stream is blocked, and the client continuously returns credit while
streaming DATA. Its same-shape Hyper harness is run with:

```sh
taskset -c 0 tools/bench_hyper_http2_flow.sh \
  --warmup=5 --iterations=20
```

Pass `--priority` to opt into RFC 9218 for an internal mixed-urgency workload.
The default remains round-robin so the Hyper comparison retains identical
scheduling semantics:

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --priority --warmup=2 --iterations=5
```

Pass `--adaptive` to enable Hyper-style receive-window growth on both peers.
Like Hyper, this overrides the fixed window arguments with the RFC default
65,535-byte starting point, samples DATA with dedicated PING round trips, and
caps the learned target at 16 MiB by default:

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --adaptive --parallel=10 --body-bytes=1048576 \
  --stream-window=8192 --connection-window=65535 \
  --warmup=2 --iterations=5
```

`run-http3-handshake` is the protected-loopback counterpart to the public
HTTP/3 fetcher: it starts a local QUIC/H3 server, performs a full client
handshake, exchanges one POST/200 response, and exits without relying on
external network access.

The QUIC examples are preconfigured-key transport smoke tests that bypass TLS
so individual 1-RTT features are easy to inspect:

- `run-quic-echo` sends STREAM data from a local client to server and echoes it
  back on the same bidirectional stream.
- `run-quic-handshake-echo` performs the same STREAM exchange after a real
  local QUIC/TLS handshake, covering raw handshake-backed transport without
  HTTP/3 framing.
- `bench-quic-handshake-stream` performs fresh real handshakes and measures raw
  one- or multi-stream upload throughput. Its defaults match the 5 × 64 MiB
  shape of `~/Work/quicz/examples/quic_bench_hs.zig`; `--streams=4`,
  `--iterations`, `--transfer-bytes`, and `--batch-packets` tune the comparison.
  `--mode=lifecycle-churn` repeatedly closes FIN/echo and RESET_STREAM batches
  under a small renewable stream limit. Add either `--loss-pct=N` (and optional
  `--rtt-us=N`) or `--reorder-every=N` to fault both directions after the real
  handshake; the benchmark verifies exact terminal counts, stream IDs,
  checksum, deterministic injection counts, and both endpoint statistics.
- `run-quic-datagram-echo` exercises RFC 9221 DATAGRAM send, receive queueing,
  and echo.
- `bench-webtransport-datagram` keeps its lightweight ping-pong baseline by
  default; `--burst --iterations=N --send-timeout-ms=N` switches to a real
  QUIC/TLS + HTTP/3 WebTransport session and measures deadline-bounded
  DATAGRAM sends under congestion backpressure.
- `run-quic-close` sends an application close frame and verifies that the peer
  enters draining with the expected error code and reason phrase.

`run-http3-fetch` is the public-network example. By default it fetches
`https://robotics.bytedance.com/`; `--verify` enables system trust-store
certificate validation, `--discover` performs best-effort Alt-Svc discovery
using an HTTP/3 HEAD probe before issuing the final request, and
`--alt-svc='h3=":443"; ma=2592000'` lets interop tests provide a known
HTTP/3 alternative service explicitly.

`run-webtransport-handshake-stream` performs a real QUIC/TLS + HTTP/3
WebTransport CONNECT, then exercises a client-opened bidirectional echo,
client-to-server unidirectional data, and a server-to-client unidirectional
stream. It uses the modern `0x41 + Session ID` bidirectional association prefix
implemented by wtransport.

## I/O backend note

Zig 0.16 and netz provide these related layers:

- `std.Io.Uring` / `std.Io.Evented`, a standard backend whose networking
  vtable still marks `listen`, `accept`, `connect`, `read`, and `write` as
  unavailable in Zig 0.16.
- zio, which supplies a complete `std.Io` implementation and uses io_uring
  with automatic epoll fallback on Linux (plus portable backends elsewhere).
- No protocol API exposes the lower-level `std.os.linux.IoUring`; doing so
  would bypass `std.Io` cancellation, deadline, and ownership semantics.

Because netz runtimes take a `std.Io` value, protocol code stays backend-neutral.
`netz.runtime.Backend.initAuto(.zio_then_threaded)` centralizes zio-vs-Threaded
selection without scattering backend or platform checks through protocol
implementations. The older `.evented_then_threaded` spelling remains a source-
compatible alias.
