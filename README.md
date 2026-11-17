# netz

`netz` is a Zig 0.16 protocol toolkit for modern application networking. It
starts with deterministic parsers, serializers, preallocated fixed-width
wire-integer helpers, and state helpers across HTTP, WebSocket, WebTransport,
MQTT, gRPC, proxy, VPN, and mesh protocol families.

Ongoing HTTP development targets the widely used HTTP/1.1, HTTP/2, and HTTP/3
versions. HTTP/1.0 and HTTP/0.9 are not supported.

The architecture and performance rules are defined in
[docs/architecture.md](docs/architecture.md): performance beyond the reference
implementations is the first acceptance requirement, with correctness, protocol
conformance, and bounded memory as prerequisites. The profiling, benchmark, and
evidence workflow is in
[docs/performance-playbook.md](docs/performance-playbook.md), and the complete
documentation map is in [docs/README.md](docs/README.md).

## Application proxy protocols

`src/proxy/` owns the application-layer proxy wire codecs, servers, and relay
lifecycles: SOCKS5 (CONNECT, BIND, UDP ASSOCIATE, RFC 1929 auth), HTTP/1
CONNECT, Shadowsocks AEAD, Trojan, VLESS/VMess with TLS/WebSocket/QUIC/HTTP2/
gRPC transports, TUIC v5, Hysteria v3, TLS stream adapters, and bounded
TCP/UDP/TLS/QUIC relay helpers. The `runtime/` submodule contains the generic
server primitives those implementations need (ACL, destination connect policy,
connection limits, statistics, rate limiting, and reloadable policy snapshots).

These modules were merged from the former `proxyz` protocol layer. The
`proxyz` package now owns Clash-style routing, DNS configuration, subscription
parsing, and health selection on top, and re-exports `netz.proxy` for
compatibility.

## VPN and mesh wire protocols

`src/vpn/wireguard/` owns the WireGuard Noise IKpsk2 handshake, message codecs,
cookie replies, replay protection, transport sessions, timers, and metrics.
Device orchestration, TUN/routing integration, configuration, credentials, and
platform runtimes remain in `vpnz`.

`src/mesh/` owns shared mesh identity/endpoint types, bounded byte helpers, the
disco discovery message codec, and the DERP frame/relay/client state machines
with their WebSocket transport adapter. Control plane, MagicDNS, ACL, routing,
NAT classification, and path-selection policy remain in `meshz`.

## Optional logging

netz uses kron directly. Library code calls `kron.info(scope, ...)`,
`kron.warn(scope, ...)`, and the other top-level functions; the execution layer
creates one `kron.Logging` and installs it with `kron.setGlobalLogging` before
starting workers. kron performs level filtering, sampling, and bounded
asynchronous queueing itself. netz does not use `std.log` and does not ship its
own logger facade. See [docs/logging.md](docs/logging.md) for setup and overhead
rules.

## Protocol coverage and verification

The detailed, feature-level coverage inventory lives in
[docs/coverage.md](docs/coverage.md): bounded parser and stateful fuzz targets,
live-network HTTP/1, HTTP/2, HTTP/3, WebSocket, WebTransport, QUIC, MQTT, gRPC,
proxy, VPN, and mesh behavior. Build and test gates are summarized under
[Build](#build), and the per-protocol parity authorities are indexed in
[docs/README.md](docs/README.md).

## Build

```sh
zig build test                 # complete repository gate
zig build test-lib             # in-process library suite
zig build test-compile -Dtarget=x86_64-windows-gnu
zig build run-http-duplex      # runnable duplex streaming example
```

Portable targets, fuzz corpora, interop gates, release archives, and the
evidence workflow are documented in [docs/build.md](docs/build.md).

## Implementation order

Protocol work is prioritized as: HTTP/1 + HTTP/2, WebSocket, QUIC, HTTP/3,
and MQTT. WebRTC development continues in the sibling `horizon` package.

## Package use

```zig
const netz = @import("netz");

const accept = netz.websocket.acceptKey("dGhlIHNhbXBsZSBub25jZQ==");
_ = accept;
```

HTTP/1 can also run over a real TCP stream:

```zig
var backend = try netz.runtime.Backend.init(allocator);
defer backend.deinit();
const io = backend.io();

var response = try netz.http1.runtime.Client.requestUri(
    allocator,
    io,
    "http://localhost:8080/",
    .{},
    .{ .write_strategy = .auto },
);
defer response.deinit(allocator);
```

WebSocket can upgrade over the same TCP layer:

```zig
var ws = try netz.websocket.runtime.Client.connectUri(
    allocator,
    io,
    "ws://localhost:8080/chat",
    .{},
);
defer ws.close();

try ws.sendText("hello");
var frame = try ws.receiveFrame();
defer frame.deinit(allocator);
```

WS and WSS can use the same end-to-end Upgrade through a cleartext HTTP
CONNECT proxy. Proxy headers are sent only on CONNECT; application headers stay
on the origin Upgrade request:

```zig
var ws = try netz.websocket.runtime.Client.connectUriViaProxyWithTimeout(
    allocator,
    io,
    "http://proxy.example:8080",
    "wss://origin.example/chat",
    .{ .extra_headers = &.{.{
        .name = "Authorization",
        .value = "Bearer origin-token",
    }} },
    .{ .headers = &.{.{
        .name = "Proxy-Authorization",
        .value = "Basic cHJveHktdXNlcjpwYXNz",
    }} },
    .{},
    .fromSeconds(10),
);
defer ws.close();
```

`Client.connectUriFollowingRedirects*` follows bounded 300/301/302/303/307/308
responses. Relative `Location` values are resolved against the prior URI, one
deadline spans the complete chain, and `RedirectOptions.proxy` reopens CONNECT
for each hop. Cross-origin hops strip `extra_headers` and refuse to forward a
client certificate by default; WSS-to-WS downgrade also requires explicit
policy opt-in.

Servers can inspect and reject the HTTP Upgrade before sending 101:

```zig
var pending = try server.receiveUpgradeRequest(.{});
var pending_open = true;
defer if (pending_open) pending.deinit();

if (!std.mem.eql(u8, pending.target(), "/chat") or
    !std.mem.eql(
        u8,
        pending.header("Authorization") orelse "",
        "Bearer example-token",
    ))
{
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

The pending value owns the transport until an outcome succeeds. TCP, Unix, and
WSS listeners share this API; WSS additionally exposes verified peer
certificates and negotiated cipher/hash metadata during admission.

The HTTP and WebSocket URI helpers synthesize Host / `:authority` / `:scheme`
from the URI and can connect to host names, IPv4 literals, and bracketed IPv6
literals such as `http://[::1]:8080/` and `ws://[::1]:8080/chat`.

On Zig 0.16, `std.Io.Uring` exists but its `std.Io.net` networking hooks are
still unavailable. All protocol runtimes nevertheless stay on the `std.Io`
abstraction: `netz.runtime.Backend.init()` uses zio's complete `std.Io`
implementation (io_uring with automatic epoll fallback on Linux, plus portable
backends elsewhere) and reports initialization failure rather than silently
changing execution models. The dependency is pinned to the project-maintained
`passchaos/zio` Zig-0.16 branch at v0.19.1 commit
`3c2365b88c9b6fef5ba709c36c6b2f8ceb77a789`. It includes the multi-message UDP
receive support required by shared-endpoint batching and treats unsupported
`MADV_NOHUGEPAGE` as the optional kernel hint it is, without Debug-build stack
traces. It also exposes coroutine-stack capacity and committed high-water
metrics without adding work to ordinary context switches. Timed runtime I/O
preserves already-ready operations as a timer-free inline path; blocking
operations link directly to their deadline timer so natural completion can
remove it without completing a generic race-group sibling; timer state itself
is constructed only after the operation proves it must park. Neither zio nor
OS-specific rings leak into the HTTP, WebSocket, QUIC, or other protocol APIs.
All runnable non-benchmark examples construct this backend and schedule local
concurrent work through `std.Io.async`; benchmark and low-level white-box code
may still construct specialized I/O fixtures to measure or fault-inject a
specific path.

Every WebTransport session facade exposes its DATAGRAM payload budget so
callers can avoid sending a payload the underlying QUIC endpoint or peer will
reject. Handshake-backed/stateful sessions use the negotiated QUIC limit; the
development and lightweight protected facades account for their endpoint limit
and exact framing overhead:

```zig
var session = try netz.webtransport.runtime.HandshakeClientSession.connect(
    allocator,
    io,
    .{ .ip4 = .loopback(0) },
    server_addr,
    .{
        .authority = "localhost",
        .path = "/wt",
        .h3 = handshake_options,
    },
);
defer session.deinit();

if (session.maxDatagramPayloadSize()) |limit| {
    if ("hello".len <= limit) try session.sendDatagram("hello");
}
```

Handshake-backed, stateful preconfigured-key, and lightweight protected
WebTransport sessions also expose ordered `sendDatagrams*` batches.
`committed_count` identifies only the socket-visible input prefix; packet
numbers for a protected but unsent suffix are consumed so retries cannot reuse
AEAD nonces. A lightweight single-DATAGRAM send follows the same boundary: once
AEAD protection succeeds its packet number is retired even if the socket makes
zero progress. Batch progress also retains that protected count for endpoint
interceptor failures that occur before socket progress. Lightweight batches
contain at most 64 datagrams in one socket
submission and reuse their encoding/protection scratch after warmup. Both
single and batch lightweight sends reject oversized payloads before allocation
or socket I/O; protected rejection does not consume a packet number.

## Design notes

- Parsers keep slices pointing into caller-owned buffers unless a protocol needs
  mutation/unmasking (for example WebSocket frame payloads).
- Public structs expose decoded wire values and avoid hidden allocation; objects
  that allocate provide explicit `deinit` methods.
- The HTTP/2 HPACK helper maintains per-connection dynamic table state and RFC
  7541 Huffman strings with collision-verified exact/name hash indexes for
  current dynamic entries; the stateless literal convenience helpers accept
  legal leading table-size updates while keeping dynamic state scoped to one block.
  HTTP/3 QPACK now provides RFC 9204 dynamic-table state with single-pass
  exact/name matching, dynamic field
  sections, both instruction stream codecs, and lightweight Protected plus
  stateful client/server decode-side live encoder-stream processing with decoder
  feedback. These HTTP/3 runtimes persist their encoder/decoder streams and
  automatically use peer-capacity-bounded, reference-safe dynamic compression
  for repeated request and response fields after either preconfigured 1-RTT or
  a full QUIC handshake. Large field sections deduplicate dynamic references
  with a temporary table-relative bitmap while preserving first-use order;
  ordinary sections retain their allocation-free stack and linear fast path. The
  lightweight preconfigured 1-RTT runtime also
  reuses protected packet scratch. Stateful preconfigured-key and
  handshake-backed runtimes batch
  multi-packet STREAM sends through UDP GSO or sendmmsg while preserving
  flow/recovery state and consuming every protected packet number on partial
  socket writes.
  Both runtimes bound speculative outbound references by the peer-advertised
  potentially-blocked stream count; Section Acknowledgment, Insert Count
  Increment, and Stream Cancellation release that budget while referenced
  entries remain protected from eviction. On receive they can advertise
  non-zero `SETTINGS_QPACK_BLOCKED_STREAMS` up to the bounded concurrent-stream
  limit, retain multiple complete dependent request/response messages, continue
  processing split/reordered encoder instructions, and resume each once its
  Required Insert Count is available.
- WebRTC support is maintained by the sibling `horizon` package; it owns STUN,
  ICE, SDP, DTLS, RTP/RTCP, SRTP/SRTCP, SCTP/DCEP, and the UDP peer runtime.
the UDP peer runtime.
