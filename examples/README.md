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
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast
zig build bench-websocket-frame -Doptimize=ReleaseFast
zig build run-webtransport-handshake-stream -Doptimize=ReleaseFast
# Linux only: raw std.os.linux.IoUring connect/send/recv around HTTP/1 bytes
zig build run-linux-io-uring-http1
```

The URI helpers derive Host / `:authority` / `:scheme` from the URI. Host names,
IPv4 literals, and bracketed IPv6 literals such as `http://[::1]:8080/` are
supported by the HTTP/1, HTTP/2 h2c, and WebSocket client examples.

`bench-http1-pipeline` mirrors Hyper's `hello_world_16`: one persistent
loopback TCP connection carries batches of sixteen bodyless requests and
thirteen-byte bodies. It includes Hyper's same-length Date field so each
response is 89 wire bytes, and performs untimed warmup batches before
measurement. Pin both reference executables to the same CPU when collecting
comparison evidence; see `docs/hyper_parity.md` for exact commands and captured
same-host results.

`bench-http2-h2c` mirrors Hyper's `http2_consecutive_x1_empty` and
`http2_consecutive_x1_req_10b` on one persistent prior-knowledge connection.
It includes a same-length Date field so steady-state request/response wire
sizes match the reference, and performs untimed warmup before each scenario.

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
- `run-quic-datagram-echo` exercises RFC 9221 DATAGRAM send, receive queueing,
  and echo.
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

Zig 0.16 includes two related APIs:

- `std.Io.Uring` / `std.Io.Evented`, a `std.Io` backend. In this release its
  networking vtable still marks `listen`, `accept`, `connect`, `read`, and
  `write` as unavailable, so the high-level `std.Io.net` runtimes use
  `std.Io.Threaded` for real TCP today.
- `std.os.linux.IoUring`, the low-level Linux ring wrapper. The HTTP/1 runtime
  exposes a Linux-only `Client.requestUriLinuxIoUring` helper that uses it for
  `connect`, `send`, `recv`, and `close`; HTTP/1 also exposes
  `LinuxIoUringServer` for accept/read/write response flows. WebSocket exposes
  the analogous `Client.connectUriLinuxIoUring` for cleartext `ws://`
  IP-literal clients. The Linux examples demonstrate those reusable paths.

Because netz runtimes take a `std.Io` value, protocol code stays backend-neutral.
`netz.runtime.Backend` centralizes Evented-vs-Threaded selection so applications
can opt into Evented mode without scattering platform checks through protocol
implementations.
