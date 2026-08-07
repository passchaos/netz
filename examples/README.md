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
zig build run-websocket-echo
# Linux only: raw std.os.linux.IoUring connect/send/recv around HTTP/1 bytes
zig build run-linux-io-uring-http1
```

The URI helpers derive Host / `:authority` / `:scheme` from the URI. Host names,
IPv4 literals, and bracketed IPv6 literals such as `http://[::1]:8080/` are
supported by the HTTP/1, HTTP/2 h2c, and WebSocket client examples.

## I/O backend note

Zig 0.16 includes two related APIs:

- `std.Io.Uring` / `std.Io.Evented`, a `std.Io` backend. In this release its
  networking vtable still marks `listen`, `accept`, `connect`, `read`, and
  `write` as unavailable, so the high-level `std.Io.net` runtimes use
  `std.Io.Threaded` for real TCP today.
- `std.os.linux.IoUring`, the low-level Linux ring wrapper. The HTTP/1 runtime
  exposes a Linux-only `Client.requestUriLinuxIoUring` helper that uses it for
  `connect`, `send`, `recv`, and `close`; WebSocket exposes the analogous
  `Client.connectUriLinuxIoUring` for cleartext `ws://` IP-literal clients.
  `linux_io_uring_http1.zig` and `linux_io_uring_websocket.zig` demonstrate
  those reusable paths.

Because netz runtimes take a `std.Io` value, they can switch to the standard
Uring backend as soon as Zig wires networking into it. The raw Linux example is
kept separate so portable examples still run on non-Linux targets.
