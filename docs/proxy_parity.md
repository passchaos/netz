# Proxy protocol coverage

`src/proxy/` owns the application-layer proxy wire codecs, servers, and relay
lifecycles. Product policy (Clash-style routing, DNS configuration,
subscriptions, and health selection) lives in `proxyz` and composes these
modules; it is not duplicated here.

## Protocol matrix

| Protocol | Path | Implemented surface |
| --- | --- | --- |
| SOCKS5 | `src/proxy/socks5.zig`, `src/proxy/socks/` | RFC 1928 CONNECT, BIND, UDP ASSOCIATE; RFC 1929 username/password authentication; proxy-side hostname resolution (`socks5h` shape); one absolute deadline across DNS, TCP, authentication, and the request |
| HTTP/1 CONNECT | `src/proxy/http_connect/` | Strict request-line/header parsing, CONNECT admission, authority validation, and server-side tunnel handoff |
| Shadowsocks | `src/proxy/shadowsocks/` | AEAD ciphers, TCP and UDP stream codecs, bounded replay protection, and server relay |
| Trojan | `src/proxy/trojan/` | TLS + password request codec and server relay |
| VLESS | `src/proxy/vless/` | Request codec and TLS, WebSocket, HTTP/2, QUIC, and gRPC server transports |
| VMess | `src/proxy/vmess/` | AEAD wire codec, request/body codecs, and TLS, WebSocket, HTTP/2, QUIC, and gRPC server transports |
| TUIC v5 | `src/proxy/tuic/` | QUIC CONNECT codec, ACL integration, and server relay |
| Hysteria v3 | `src/proxy/hysteria/` | CONNECT-over-QUIC codec, ACL integration, and server relay |

## Shared runtime primitives

`src/proxy/runtime/` provides ACL matching, destination connect policy,
connection limits, rate limiting, reloadable policy snapshots, and statistics.
`src/proxy/internal/` provides bounded TCP/UDP/TLS/QUIC relay helpers, address
resolution, byte buckets, and timed I/O. `src/proxy/transport/` adapts proxy
streams over WebSocket, HTTP/2, gRPC, and QUIC.

These helpers preserve the repository rules: caller-owned buffers, bounded
queues and retry loops, absolute deadlines, and one owner per transport.

## Verification

Current coverage is unit and integration testing inside `src/proxy/` (97 tests
at the time of writing). `zig build fuzz-proxy` replays bounded hostile inputs
through the SOCKS5, HTTP CONNECT, Trojan, VLESS, VMess, TUIC, and Hysteria
codecs. Existing external gates cover SOCKS5 and HTTP CONNECT compositions used
by HTTP, WebSocket, MQTT, gRPC, HTTP/3, and WebTransport.

`zig build interop-shadowsocks-sing-box` adds an independent Shadowsocks AEAD
gate. A sing-box 1.14.x SOCKS5 inbound forwards through its Shadowsocks
outbound to the netz server, which relays to a loopback HTTP target; the gate
requires the exact body for `aes-256-gcm`, `aes-128-gcm`, and
`chacha20-ietf-poly1305`. The gate also exposed and fixed a zio compatibility
bug in the proxy deadline read path: `io.operateTimeout` race groups panic under
zio, so deadline reads now use `std.Io.Select` with a timeout arm.

Open verification work:

- no independent peer gate for Trojan, VLESS, VMess, TUIC, or Hysteria;
- no fixed-binary performance baseline against a reference proxy
  implementation.

Until those gates exist, claims for those protocols are limited to the in-repo
codec and relay tests.
