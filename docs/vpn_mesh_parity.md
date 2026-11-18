# VPN and mesh wire protocol coverage

`src/vpn/wireguard/` and `src/mesh/` own reusable protocol codecs and state
machines. Product policy remains in the sibling `vpnz` and `meshz` packages:
TUN/routing, DNS, kill-switch, configuration, credentials, control plane,
MagicDNS, ACL, NAT classification, and path selection are not part of netz.

## WireGuard

| Component | Path | Implemented surface |
| --- | --- | --- |
| Noise IKpsk2 handshake | `src/vpn/wireguard/noise.zig` | Initiator/responder handshake state, PSK mixing, and transcript hashing |
| Message codecs | `src/vpn/wireguard/message.zig` | Handshake initiation/response, cookie reply, and transport message framing |
| Cookies | `src/vpn/wireguard/cookie.zig` | Cookie reply generation and validation |
| Replay protection | `src/vpn/wireguard/replay.zig` | Bounded sliding-window replay checks |
| Sessions | `src/vpn/wireguard/session.zig` | Transport session keys, counters, and lifecycle helpers |
| Timers | `src/vpn/wireguard/timers.zig` | Handshake/keepalive/rekey timer state |
| Metrics | `src/vpn/wireguard/metrics.zig` | Connection and packet counters |

## Mesh and DERP

| Component | Path | Implemented surface |
| --- | --- | --- |
| Shared types | `src/mesh/types.zig` | Node identity, endpoint, and key types |
| Bounded helpers | `src/mesh/wire.zig` | Length-prefixed and bounded byte helpers |
| Disco | `src/mesh/disco/` | Discovery message codec and validation |
| DERP frames | `src/mesh/derp/frame.zig` | Frame codec and bounds |
| DERP relay | `src/mesh/derp/relay.zig` | Relay state machine |
| DERP client | `src/mesh/derp/client.zig` | Client state machine |
| DERP WebSocket | `src/mesh/derp/websocket.zig` | WebSocket transport adapter |

## Verification

Current coverage is unit testing inside `src/vpn/` and `src/mesh/` (63 tests at
the time of writing). `zig build fuzz-wireguard-mesh` replays bounded hostile
inputs through the WireGuard message parsers, disco messages, and DERP frames.
There is no external interoperability gate against `wireguard-go`, Tailscale
DERP, or another mesh peer.

Open verification work:

- add an independent WireGuard handshake/transport peer gate;
- add a DERP frame/relay peer gate and a long-running relay churn test;
- add fixed-binary benchmarks for handshake, transport encryption, and relay
  forwarding.

Until those gates exist, claims for these modules are limited to the in-repo
codec and state-machine tests.
