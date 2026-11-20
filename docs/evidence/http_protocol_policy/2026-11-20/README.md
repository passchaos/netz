# Ordered protocol policy

Base revision: `1a6d5fb9`. Work began on 2026-11-20 and final validation ran on
2026-11-21, Zig 0.16.0, macOS aarch64. Final changed source hashes are recorded
in `sources.json`.

`prefer_http3` now tries the URI's authenticated H3 connection first, then
offers H2/H1 through the existing TCP TLS ALPN path. `prefer_http2` keeps its
H2/H1 order and default status. A preference probe defaults to 250 ms and uses
at most half the remaining caller connection deadline. Both phases preserve
the original deadline. Connection/protocol unavailability permits advancing;
certificate/configuration/allocation/cancellation failures remain errors.

Protocol selection takes place before request output. UDP blackhole tests send
single-pass POST Readers over the eventual H2/H1 connection without rewind or
replay. Once an application request starts, its failures use the existing
request retry/replay policy rather than restarting protocol selection.

The primary Pool now accepts both H3 policies. The H2 frame owner returns an
H1/H3 lease to the exclusive request path, and ordinary requests, manual streams
and raw leases share their existing admission, idle and combined budgets.
Optional Alt-Svc H3 dispatchers retain their separate multiplexed route.
The stream handle's exclusive branch is named `leased` because it can now
own TCP or QUIC. Cross-origin isolation clears explicit QUIC resumption inputs,
and native H3 client identities participate in redirect restriction checks.

| Gate | Result | Artifact |
| --- | --- | --- |
| Initial sequential selection, UDP fallback, tight deadline, H3 Pool reuse and certificate refusal | 104/104 | `debug.log` |
| Expanded policy/ALPN/direct H3/lease/Reader/cancellation overlap | 113/113 | `verified-debug.log` |
| No-I/O feasibility constraints and explicit TCP/QUIC origin isolation | 90/90 | `constraints-debug.log` |
| ReleaseFast policy and affected Alt-Svc overlap before hostname refinement | 117/117 | `releasefast.log` |
| Hostname dual-stack probe before address-delay cap | 94/95; one H3 selection failure | `hostname-debug.log` |
| Hostname probe after address-delay cap | 95/95 | `hostname-verified-debug.log` |
| Final ReleaseFast policy and affected Alt-Svc overlap | 117/117 | `verified-releasefast.log` |

The selected cases include:

- H3 success on IPv4/IPv6 with both Threaded and zio;
- UDP endpoints sending no handshake response, followed by H2-only or H1-only
  TCP TLS servers on the same port, including one-connection Pool reuse;
- a 700-ms caller deadline with a 5-second configured preference budget;
- direct H3 ordinary Pool requests, manual streams and reused raw leases under
  `prefer_http3` and `http3_only`, with a combined connection limit of one;
- wrong certificate pin returned as `CertificateUntrusted`;
- cancellation of the first resolver call with no second TCP lookup, joined
  borrowed resolver state and an untouched POST Reader;
- an I/O implementation that fails any attempted I/O, proving cleartext,
  TCP proxy and TLS-1.2-only preference constraints skip the H3 probe.

The hostname regression resolves `localhost` for an IPv4 H3 listener. A 250-ms
H3 probe originally ended before the default 250-ms address-racing delay let
IPv4 participate after the unreachable IPv6 candidate. The preference path now
caps the racing delay to one quarter of its remaining probe budget. Strict H3
connections retain their configured address policy without this probe cap.

```sh
zig build test-http \
  '-Dtest-filter=unified HTTP protocol policy' \
  '-Dtest-filter=unified HTTP ALPN policy' \
  '-Dtest-filter=unified HTTP direct H3' \
  '-Dtest-filter=streaming deadlines return H1 H2' \
  '-Dtest-filter=streaming deadlines discard completed' \
  '-Dtest-filter=blocked Reader' \
  '-Dtest-filter=isolates explicit TLS' --summary all

zig build test-http \
  '-Dtest-filter=protocol policy skips ineligible' \
  '-Dtest-filter=isolates explicit TLS' --summary all

zig build test-http -Doptimize=ReleaseFast \
  '-Dtest-filter=unified HTTP protocol policy' \
  '-Dtest-filter=unified HTTP ALPN policy' \
  '-Dtest-filter=unified HTTP direct H3' \
  '-Dtest-filter=streaming deadlines return H1 H2' \
  '-Dtest-filter=streaming deadlines discard completed' \
  '-Dtest-filter=blocked Reader' \
  '-Dtest-filter=isolates explicit TLS' \
  '-Dtest-filter=pooled H3 fields and interim callbacks' \
  '-Dtest-filter=learns Alt-Svc' --summary all
```

Counts include imported support tests and overlap between bundles. The evidence
is scoped loopback and source-boundary verification, with no new external-peer
certification or performance claim. Public contracts are documented in
[protocol policy](../../../http_protocol_policy.md).
