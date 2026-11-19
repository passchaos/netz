# MQTT transports and runtime fast path

[Back to the rumqtt parity index](../rumqtt_parity.md).

## MQTT-over-WebSocket transport

Run the persistent QoS 1 transport smoke benchmark with:

```sh
zig build bench-mqtt-websocket -Doptimize=ReleaseFast
```

It opens one MQTT 5 session, then measures 2,000 sequential 1 KiB
PUBLISH/PUBACK exchanges after 100 warmups. The benchmark is a reproducible
netz baseline, not yet a rumqtt speed ratio; an equal-wire rumqtt driver still
belongs to the common broker-load work below.
The maintained client and local server both obtain `std.Io` from zio, the
server runs through `std.Io.async`, and the result identifies both endpoints as
`zio-std-io`. The numeric result below predates that migration and remains a
historical Threaded baseline.

2026-08-17 same-host historical `ReleaseFast` smoke result:

```text
ns/publish+PUBACK: 13,231
operations/s:      75,579
```

The adapter requires `Sec-WebSocket-Protocol: mqtt` on both client and server.
It reuses the TCP runtime's MQTT negotiation, QoS 0/1/2, inflight, topic-alias,
and capability state rather than maintaining a second protocol state machine.
WS and WSS URI clients can also establish authority-form CONNECT tunnels
through a cleartext HTTP proxy. Proxy-only fields such as
`Proxy-Authorization` are written only on CONNECT, while `extra_headers`
remain end-to-end Upgrade fields. One caller deadline spans proxy DNS/TCP,
CONNECT, origin TLS, Upgrade, MQTT CONNECT and final CONNACK. The proxy-aware
reconnect connector opens a new tunnel per attempt and forwards cached TLS
1.2/1.3 tickets; MQTT 5 Server Reference redirects retain the proxy while
recomputing the CONNECT authority and origin TLS identity for every hop, and
their deadline variants retain one absolute budget across the complete chain.
Separate HTTP-redirect entry points follow the WebSocket 300/301/302/303/307/
308 policy before emitting MQTT CONNECT. The combined MQTT 5 entry points run
that HTTP chain independently for every Server Reference hop and retain one
absolute deadline across both layers. The owning WebSocket result returns its
actual final URI, so MQTT loop/default-transport/authorization decisions use
the broker that completed Upgrade rather than the initially requested load
balancer. A reconnect-aware connector rebuilds the HTTP chain per attempt and
passes TLS 1.2/1.3 tickets into the first WSS origin; cross-origin redirect
policy clears those tickets before the next authority.
Raw TCP, native TLS, WS/WSS, HTTP proxy, MQTT redirect, and managed reconnect
paths retain the same explicit `AddressConnectPolicy`. Ordered fallback remains
the compatibility default. Happy Eyeballs is opt-in, bounded, deadline-aware,
and cancellation-safe; connector-specific policy wins when present, otherwise
reconnect-owned policy is inherited. Returned addresses never replace MQTT
authority or TLS identity, and literal IP targets bypass the resolver/race.
WS and WSS listeners may additionally require an exact Origin allowlist; a
configured policy rejects missing, duplicate, or non-matching Origin headers
before the 101 response, while the default remains disabled for native clients.
Like rumqtt's audited `ws_stream_tungstenite` adapter, each write is one binary
WebSocket message while reads expose a continuous byte stream: an MQTT packet
may span messages and one message may contain bytes from multiple packets.
Client masking is done in place on the temporary encoded packet to avoid an
extra payload copy. Broker Keep Alive enforcement also remains packet-scoped:
one absolute deadline spans WebSocket fragments, messages, and control frames,
so Ping/Pong traffic cannot keep an otherwise idle MQTT session alive.

`zig build interop-mqtt-websocket-mosquitto -Doptimize=ReleaseFast` now imports
the audited Mosquitto `mqtt_packets.py` generators and `WebsocketWrapper` as an
external peer. It runs MQTT 3.1, MQTT 3.1.1, and MQTT 5 over both WS and
certificate-verified TLS 1.3 WSS. Every case sends a 65,556-byte QoS 1 PUBLISH
split across two WebSocket messages, coalesces a following MQTT PINGREQ into
the second message, checks the exact PUBACK and PINGRESP, then verifies a netz-originated
QoS 1 PUBLISH byte-for-byte before acknowledging it and disconnecting. The
finite netz process validates the client ID, topic, complete payload pattern,
and disconnect, so success cannot be inferred from the HTTP upgrade alone.
The WS/WSS endpoint obtains its `std.Io` from `netz.runtime.Backend`; readiness
and success records require `client_io=python-socket server_io=zio-std-io`. The
same gate also runs MQTT 5 behind Mosquitto-shaped PROXY v1 WS and PROXY v2 WSS
prefaces before the HTTP or TLS handshake.
`zig build interop-mqtt-websocket-origin -Doptimize=ReleaseFast` separately
ports Mosquitto's `13-websocket-bad-origin.py` request shape: a disallowed
origin is closed before upgrade, then an allowed origin completes WebSocket and
MQTT 5 negotiation on the same finite zio-backed server process; its runner
requires the same backend identity rather than accepting a generic listening
message.

The audited rumqtt client supports MQTT 3.1.1 and MQTT 5 over WebSocket, while
the rumqttd server path still contains `TODO: Add support for V5 protocol with
websockets`. Netz tests all three MQTT versions end to end on its client and
server and
also covers cross-message packet reassembly, QoS 1, QoS 2, and strict
subprotocol rejection. Client `wss://` uses the generic WebSocket TLS
transport. Setting `ConnectOptions.client_identity` or a TLS version policy
selects the shared vail-backed TLS 1.2/1.3 client, which sends supported
client identities and maps
the same system/caller CA plus hostname policy or a pin/custom
`server_verifier`. Cleartext address-based `connect` rejects configured TLS
credentials instead of silently dropping them.

Netz additionally terminates WSS natively with the same strict `mqtt`
subprotocol and MQTT 3.1.1/5 state machine as WS. The TLS listener supports
concurrent serving and optional/required client certificates; verified peer
chains remain visible through `Connection.peerCertificates()`. End-to-end
tests prove the public MQTT WSS client performs authenticated CONNECT and QoS 1
PUBLISH/PUBACK while the server observes the exact verified client DER chain.
Mosquitto exposes the analogous client certificate/key capability through
`mosquitto_tls_set` regardless of whether MQTT is carried directly or over
WebSocket; netz now preserves that transport parity with typed in-memory
identities instead of requiring certificate/key file paths.

## Native MQTT-over-TLS transport

The native vail transport now negotiates TLS 1.2 and TLS 1.3. Callers can
require either version or offer both with TLS 1.3 preference. The TLS 1.2
profile is deliberately modern: ECDHE with AES-GCM or ChaCha20-Poly1305,
mandatory Extended Master Secret and secure-renegotiation signaling, no CBC,
static-RSA key exchange, or renegotiation. Listener `tls_version`/`ciphers` and
bridge `bridge_tls_version`/`bridge_ciphers` map this policy explicitly.
Both endpoint roles support X25519, P-256, P-384, and P-521. The dual-version
client retains independent TLS 1.2 private material for every group it
advertises, so an OpenSSL TLS 1.2 server may select its default X25519 rather
than being restricted to a test-forced P-256 fallback. Netz's high-level
client/server default is X25519-first with P-256 fallback, matching the modern
OpenSSL/rustls preference; Vail's low-level caller-owned policy remains
explicit. Mosquitto-compatible `tlsv1.2` remains a minimum-version policy;
Netz additionally accepts `tlsv1.2-only` on listeners and bridges when an exact
version boundary is required. That mode advertises all four groups, while the
dual-version ClientHello advertises only X25519/P-256 because those are the
TLS 1.3 retry keys it retains. A production OpenSSL gate forces P-384 and P-521
in turn and completes MQTT 5 with Netz in both client and server roles.
TLS 1.2 clients filter a configured identity against CertificateRequest's
certificate types, signature algorithms, and acceptable CA distinguished
names. Compatible P-521 identities are supported; when no identity is suitable
the client sends an empty Certificate so optional mTLS can continue and
required mTLS is rejected by the server at the protocol boundary.
The `interop-tls12-client-auth-openssl` process gate independently verifies
both a matching certificate and an unmatched optional-mTLS request through
the same shared stream used by MQTT TLS and WSS. The server rejects a client
CertificateVerify algorithm it did not advertise.
The matching `interop-tls13-client-auth-openssl` gate verifies that TLS 1.3
uses the same CA-aware selection and empty-certificate fallback. Unknown TLS
1.3 CertificateRequest extensions are ignored for forward compatibility, but
duplicate extension types remain fatal across the complete 16-bit namespace
without an arbitrary count ceiling. Repeated signature-algorithm values remain
acceptable in TLS 1.2/1.3 ClientHello and TLS 1.3 CertificateRequest vectors.
A present certificate-authorities extension must contain at least one non-empty
DistinguishedName; omitting it permits any issuer. Non-empty request contexts
are rejected during the initial handshake and remain reserved for post-handshake
auth. TLS 1.3 servers can additionally send OID filters; clients enforce Key
Usage and Extended Key Usage subsets on the leaf, reject repeated or malformed
recognized filters and prohibited anyExtendedKeyUsage requests, and ignore
unrecognized OIDs. CertificateRequest accepts and exposes the standard empty
status-request signal, rejects non-empty forms and recognized extensions that
are illegal in that message, and ignores only genuinely unknown extensions.
Client identities can carry leaf or per-entry OCSP staples; clients send them
only when requested, while servers reject unsolicited staples and preserve the
CertificateEntry association for trust verification.
Servers validate the complete CertificateRequest and its
nested vector lengths before writing ServerHello, preserving transactional
failure for invalid authentication configuration.
HTTP/1, HTTP/2, WSS, and MQTT round-trip tests force TLS 1.2, while OpenSSL
interoperability covers both endpoint roles and good/missing/revoked OCSP.
The shared stream also exposes RFC 5077 TLS 1.2 ticket issuance and resumption:
servers use an application-owned bounded keyring and generate a unique sealing
nonce per connection, while clients can transfer an owned ticket cache into a
later connection. TLS 1.3 ticket extension parsing covers the complete 16-bit
namespace, rejects duplicates, recognized misplaced extensions and the
RFC-forbidden 65,535-byte vector, while ignoring genuinely unknown extensions.
Cached state is bound to the server identity, ALPN, cipher suite, and lifetime;
an unauthentic ticket falls back to a full handshake.
The reconnect client owns the newest TLS 1.2 ticket independently of each
short-lived Network Connection and supplies it only through ticket-aware
native TLS/WSS connectors. A renewed ticket replaces and securely destroys the
prior cache; an expired cache is destroyed before dialing, while an
unauthentic ticket is replaced after the server's full-handshake fallback, so
neither stale form can poison later reconnect attempts. The shared stream's bidirectional
`interop-tls12-ticket-openssl` process gate independently proves both netz
client and netz server resumption against OpenSSL rather than relying only on
self-interoperability.
The versioned stream additionally exposes RFC 8446 TLS 1.3 PSK-DHE tickets:
post-handshake messages are authenticated and retained instead of discarded,
and the server issues a fresh stateless ticket after either a full or resumed
handshake. The shared parser preserves finite RFC 8446 early-data limits even
though MQTT leaves early data disabled; zero-lifetime tickets are consumed and
discarded without failing the live connection or replacing an older cache entry.
Client caches and server keyrings expire tickets at the exact advertised
lifetime boundary and reject timestamps before issuance.
The bidirectional
`interop-tls13-ticket-openssl` gate validates
both endpoint roles against OpenSSL. MQTT reconnect now owns, ages, renews, and
reuses these TLS 1.3 tickets across both native TLS and WSS connections. Its
connector contract carries TLS 1.2 and TLS 1.3 state together, preserving
version fallback without sharing ticket state between protocols. Early data
remains disabled, so MQTT CONNECT ordering is unchanged.
Configured TLS bridges use the same reconnect-owned lifecycle for both ticket
versions. Before a multi-address attempt, the connector validates each cached
ticket against the selected endpoint hostname and lifetime; a failover target
therefore performs a full handshake instead of receiving another host's
resumption state.
Configured MQTT TLS and WSS listeners can enable either version with
`tls12_session_tickets true` or `tls13_session_tickets true`, an explicit
matching `*_session_ticket_server_id`, and a bounded
`*_session_ticket_lifetime`. Each logical listener owns independent, securely
generated process-lifetime TLS 1.2 and TLS 1.3 keyrings shared by its IPv4/IPv6
sockets, preventing the protocols from sharing an AEAD key/nonce domain. The
configuration rejects missing identities, policies that do not offer the
configured ticket version, zero or overlong lifetimes, and TLS
client-authentication combinations whose peer identity cannot safely survive
stateless resumption. Dedicated Python/OpenSSL gates verify both versions on
configured MQTT/TLS and MQTT-over-WSS listeners through complete MQTT 5
CONNECT/PING/DISCONNECT exchanges.

`mqtt.tls_runtime.Client` accepts host names, literal addresses with an explicit
TLS identity, and `mqtts://`/`ssl://` URIs (default port 8883). It reuses the
same Zig 0.16 TLS client as HTTPS/WSS, including operating-system roots,
caller-managed CA bundles, hostname verification, and explicit truncation
policy. Setting `ConnectOptions.client_identity` or a non-default TLS version
policy selects the vail TLS 1.2/1.3
stream client so it can answer CertificateRequest with Ed25519, ECDSA, or SM2
identity material. The vail path maps the same system/caller CA and hostname
policy by default, or accepts a pinned/custom `server_verifier`; clients
without an identity keep the standard-library TLS path.
Configured bridges also support Mosquitto's explicit `bridge_insecure true`
compatibility switch. It disables only DNS/IP certificate identity matching;
the selected CA path, validity, signature, serverAuth EKU, revocation and
stapled-OCSP policies remain enforced. The default remains strict. A production
OpenSSL gate exercises TLS 1.2 and TLS 1.3 independently: the default rejects a
CA-trusted `DNS:localhost` certificate when the bridge target is `127.0.0.1`,
the explicit opt-in completes MQTT 5, and an opt-in peer signed by an
unconfigured CA is still rejected. Its TLS 1.2 arms leave OpenSSL's group
selection at the default, exercising X25519 rather than forcing P-256.

`mqtt.tls_runtime.Server` is a native TLS 1.2/1.3 listener backed by project-local
vail primitives. It accepts caller-provided DER certificate chains and
Ed25519/ECDSA/SM2 signers, generates fresh handshake/key-exchange/signature
entropy per connection, supports separate TLS 1.2 and TLS 1.3 cipher-suite preference,
supports an ALPN protocol list with mandatory overlap when configured,
fragments large MQTT writes into bounded TLS records, and preserves byte-stream
semantics when records and MQTT Control Packets have different boundaries. The
accepted transport enters the same MQTT broker-side CONNECT, capability, Topic
Alias, inflight and QoS state machine used by TCP and WebSocket. Client and
server both default TCP_NODELAY on for latency-sensitive control packets and
allow callers to retain Nagle for batching-oriented deployments.

`ListenOptions.client_auth` adds runtime-selectable optional or required mTLS,
rather than rumqttd's process-wide `verify-client-cert` build feature. It emits
TLS 1.3 CertificateRequest, validates the returned chain through a caller
callback or pinned Ed25519/ECDSA/SM2/RSA key, verifies client
CertificateVerify possession and Finished, and keeps an owned peer DER chain
available from `Connection.peerCertificates()` until close. Optional mode
accepts the standards-compliant empty client Certificate response; required
mode rejects it.

Direct MQTT TLS clients can likewise send an ordered ALPN offer without
requiring a client certificate. This selects the vail-backed client path,
retains normal system/caller-CA and hostname verification, and makes the
server-selected value available through `Connection.negotiatedAlpn()` on both
ends. The same client path now retains the complete verified server certificate
chain and exposes it through `Connection.peerCertificates()` for native MQTT
TLS and WSS; server-side mTLS continues to expose the verified client chain.
Both endpoint roles also expose RFC 8446 exporter keying material for
application authentication and channel binding, together with typed
`negotiatedCipherSuite()` and `negotiatedTranscriptHash()` metadata for native
TLS and vail-backed WSS. Unsupported cleartext and standard-library TLS paths
return null instead of synthesizing negotiation state.
MQTT-over-WebSocket can select the vail path independently of client identity,
so ordinary WSS clients receive the same metadata and exporter/KeyUpdate
surface instead of requiring mTLS as an accidental feature flag. Native MQTT
TLS and MQTT-over-WSS options both expose the shared `stapled_ocsp` /
`request_ocsp` policy; requiring a staple selects vail automatically and
rejects the TLS connection before MQTT or WebSocket bytes are emitted.
The same transports expose explicit RFC 8446 application traffic-key rotation
and sent/received update counters. Native MQTT TLS tests require a reciprocal
update before PING/DISCONNECT, proving MQTT framing survives both new epochs.
This covers rumqttc's configurable TLS ALPN surface and Mosquitto's
client/bridge ALPN option while also giving server applications the negotiated
identity directly. Empty ALPN lists preserve the existing standard-library TLS
client path.

End-to-end tests cover a real production-listener handshake with verified
localhost CA/SAN, MQTT 5 CONNECT and QoS 1 PUBLISH/PUBACK, plus MQTT 3.1.1
through `mqtts://`. Native Zig client/server mTLS tests prove client
CertificateVerify, peer-chain exposure, CA/SAN verification, and bad server-pin
rejection. The explicit
`zig build interop-mqtt-mtls-openssl` gate additionally proves authenticated,
ECDSA and RSA-PSS client identities, anonymous-rejected, untrusted-rejected,
and optional-anonymous TLS 1.3 paths plus required ECDSA mTLS over TLS 1.2
against OpenSSL's real
client-certificate implementation. The netz endpoint obtains `std.Io` from
zio, and the gate requires every readiness/result record to identify
`client_io=openssl-sync server_io=zio-std-io`.

Run the steady-state 1 KiB QoS 1 baseline with:

```sh
zig build bench-mqtt-tls -Doptimize=ReleaseFast
```

The maintained client and local TLS server now obtain `std.Io` from zio, the
server is scheduled with `std.Io.async`, and the structured result identifies
both endpoint runtimes as `zio-std-io`.

The numbers below are the 2026-08-18 same-host `ReleaseFast` Threaded baseline,
the median of three runs after 100 warmups and 2,000 measured PUBLISH/PUBACK
exchanges through the production TLS server and MQTT broker-side runtime:

```text
ns/publish+PUBACK: 19,427
operations/s:      51,473
```

This is a reproducible netz baseline rather than an equal-wire rumqtt speed
claim. Unlike rumqtt's feature-gated rustls/native-tls split, the netz API is
available through one built-in Zig TLS transport.

The audited rumqttd rustls path can require a client certificate only when
built with `verify-client-cert`; its native-tls path cannot authenticate
clients. Netz exposes optional/required policy per listener without a feature
split, returns verified peer chains to the application, and provides a native
vail-backed client-identity path. External clients such as OpenSSL also
interoperate with the server.

## zio timed-I/O runtime fast path

The runtime dependency now pins the pushed `passchaos/zio` commit
`aa1a91f768f4ff9ae92c9937c6b8ef5d0d0e8851`. It includes the direct waiter
change from `4f12748e`: a timed I/O operation inside a runtime task uses the
completion's `Waiter` timer instead of building a general two-member
`Group(.race)`. The blocking/no-task fallback is retained, and both timeout and
external cancellation explicitly cancel and join the outstanding I/O
completion. The follow-up also avoids refreshing the event-loop clock when a
timer already carries an absolute deadline; relative durations still receive a
fresh origin, and `poll` refreshes every clock before expiry checks. Dedicated
tests cover natural completion, timeout, cancellation, absolute-deadline
firing, and cached-clock preservation under default, epoll, poll,
single-executor, and pinned scheduling; the complete zio suite passed 763 tests
with 8 platform skips.

A five-pair, fixed-binary, AB/BA, CPU-pinned MQTT 5 QoS 2 comparison accepted
only samples with no concurrent Zig compiler. Candidate/baseline paired medians
were 1.0584x throughput with 0.9210x p50 for serial traffic, 0.9973x/1.0040x
for publishers-32, 1.0110x/0.9551x for fanout-32, 1.0010x/0.9892x for balanced
32x32, and 1.0176x/0.9476x for the 4-KiB shape. The 4-KiB candidate won all
five throughput pairs and lowered p99 in all five. Seven additional pairs put
MQTT-over-WebSocket at 1.0053x throughput with 6/7 wins and native
MQTT-over-TLS at a neutral 0.9998x. A matched `perf` capture removed
`Group.groupCallback` and `Loop.cancelLocal` from the sampled target path;
`timedWaitForIoClock` self cost moved from 3.11% to 0.48%, with direct waiter
and timer-clear work visible instead. These percentages describe different
total runtimes and are structural evidence, not absolute CPU-time ratios.

For the follow-up absolute-deadline change, a seven-pair CPU-thread-time
microbenchmark reduced absolute timer arm plus clear from 133 to 61 ns/op
(0.4656x median, 7/7 wins). A five-pair MQTT rerun isolated the broker and
driver on CPUs 10 and 11 outside concurrent build affinity; throughput paired
medians were 1.0042x, 1.0122x, 1.0037x, 1.0046x, and 1.0074x across serial,
publishers-32, fanout-32, balanced-32x32, and 4-KiB shapes. The profile's
`clock_gettime` self share fell from 16.35% to 11.54%, with the former 6.17%
waiter child path absent. End-to-end movement is therefore positive to neutral,
while the removed clock read is the primary supported result.

The TCP/TLS/WebSocket packet framing paths now retain the `FixedHeader` they
already decoded to establish the complete packet length and pass it into
`OwnedPacket`, rather than decoding Remaining Length a second time. The common
TCP caller-buffer and uninterrupted owned paths, TLS stream path, and
WebSocket aggregation path all reuse that result; only a large TCP body resumed
by a later call reparses its retained header, avoiding extra steady-state
connection storage. Five fixed-binary CPU-10/11 QoS 2 pairs produced
candidate/baseline throughput medians of 1.0046x, 1.0022x, 1.0041x, 0.9989x,
and 1.0008x across serial, publishers-32, fanout-32, balanced-32x32, and 4-KiB
shapes. The ranges overlap, so no end-to-end speedup is claimed. In matched
100,000-publish profiles, the former 1.33% `FixedHeader.parse` child path below
`readTcpPacketWithPolicy` disappeared. The baseline/candidate broker hashes
are `74cff6622c25318b1d0f6c6fb45a4056af6fcdcb282d049b8fc0a5a2e5959d53`
and `7555c1775b84778f985c69e411f7e52a1761151a3be72493a6df395182b41975`;
the unchanged driver hash is
`30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.

PUBLISH and publish-acknowledgement decoding now continue that ownership chain:
their whole-packet `parse` APIs retain complete standalone validation, while
the broker passes the already bounded Remaining Length payload and header flags
to `parsePayload`. This removes another fixed-header decode from incoming
PUBLISH, PUBACK, PUBREC, PUBREL, and PUBCOMP processing without trusting
unframed network input or adding connection state. Against the framing-only
baseline, five fixed-binary CPU-10/11 QoS 2 pairs produced throughput medians
of 1.0088x, 1.0135x, 1.0025x, 1.0003x, and 1.0002x in serial,
publishers-32, fanout-32, balanced-32x32, and 4-KiB order. The overlapping
ranges again limit the conclusion to no observed regression. In matched
100,000-publish profiles, `FixedHeader.parse` fell from 1.64% to 0.66% self
samples and remained only under outbound `Connection.writePacket`; its
receive-side broker paths disappeared. The framing-only baseline and final
candidate broker hashes are
`7555c1775b84778f985c69e411f7e52a1761151a3be72493a6df395182b41975`
and `51866c4694a3fc96d28491d5d5204f103b97ecb88ccf7acff32ed45ecccf3253`.

Internally generated control packets now use a private typed-write path as
well. CONNECT, CONNACK, publish acknowledgements, subscription controls, PING,
DISCONNECT, and AUTH retain direction, authentication-state, peer-size,
deadline, and transport-failure validation, but no longer decode their own
freshly encoded Fixed Header. Arbitrary Session/restored bytes remain on the
fully validating raw path. Against the preframed-parser baseline, five fixed-
binary CPU-10/11 QoS 2 pairs produced throughput medians of 1.0101x, 1.0006x,
0.9989x, 1.0238x, and 1.0053x in serial, publishers-32, fanout-32,
balanced-32x32, and 4-KiB order. Ranges overlap, so no universal speedup is
claimed. The matched 100,000-publish profile no longer contains
`FixedHeader.parse`; the prior profile's remaining 0.66% came only from
outbound `Connection.writePacket`. The baseline/candidate broker hashes are
`51866c4694a3fc96d28491d5d5204f103b97ecb88ccf7acff32ed45ecccf3253`
and `dccf66204cdb25779951c4ae42a2fd37085710d8e45e69b98b972addceeb2836`.

Both fixed WebTransport binaries also completed 10,000 real
QUIC/TLS/HTTP/3 1-KiB DATAGRAM sends and receives, in batches of 16 with 64
maximum in flight, zero timeouts, and identical checksum. Host compilation
prevented a clean timed pair, so no WebTransport speed claim is made. The full
method, ratios, binary hashes, perf interpretation, and evidence boundary are
recorded in `docs/benchmark-baseline.md`.

Local outbound QoS 2 completion also resumes after in-process journal errors.
If coordinator clearing fails, the adapter reoffers its selected PUBREL with
the same Packet Identifier after receipt rollback. If broker PUBCOMP removal
already happened in memory but its journal write failed, polling retries the
complete broker image before selecting another delivery. Provisional listener
registration remains a retryable SnapshotBusy barrier. Unit tests restore the
broker journal to prove completion was persisted; a bounded real-TCP two-broker
test covers both failures and uses a subscriber PING barrier to reject any
extra target delivery.

Local-consumer QoS 0 completion retains a broker-owned persistence barrier if
the selected delivery was removed in memory but its journal write failed.
Explicit completion retries and polling finish that same barrier before
selecting another message, including polling through a copied consumer handle.
The local bridge separately remembers that its target send finished, so it
retries only local completion. Journal restoration and real-TCP tests cover
in-place retry, local-source reconnect, continued queue draining, and the
absence of a second target publication. Their PING barriers read the next
packet directly rather than using a synchronous helper that can buffer
interleaved PUBLISH packets.

