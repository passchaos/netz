# Authentication surfaces

Reviewed against the public source surfaces on 2026-11-20. The credential
transport, identity verifier and application authorization policy are separate
layers; protocol handshake checks do not establish a logged-in application user.

| Protocol | Credential / identity surface | Built-in policy and application boundary |
| --- | --- | --- |
| HTTP | TLS server certificate verification and client certificates; `RequestOptions.headers` carries Authorization, Cookie and application-defined fields. | H1/H2 stream TLS supports optional/required client authentication. H3 uses QUIC client authentication. Generic HTTP Basic/Bearer validation, JWT validation and RFC 7616 Digest challenges belong to the application. The content `http.digest` module implements RFC 9530 integrity fields. |
| WebSocket | Native opening-handshake `extra_headers`, CookieJar adapters and WSS client identities; HTTP/2 and HTTP/3 extended CONNECT carry regular fields. | Pending Upgrade/CONNECT values expose request fields before success and can reject admission. WSS supports optional/required mTLS through the stream TLS policy. Bearer/Basic/Cookie verification remains application policy. |
| WebTransport | Native Extended CONNECT `headers`, handshake-backed QUIC client identity and H2 TLS transport identity. | Pending session admission exposes authority/path/Origin/fields and supports rejection before success. Origin policy and session limits are built in; token/Cookie/Basic verification is application policy. |
| MQTT | MQTT 3.1.1/5 CONNECT username/password, MQTT 5 Authentication Method/Data plus AUTH packets, native TLS/WSS client identity. | Broker CONNECT callbacks, a Mosquitto password-file verifier, initial Enhanced Authentication and live reauthentication callbacks, and certificate identity-to-username mappings. Named SCRAM/OAuth/JWT mechanisms are supplied by application callbacks. |

## HTTP, WebSocket and WebTransport

Native clients can send an `Authorization: Bearer ...` or Basic field without
changing protocol framing. HTTP uses `http.RequestOptions.headers`, WebSocket
H1 uses `websocket.runtime.ConnectOptions.extra_headers`, and WebTransport
uses its CONNECT option `headers`. Cookies can be managed through HTTP
CookieSession and WebSocket CookieJar adapters. WebTransport can carry an
explicit Cookie field through its native header API; it has no corresponding
automatic CookieJar session composition. A runnable 401 challenge plus Bearer
and Basic exchange lives in `examples/http/client_auth.zig`.

WebSocket servers inspect `PendingUpgrade.header()`/`headers()` before sending
101; extended CONNECT and WebTransport use their pending admission surfaces
before 2xx. Applications can validate a token, credentials or session and
return a failure response. Native custom-header options are not interchangeable
with browser WebSocket/WebTransport constructors; browser credential behavior
must be handled at that integration boundary.

TLS client verification can use configured trust stores, pinned keys or
application verifiers. URI-level HTTP (H1/H2/H3, direct and pooled), WSS and
WebTransport clients verify with platform roots by default; low-level QUIC
session helpers keep the explicit-configuration contract. Native TCP TLS
supports optional or required client certificates. The current QUIC/H3
`client_auth` path requires a client identity when CertificateRequest is sent;
it does not implement anonymous optional-client completion. This requirement
also applies to H3 WebSocket and WebTransport.

Protocol nonce/accept-key checks, Origin checks and QUIC address-validation
tokens have their own protocol roles. Application credentials and authorization
are validated independently. TLS ticket/PSK resumption retains transport
authentication context while application login policy continues to apply.

## MQTT

`mqtt.runtime.ConnectOptions.username` and `password` populate CONNECT.
`broker.Options.connect_authorization` handles username/password policy, with
transport-aware and listener-local counterparts. Anonymous admission is an
explicit broker/listener policy.

`mqtt.password_file.File` verifies Mosquitto Argon2id entries, `$7$`
PBKDF2-SHA512 entries and legacy `$6$` salted SHA-512 entries. It rejects
plaintext/malformed entries and owns the decoded credential generation.

MQTT 5 Enhanced Authentication uses Authentication Method/Data and AUTH
challenges, with client `ClientAuthHandler.respond` and broker
`AuthenticationHandler.start`/`handle`. The runtime owns method consistency,
packet direction, initial authentication state, completion and reauthentication;
callbacks implement the mechanism's credential validation and challenge data.
An application can establish an authenticated username through that exchange.

TLS/WSS mTLS retains verified peer certificate chains. Listener policy can map
the certificate commonName or complete Subject into the MQTT username through
`use_identity_as_username` or `use_subject_as_username`. Trusted PROXY v2 SSL
assertions have their separately configured identity boundary. Topic ACL and
per-listener authorization apply after identity policy.

Sources: [HTTP options](../src/http/client/types.zig),
[WebSocket runtime](../src/websocket/runtime.zig),
[WebTransport runtime](../src/webtransport/runtime.zig),
[QUIC handshake](../src/quic/handshake.zig),
[MQTT runtime](../src/mqtt/runtime.zig),
[broker policy](../src/mqtt/broker.zig),
[password verifier](../src/mqtt/password_file.zig).
