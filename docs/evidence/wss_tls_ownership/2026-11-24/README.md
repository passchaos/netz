# WSS vail TLS helper ownership — 2026-11-24

The WSS identity helper destroyed an established TLS connection when its ALPN
policy rejected the negotiated protocol. Its callers still held their raw
stream close guards until the helper returned successfully, so policy rejection
closed the same socket twice. The helper retained the raw stream on earlier
handshake/setup errors, giving direct callers a different error cleanup
contract depending on the failure stage.

The helper now consumes the supplied stream at entry on all outcomes. A raw
stream guard handles initialization failure; successful TLS initialization
transfers responsibility to the connection, whose guard handles policy
rejection. All three WSS setup paths transfer ownership before invoking this
helper and assume ownership of the returned connection only on success.
The lower-level TLS stream constructors retain their existing contract.

The client-owned regressions live in `runtime/client/tls_ownership_tests.zig`:

- Eight real, authenticated TLS handshakes combine TLS1.2/TLS1.3 with host,
  address, URI and adopted-stream entry points. The peer negotiates `h2`, so WSS
  must return `InvalidAlpn`, close once and deliver no HTTP Upgrade bytes.
- Two direct helper calls exercise a zero TLS budget and first-allocation OOM.
  Both require one close and EOF from the actual TCP peer.

The probe counts every close invocation and forwards the first close to the
real socket. It suppresses a baseline duplicate kernel close so a reused
descriptor cannot affect another fixture task, while the count assertion still
fails at two. It rescues a leaked socket when an early-failure assertion sees
zero closes. Peer tasks finish before replacing the probe delegate.

The overlap set covers the existing direct-helper ALPN rejection, common TLS
budget inheritance, explicit/nested budget overrides, IPv6 authorities, expired
TCP/TLS transition cleanup, ordinary vail WSS KeyUpdate and mTLS echo. Native
Linux and Windows CI select both new ownership regressions.

| Verification | Result | Evidence |
| --- | --- | --- |
| Baseline before production changes | 39/41 passed; two expected failures with 2 and 0 closes | [before.log](before.log) |
| Debug ownership and affected WSS paths | 48/48 passed | [Debug.log](Debug.log) |
| Client-module test layout and ownership regressions | 41/41 passed | [layout.Debug.log](layout.Debug.log) |

```sh
zig build test-websocket '-Dtest-filter=WSS vail TLS rejection closes' '-Dtest-filter=WSS vail TLS helper failure' -j1 --summary failures
zig build test-websocket '-Dtest-filter=WSS vail TLS rejection closes' '-Dtest-filter=WSS vail TLS helper failure' '-Dtest-filter=WSS vail TLS rejects a non-HTTP/1.1 negotiated ALPN' '-Dtest-filter=WSS common handshake budget' '-Dtest-filter=WSS named endpoint' '-Dtest-filter=WSS TLS ownership closes' '-Dtest-filter=ordinary vail WSS client exposes TLS state and KeyUpdate' '-Dtest-filter=WSS public client identity completes mTLS echo' -j1 --summary all
zig build test-websocket '-Dtest-filter=WSS vail TLS rejection closes' '-Dtest-filter=WSS vail TLS helper failure' -j1 --summary all
```
