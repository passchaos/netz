# Trust startup cancellation and deadlines — 2026-11-25

At `1baf040c`, the low-level QUIC `SSL_CERT_FILE` path maps a canceled file open
to `NativeTrustStoreUnavailable`. Default facade root loading also bypasses
the caller's deadline before invoking the bounded H3 handshake. Three
regressions reproduce canceled configured-root loading, pending cancellation
before default roots, and an operation completing after its startup budget.
The baseline reports 33/36 passed with those three failures.
The cancellation cases exercise the original public APIs; the deadline case
uses a direct-load baseline matching their original synchronous root-loading
behavior before the shared operation owner existed.

The shared TLS trust-loading owner reserves a strict absolute-deadline watcher
before admitting root loading. It keeps loader arguments alive through joined
completion and releases every rejected owned store. Deadline checks cover
admission, operation execution, both success and error completion, and transfer
to the connection. Bounded loads reject unavailable concurrency instead of
performing the operation inline.

The QUIC trust adapter preserves local cancellation, memory and admission
errors while retaining its source-unavailable classification. A stable
authentication owner removes root/verifier lifetime management from the large
handshake module. Unified H3, H3 WebSocket and WebTransport URI facades forward
their existing deadline through default root loading. TCP verified-client TLS
1.2/1.3 startup includes system roots in the original handshake budget.

The [architecture note](../../../architecture/trust-startup.md) describes
ownership, error and timing boundaries. Verification commands and results are
recorded beside this document.

| Verification | Result | Evidence |
| --- | --- | --- |
| Original cancellation and startup deadline regressions | 33/36 passed; three failures | [before.Debug.log](before.Debug.log) |
| Root-loading admission, cancellation/late cleanup, authenticated QUIC/TLS, trust policy and owning URI constructors | 408/408 passed | [Debug.log](Debug.log) |
| H3 secure entropy and real startup/observed-cancellation overlap | 65/65 passed | [h3-overlap.Debug.log](h3-overlap.Debug.log) |
| Selected trust guards for Windows across QUIC/TLS/HTTP/WebSocket/WebTransport | Compiled | [windows.compile.log](windows.compile.log) |
| CA file authentication through configured and caller-owned stores with one zio runtime | 35/35 passed | [authentication.Debug.log](authentication.Debug.log) |
| Both CA authentication fixture modes for Windows | Compiled | [authentication.windows.compile.log](authentication.windows.compile.log) |

The authenticated native-root fixture verifies the stable lifetime of the
`BundleVerifier` callback context, in addition to the system store's lifetime.
Late success/error tests advance a controlled clock only after the loader
starts and account for every allocation released before the owner returns.
The caller-cancellation fixture observes loader entry, cancels the owning task,
and verifies loader exit after the join.

The configured `SSL_CERT_FILE` authentication fixture uses one zio runtime and
a joined server task. A second mode loads the same PEM into a caller-owned
system store, so the borrowed-store callback path can run on native Windows
without modifying the process environment. Native CI selects both actual CA
authentication modes alongside startup admission and cancellation checks.

The [native follow-up](../../ca_bundle_lock/2026-11-25/native-platforms.json)
at `1ff6cb48` records successful Linux and Windows trust-startup gates, including
the Windows positional PEM preparation fix and CA bundle lock admission.
