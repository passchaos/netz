# WebTransport and direct QUIC socket deadlines

Direct STREAM, sliced STREAM, DATAGRAM, terminal/control output and fair
WebTransport stream batches now carry their original awake-clock budget to
cooperative socket submission and the endpoint send mutex. The worker joins
before borrowed payload or progress storage leaves scope. Application bytes,
FIN and payload prefixes commit before an error is exposed; protected unsent
packets still consume their nonces. Development and preconfigured-key
DATAGRAMs share the same joined progress contract.

WebTransport association-prefix submission uses a cohesive sender module;
development/protected DATAGRAM socket work lives in a separate budget module.
`trySendDatagramsWithDeadline` and its timeout form submit one bounded window
and return pacing/congestion to the endpoint owner without reading UDP.
HTTP/3 CONNECT DATAGRAM pacing retains that reader and the original deadline,
so an already queued CLOSE/STOP or sibling/QPACK input remains observable.

[baseline.json](baseline.json) records a current-source snapshot failure:
after a real UDP prefix event, direct STREAM submission did not return under
its deadline and required the bounded fixture escape. Native probes retain
backend userdata and advance an atomic test clock after actual submission.
Older observer fixtures were migrated to that native context as bounded
operations began admitting concurrent tasks.

[validation.json](validation.json) records the integrated current main based
on `b525e471deebbc41d854eceec690c73e4898e219`: 75 QUIC, 234 WebTransport
and 133 HTTP3 tests passed on macOS; the same scope compiled for x86_64
Windows. Cases include actual prefix/timeout/network-error races, nonce-safe
suffix reuse, valid association prefixes, completed FIN, fair batch counts,
credit/reset state and pacing-time peer CLOSE/STOP with buffered sibling data.
The newer main H3 body-parts fixture was preserved and included in this scope.

The native CI deadline step now includes the portable new raw/associated
STREAM and DATAGRAM regressions. [ci_control_flow.json](ci_control_flow.json)
records shell syntax and child success/error exit preservation. The original
combined protocol step, dependency pins and timeout values are unchanged.
Native Linux/Windows execution and the complete gate still need this change's
CI run. Cross-compilation and this local scope do not establish full acceptance
or an end-to-end throughput improvement.
