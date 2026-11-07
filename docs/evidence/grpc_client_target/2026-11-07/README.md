# Bootstrap target wire evidence

`full.Debug.final/report.json` records 37/37 passing vectors against the real
LDS subscriptions and backend `:authority` headers of grpcio 1.76.0's C-Core.
The native emitter uses the public `grpc.xds.client_target` resolver. The
report includes exact bootstrap inputs, reference and native results, wire
observations, failures, dependency metadata and executable/source hashes.

The vectors cover bare and qualified targets, default/custom/constant/repeated
templates, escaped authority and service names, queries/fragments, inherited
authority servers, invalid targets and bounded expansion. grpc-js differs on
some URI escaping rules, so it supplies the independent ADS/backend peer while
C-Core supplies the resolver oracle. The capture client confirms the URI
observations through actual communication.

`gates.json` identifies the native build and final wire run. Earlier reports
and logs retain the intermediate failures and corrections. All 1,378 original
process artifacts, including bootstrap JSON and stdout/stderr, are preserved
byte-for-byte in `case-transcripts.tar.gz`; its checksum is adjacent. Extract
from this directory to restore the paths referenced by the reports:

```sh
sha256sum -c case-transcripts.tar.gz.sha256
tar -xzf case-transcripts.tar.gz
```

Reproduce with the commands in `tools/interop/grpc_client_target/README.md`.
The independent wire proof covers resolver behavior; managed federation and
its allocation/transaction boundaries have separate native and wire gates in
`docs/evidence/grpc_federation/2026-11-07/`.
