# Strict HTTP/2 conformance

The maintained h2spec 2.6.0 source revision
`70ac2294010887f48b18e2d64f5cccd48421fad1` was built with the recorded native
Go toolchain. `reference.json` contains its source and executable hashes.
`owner_sources.json` captures the HTTP/2 runtime and shared owning sources.

| Transport | Tests | Passed | Skipped | Failed |
| --- | --- | --- | --- | --- |
| h2c | 147 | 147 | 0 | 0 |
| TLS 1.3 | 147 | 147 | 0 | 0 |
| TLS 1.2 | 147 | 147 | 0 | 0 |

All runs use the maintained runner's mandatory `--strict` and two-second
per-case deadline. The runner verifies a nonempty complete summary.

The TLS 1.2 build attempt encountered a lexical error in concurrent gRPC
development (`SecretPlan.refresh` capture shadowing), preserved in `tls12.log`.
The completed TLS 1.2 run reused the already compiled server and verified
that every captured HTTP/2 owning source hash remained unchanged. Its command,
server executable hash and successful summary are recorded in `gates.json`
and `tls12.frozen-owner.log`. This is HTTP/2 conformance evidence; it does not
claim completion of other protocol families.

After capture, `build.zig` added the independent gRPC client-target and
federation fixture targets. The captured HTTP/2 and shared runtime source
hashes still match; that build-only addition does not change this server.
