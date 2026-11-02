# Native xDS matching oracle

Run `zig build interop-grpc-xds-regex --summary all`; add
`-- --output <report.json>` to save hashes and comparison counts.

The gate generates a deterministic corpus of RE2 operators and UTF-8 text,
compares every native full-match result and syntax decision against actual
RE2 WASM, and includes overlapping alternatives and nested repetitions on
large input. The native runner checks that each instruction is visited at
most once per byte position. RE2 wrappers are explicitly released between
patterns to stay within the oracle's fixed WASM memory.

The pure Zig kernel is compiled as an independent module for quick differential
iteration. Public routing/header/domain integration is covered by
`zig build test-lib -Dtest-filter='gRPC xDS' --summary all` and package tests.
