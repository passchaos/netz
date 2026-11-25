# Portable audited WebTransport peer — 2026-11-26

The complete job in [run 45652362748](https://github.com/passchaos/netz/actions/runs/45652362748)
failed when the Rust peer tried to read `../../../../../Work/wtransport/wtransport`.
That developer-local checkout is unavailable in CI. The complete command also
reached its existing 28-minute limit; the public failure annotations do not
establish its final active runtime operation.

The peer now fetches the original audited Git revision
`d96cbb87c9127fcb453fb05bbb47ef93402daec2` from
`https://github.com/BiagioFesta/wtransport`. Both `wtransport` and
`wtransport-proto` remain at 0.7.1. Comparing the entire lockfile with the previous
commit preserves all 149 package versions, dependency lists and existing
checksums; only those two packages gain the fixed Git source.

The locked release build and actual native interop both pass. The direct gate
exercises both endpoint directions, CONNECT acceptance/rejection metadata,
DATAGRAM limits, bidi/uni streams, reset/stop codes, sibling progress, connection
reuse and peer close. The SOCKS5 gate also passes with remote DNS and two
associations. [The receipt](validation.json) records the source hashes and
[the transcript](interop.log) retains the runtime results.

Validation ran on aarch64 macOS under the shared build guard. Local script
duration calls use the Python subprocess timeout shim; this does not validate
CI's GNU process-group timeout behavior. Local Vail was `d93847a7`, while the
unchanged CI pin is `3b772b0c`; Vort matches its CI pin. A new pinned complete CI
run remains required. Dependency versions and CI budgets are unchanged.
