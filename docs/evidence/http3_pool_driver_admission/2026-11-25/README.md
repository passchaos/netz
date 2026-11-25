# HTTP/3 pool driver admission — 2026-11-25

Run [45593409742](https://github.com/passchaos/netz/actions/runs/45593409742)
on `2a3a663d7e73c728d13f12e0673c890420d49614` reached the 30-minute
job limits. Linux and Windows native trust annotations repeatedly stopped at
`HTTP effective trust Alt-Svc pool accepts a verifier over an inactive CA
bundle`. The test only constructs and destroys a pool; it does not attempt a
peer handshake. Four cross-compilation jobs, bounded fuzz replay and the QUIC
soak passed, while native trust and complete-suite acceptance remained missing.
[The diagnostic receipt](ci-diagnostic.json) retains the exact job and step
results. Complete-suite notices identify a previously completed test, so they
do not diagnose that gate's actual remaining runtime or compilation boundary.

The pool launched its indefinite exclusive and shared request owners with
`std.Io.async`. Its exclusive dispatcher also launched route workers waiting
on a startup barrier with `Group.async`. Both APIs may execute their function
inline before returning. A Threaded backend's default async capacity is CPU
count minus one; exhausting that capacity made construction or worker
registration wait for work that could only be released later by the caller.

The new zero-async-capacity regression reproduces that wait on macOS before
the fix. It reaches the named regression and cannot finish even during fixture
cancellation; its owned Zig tree is terminated at the 60-second guard limit
with exit 137. [The baseline transcript](before.log) records that boundary.

Pool owners and exclusive route workers now use `std.Io.concurrent` and
`Group.concurrent`. Failure to admit a pool owner returns
`ConcurrencyUnavailable`; construction joins an already admitted owner before
freeing the pool. Partial route admission closes the dispatcher and joins its
group while the startup barrier remains alive. Lazy SOCKS5 shared-endpoint
admission clears the incomplete driver and releases its association on failure,
so a subsequent request can retry.

The focused regressions cover zero async capacity for shared and exclusive
backends, rejection of either pool owner with exact allocation reclamation,
rejection of either route worker with group shutdown, and a real SOCKS5
association rejected at lazy owner admission then retried. The retry uses an
invalid URI to end after successful endpoint/driver admission without requiring
a QUIC peer. Existing effective-trust, deadline-close, cloneable route sender
and authenticated SOCKS5 Alt-Svc tests exercise the affected integration paths.
The optional `http3 = null` backend still needs no H3 owner admission.

Local Debug and ReleaseSafe each pass 117/117 tests and 10/10 build steps,
including support tests imported by the focused root. Results are recorded in
[validation.json](validation.json), [Debug.log](Debug.log) and
[ReleaseSafe.log](ReleaseSafe.log). These scoped macOS results do not replace
native Linux/Windows or complete-suite acceptance. CI's existing native trust
filter set includes the new driver-admission regressions; its job limits and
protocol coverage are retained.
