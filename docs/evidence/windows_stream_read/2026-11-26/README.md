# Windows Threaded stream completion retention

Base revision: `29a96c7e3a1c33af266930c779acd7b6bf35eef0`.
This change introduces one shared socket-read boundary for HTTP/1, HTTP/2,
WebSocket and both native/standard TLS transport readers.

## Native evidence and acceptance boundary

[Run 45799170389](https://github.com/passchaos/netz/actions/runs/45799170389)
provides the corrected Windows probe's actual result:

```json
{"raw_error":"Canceled","raw_count":0,"raw_changed_bytes":5,"raw_payload_in_buffer":true,"batch_count":5,"batch_cancel_pending":true,"batch_cancel_after_native_completion":true,"exact_suffix":true}
```

The ordinary Threaded read consumed the five-byte payload but returned only
`Canceled`. The actual Batch completion retained five bytes, and real parent
cancellation remained observable after those bytes were returned. A separate
entered pending receive canceled/joined after one native self-alert, left its
idle buffer untouched and reused the same socket exactly.

The original H2 TLS endpoint tests still failed on that revision, with
`RecordTooLarge` in different peer stages. The native primitive's count loss
is established; causal repair of those protocol failures still requires the
delivered adaptation's native Windows results. Local macOS tests or Windows
compilation cannot substitute for that qualification.

## Shared read ownership

[Ordinary reads](../../../../src/internal/stream_io/read.zig) preserve custom
`netRead` callbacks. Matching Windows Threaded read and Batch cleanup callbacks
select [the completion owner](../../../../src/internal/stream_io/windows_read.zig).
It checks pending cancellation before admission, submits the same AFD RECEIVE
with `NO_FAST_IO` and `OVERLAPPED`, and retains request/vector/operation storage
until the native operation has completed or cancellation has joined.

The concurrent Batch wait checks cancellation after each alert. Threaded's
async wait holds one alertable syscall across its pending loop, so an idle
read need not finish after a cancellation alert; it is not used here. Before
canceling a pending Batch, one current-thread alert lets Threaded's initial
infinite cancel wait advance to `NtCancelIoFileEx` and completion join. There
is no socket-mode change or polling loop.

Successfully completed bytes and EOF win interruption, and cancellation is
rearmed only after an actual canceled wait. An unavailable wrapped wait maps
to the existing ordinary stream-reader resource error when no completion was
accepted. The public reader error surface stays unchanged.

Timed fallback reads use the same primitive inside their existing joined read
task; their original deadline watcher and completion retention remain in place.
Already canceled callers are rejected before admitting those tasks. Vector
reads retain up to eight destinations for the standard TLS Reader. Connection
and TLS record cursors advance only after the accepted count is returned.

## Focused verification

All Zig commands ran serially under the shared guard with Zig 0.16.0:

- Native core scopes: 17 HTTP/1, 57 HTTP/2 and 35 TLS passes; five Windows-only
  tests skipped in each scope on macOS.
- Native protocol scopes: 49 HTTP/1, 137 WebTransport and 22 WebSocket passes.
  The original H2 Threaded/TLS traffic, KeyUpdate, capacity, close and handle
  reuse assertions remain unchanged.
- QUIC prefix scope: 35 passes. Its observer now forwards all callbacks to the
  actual delegate and tests real Future admission, cancellation and join. It
  runs POSIX Threaded plus the application backend; Windows uses application
  IOCP for its supported timed UDP operation.
- Matching Windows compilation: core 14/14, protocol 14/14 and QUIC 8/8 steps.

The five new Windows tests cover completion/cancellation with bytes and EOF,
entered idle-read cancellation and socket reuse, cancellation before admission,
64 active send/cancel races conserving the exact TCP prefix, and two-destination
vector completion. Both ordinary and timed forms are covered. The existing
native resolver filter selects them without changing its command.

An independent native QUIC prefix command follows the existing protocol and
probe commands inside their unchanged five-minute step. Original commands,
dependency pins, budgets and real migration tests are preserved.

[validation.json](validation.json) records source hashes, exact commands and
native annotations. Native Windows adaptation acceptance, full-library ABRT
triage and fixed-workload performance measurements remain separate work.
