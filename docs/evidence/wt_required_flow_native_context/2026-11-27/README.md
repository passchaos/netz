# WebTransport required-flow rejection observer

Complete run [45849067907](https://github.com/passchaos/netz/actions/runs/45849067907/job/140010311466)
on `4b1924f4` aborts at case 4792/7490,
`WebTransport required Session flow control retries scoped server rejection`.
Its stack reaches `std.Io.Threaded.groupConcurrent` and the allocator while
starting a deadline task. The fixture installs a send observer's userdata
with an inherited backend VTable, so the task callback interprets that
observer as the backend context.

Both observer installations in `required_flow_tests.zig` now forward every
callback through `forwarded_io.table` with the delegate's actual userdata.
Only the existing send-failure injection is overridden. The observer and its
table remain in scope until the endpoint's original I/O is restored.

All four original required-flow test names and checks remain: shared/reused
opens and queued CONNECT allocate no stream, failed server rejection stays
pending and retries its scoped cause, a sibling HTTP request remains usable,
and pending acceptance sends no status 200 while its protected rejection
reaches the client. The existing one- and two-second deadlines remain.

The tests use the shared native protocol runner: POSIX Threaded with zero
async capacity and the application backend with one executor. The Windows
datagram scope uses the supported application backend. Windows compilation
is distinct from native execution. Delivered complete and native qualification
remain pending; the broader HTTP-family goal stays active.

[validation.json](validation.json) records the original CI failure, final
source hashes and checks: 122 scoped native cases pass on macOS, and the same
scope's Windows compilation passes 8/8 build steps. The original four named
cases retain all 31 assertions. These results do not qualify delivered
Linux/Windows execution or the separate Windows protocol-step timeout.
