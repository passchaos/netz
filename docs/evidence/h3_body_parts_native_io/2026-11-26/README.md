# H3 body-parts native I/O regression

The named request/response DATA-parts regression replaced `std.Io.userdata`
with a clock observer while retaining Threaded's concurrency callbacks. Actual
bounded sends now admit worker/timer tasks, so those callbacks interpreted the
observer as their backend. The main-branch case reproduced a null-pointer
segmentation fault and process ABRT; [baseline.json](baseline.json) records the
exact filter and log hash.

Each request and response observer now owns a native Threaded sender backend.
Its vtable preserves backend userdata, uses an atomic send-advanced clock and
joins all timed work before leaving the observer scope. Original deadline,
three-byte prefix, FIN, packet-number and same-stream suffix assertions remain.
The backend is destroyed after the endpoint's original I/O has been restored.

[validation.json](validation.json) records 67 macOS tests passing and the same
scope compiling for x86_64 Windows. CI annotation support has 11 passing tests;
segmentation/bus faults and ABRT/ILL exits now retain the preceding test name
and first allocator/stack context instead of reporting only a later build exit.
Windows compilation is not native Windows execution of this changed case.

[ci_1bd_status.json](ci_1bd_status.json) records the preceding production head
`1bd95082b20408baad85ccc674cbdf7ab05f8874`. Native Linux and Windows jobs,
including the new H3 socket-deadline scope, passed. Linux's client CA reload
also passed in that execution. The complete command still exited 137 at its
existing 28-minute bound and recorded an earlier unlabelled test ABRT. The
local reproduction identifies a real main-branch defect; without the aggregate
test name, it does not establish that every complete-gate failure is resolved.
Dependency pins and CI timeout values remain unchanged.
