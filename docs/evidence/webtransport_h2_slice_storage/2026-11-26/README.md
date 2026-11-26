# WebTransport H2 sliced command storage

The client and server endpoints previously concatenated slices in a temporary
allocation and then cloned that buffer into the command arena. Both now check
deadline and caller cancellation before staging, and copy payload slices directly
into the arena owned by the queued job. The public signatures and command
execution path retain their existing ownership, stream-ID, slice order and FIN
contracts. Payload staging failure releases every provisional job and parent
reference.

The selected tests mutate both caller payloads and slice descriptors after job
creation, abandon the caller reference while preserving the queue reference,
inject every staging allocation failure, and count caller allocations through
real public endpoint submission and its sole worker. The counter comparison uses
a stale handle to isolate command storage from Session serialization. Expired
and wrong-clock calls run with payload allocation denied and make zero allocation
attempts. Separate real TLS tests exchange sliced STREAM payloads in both endpoint
roles. The formal H2 WebTransport root imports all new tests.

[validation.json](validation.json) records exact current sources, filters, native
results and same-scope Windows cross-compilation. It measures command staging,
without claiming throughput or total wire copies. Native Linux/Windows CI gets
an independent H2 wake and sliced-storage command under the original five-minute
protocol budget; original combined commands and dependency pins are preserved.
Complete acceptance remains open.
