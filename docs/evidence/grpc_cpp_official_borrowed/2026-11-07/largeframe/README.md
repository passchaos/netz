# Official grpc-cpp comparison: large frames, cached allocator, borrowed writes

This is the same official harness at netz `43139e7a` versus grpc-cpp
`03d65cc67c`, with the native benchmark configured for the library's 256-KiB
frame default, the opt-in cached allocator and borrowed SharedChannel request
storage. Five alternating samples pinned CPU 12, used 100 warmups and 2,000
measured roundtrips, and validated every netz payload byte.

| Mode | Payload | netz median ns | grpc-cpp median ns | netz / grpc-cpp |
| --- | ---: | ---: | ---: | ---: |
| Persistent | 0 | 13,423 | 31,896 | 0.421 |
| Persistent | 512 | 13,706 | 32,507 | 0.422 |
| Persistent | 4 KiB | 16,935 | 34,790 | 0.487 |
| Persistent | 256 KiB | 249,500 | 236,982 | 1.053 |
| RPC per roundtrip | 0 | 42,782 | 85,184 | 0.502 |
| RPC per roundtrip | 512 | 43,141 | 86,178 | 0.501 |
| RPC per roundtrip | 4 KiB | 45,815 | 88,712 | 0.516 |
| RPC per roundtrip | 256 KiB | 276,230 | 298,508 | 0.925 |

The 256-KiB per-call mode is faster than grpc-cpp in this configuration, while
persistent ping-pong remains 5.3% slower. A CPU-0 run of the same configuration
measured 1.048x and 0.916x, so the result is stable across two CPUs. The earlier
2026-11-02 0.946x/0.825x table used a different host state; these current
samples are internally alternating and are not a cross-run regression claim.
This remains a same-application-shape comparison: grpc-cpp serializes and parses
protobuf while netz uses pre-encoded messages.
