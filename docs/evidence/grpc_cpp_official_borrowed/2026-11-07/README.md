# Official grpc-cpp comparison with borrowed SharedChannel writes

This directory records the official `grpc_benchmark.py` comparison at netz
`8b83e575` against grpc-cpp `03d65cc67c`. The native arm used the new
`--borrowed-writes` SharedChannel request storage; both sides used the benchmark
defaults (16-KiB frames, 65,535-byte stream/connection windows). Five
alternating samples pinned CPU 0, used 100 warmups and 2,000 measured
roundtrips, and validated every netz payload byte.

| Mode | Payload | netz median ns | grpc-cpp median ns | netz / grpc-cpp |
| --- | ---: | ---: | ---: | ---: |
| Persistent | 0 | 13,245 | 32,213 | 0.411 |
| Persistent | 512 | 13,641 | 32,819 | 0.416 |
| Persistent | 4 KiB | 16,766 | 35,214 | 0.476 |
| Persistent | 256 KiB | 407,731 | 244,080 | 1.670 |
| RPC per roundtrip | 0 | 47,540 | 86,277 | 0.551 |
| RPC per roundtrip | 512 | 48,031 | 87,058 | 0.552 |
| RPC per roundtrip | 4 KiB | 51,465 | 89,889 | 0.573 |
| RPC per roundtrip | 256 KiB | 482,390 | 315,316 | 1.530 |

The 256-KiB ratios improve from the earlier default-shape 2.079x/1.846x record
to 1.670x/1.530x. grpc-cpp includes protobuf serialization and parsing while
netz uses pre-encoded messages, so this remains a same-application-shape
comparison rather than an equal-wire or equal-API claim.

`context.json` records the clean netz revision, executable hashes, CPU and
storage mode. `summary.json` contains every native and grpc-cpp sample.
`netz-*.log` and `grpc-cpp-*.log` are the raw alternating-sample records.

Reproduce after building the pinned grpc-cpp benchmark:

```sh
cd ~/Work/grpc
CC=/usr/bin/gcc CXX=/usr/bin/g++ bazel build \
  --compilation_mode=opt --lockfile_mode=off \
  //test/cpp/microbenchmarks:bm_fullstack_streaming_ping_pong
cd /home/passchaos/project-z/netz
zig build bench-grpc-cpp -Doptimize=ReleaseFast -- \
  --cpu=0 --samples=5 --netz-borrowed-writes
```
