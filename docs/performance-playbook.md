# netz performance playbook

This is the operational guide for measuring and improving netz. It complements
`docs/architecture.md`: the architecture document defines what must stay true,
this document defines how to prove that a change is faster without breaking it.

## 1. Before optimizing

Do not start from intuition. A performance change needs one of:

- a benchmark scenario that is part of a maintained target
  (`zig build bench-*`) and a profile or count showing the path is hot;
- a reference-gate observation (quic-go, nghttp, Mosquitto, Autobahn, gRPC C++)
  showing a gap;
- an architectural defect with a provable resource bound, such as an
  amplification or a hidden allocation.

Record the current number first. A change without a before number cannot be
retained.

## 2. Profiling

Use release-mode fixed binaries, not `Debug` or ad-hoc test harnesses:

```sh
zig build <bench-step> -Doptimize=ReleaseFast
perf record -F 199 -g -p <pid> -- sleep 3
perf report --stdio --no-children
```

`perf_event_paranoid=1` allows same-user process sampling on this host. If
ptrace is restricted, keep the benchmark process alive in terminal mode and
sample by PID; do not attach a debugger to a timing run.

For allocation questions, use a failing or counting allocator around the exact
operation. For cache behavior, compare the same algorithm with a smaller node
or a parallel array before reaching for a different algorithm.

Two profiling traps are common here:

- Looping a short-lived process mixes dynamic-linker and startup samples into
  the profile. Profile a long-running server by PID while a driver connects,
  or loop a CPU-only benchmark that runs long enough to sample.
- The MQTT broker example treats `--connections=N` as a demo connection budget
  and shuts down after N connections. Profiling runs need a high budget, or the
  driver sees `ConnectionClosed`/`ConnectionResetByPeer` partway through.

## 3. Authoring a benchmark

Sampler-backed microbenchmarks use `examples/support/bench_sampling.zig`, which
wraps `harnessz.bench.run`:

- `iterations` is the work performed inside one timed callback;
- `samples` is the number of timed callbacks (default 10);
- `warmup` is untimed callbacks before sampling;
- the callback returns a checksum so dead-code elimination cannot remove work.

Every scenario prints `min`, `p50`, `p90`, `p99`, `mean`, and `stddev`. A
benchmark also supports `--baseline=<path>`, `--update-baseline`, and
`--warn-only` through the shared helper; `zig build bench-record` and
`zig build bench-gate` drive the maintained set.

Rules for benchmark scenarios:

- include a realistic matching and a non-matching case when the operation is a
  filter or lookup;
- include a case where the optimization should be neutral; a claimed win that
  also changes unrelated scenarios needs an explanation;
- never change the workload and the code in the same A/B without recording that
  the workload changed;
- keep checksums stable across both arms so a wrong result cannot look fast.

## 4. Fixed-binary A/B protocol

The accepted protocol for a performance claim:

1. Snapshot the source for both arms. For a single-file experiment, save the
   pre-change file, build the baseline binary, restore the change, build the
   candidate binary. Record both binary SHA-256 values.
2. Pin one CPU: `taskset -c N <binary>`.
3. Run at least eight alternating pairs: odd pairs baseline-first, even pairs
   candidate-first.
4. Collect the scenario values from each run. Report the median of each arm and
   the median of per-pair ratios, plus per-pair wins.
5. Treat a scenario as neutral when the win count is split and the ratio is
   inside noise. Do not describe a neutral result as a win.
6. Keep the raw logs until the evidence JSON is written.

Minimal driver:

```sh
for i in 1 2 3 4 5 6 7 8; do
  if [ $((i % 2)) -eq 1 ]; then order="old new"; else order="new old"; fi
  for arm in $order; do
    taskset -c 2 /tmp/bench-$arm > /tmp/ab-$i-$arm.log 2>&1
  done
done
```

Avoid `rm -f glob*` in `zsh` drivers: an unmatched glob aborts the whole
`&&` chain before the loop starts. Use `find ... -delete` or `setopt null_glob`.

## 5. Host-load policy

This host is shared with other build sessions. The rules are:

- On a loaded host, claim only interleaved ratios and per-pair wins. Do not
  claim absolute nanoseconds or throughput.
- Use `uptime` before and after a batch; record the load range in the evidence
  notes.
- A full test suite that fails only in unrelated timing/deadline tests under
  load must be re-run immediately with the same binary. Record the flake and
  the clean rerun, not just the failure.
- Never start a timing batch while a compile or test suite is running on the
  same cores. Pin the batch to a CPU and keep other work off that CPU when
  possible.
- `--warn-only` on `bench-gate` is for diagnostics on a loaded host. It is not
  evidence that a regression is acceptable.
- The `bench-record` and `bench-gate` steps are serialized in `build.zig`. Do
  not add `-j` parallelism back: concurrent benchmarks compete for cores and
  memory bandwidth and report false regressions even on unchanged binaries.
- Pinning with `taskset` changes the harnessz environment fingerprint because
  the fingerprint includes the process CPU count. Compare a pinned run only
  against a baseline recorded under the same affinity.

## 6. Evidence recording

Every accepted change gets a JSON file under `docs/evidence/<area>/<date>-<slug>.json`.
Required fields:

```json
{
  "schema": 1,
  "date": "YYYY-MM-DD",
  "head": "working-tree or commit",
  "subject": "one-line claim",
  "change": "what changed and why, including invariants preserved",
  "benchmark": {
    "command": "taskset -c N <bench>",
    "pairs": 8,
    "order": "alternating before/after",
    "before_sha256": "...",
    "after_sha256": "...",
    "results": {
      "scenario": {
        "before_ns_per_op": 0.0,
        "after_ns_per_op": 0.0,
        "speedup": 1.0,
        "wins": "8/8"
      }
    }
  },
  "tests": {
    "focused": {"command": "...", "passed": 0, "total": 0},
    "full_library": {"command": "...", "passed": 0, "total": 0}
  },
  "source_sha256": {
    "src/path/file.zig": "..."
  },
  "notes": "host load, neutral scenarios, rejected alternatives, caveats"
}
```

Then run:

```sh
zig build verify-evidence
```

`invalid` and `unreadable` must be zero. `stale` hashes are expected source
drift and are reported, not failed, unless `--strict` is passed.

## 7. Retain or reject

Retain a change when:

- the primary scenario wins outside noise, or the change fixes a provable
  resource/architecture defect;
- no maintained scenario regresses beyond noise;
- focused tests and the full library suite pass;
- the relevant interop gate passes when wire behavior changed;
- the evidence file is complete and the audit reports `invalid=0`.

Reject or revert a change when:

- the win disappears in alternating pairs or the win count is split;
- it buys one scenario by regressing another without an explicit trade-off;
- it adds an allocation, an unbounded buffer, or a hidden retry to a hot path;
- it relies on a benchmark-only fast path that the production API does not use;
- the measurement is too weak to distinguish it from noise.

Record rejected experiments with their numbers in the evidence notes or in
`docs/benchmark-baseline.md`. A rejected idea with data is useful; a rejected
idea without data will be re-tried.

## 8. Common pitfalls

- **Benchmark source drift.** Comparing two binaries built from different
  benchmark sources is not an A/B. Snapshot the benchmark file with the arms.
- **Dead-code elimination.** Return a checksum that depends on every result.
- **First-call laziness.** Warm the exact operation under test; a warmup that
  exercises a different path does not remove lazy initialization.
- **Allocator mismatch.** Compare the same allocator and the same growth
  policy; a benchmark using a different allocator measures the allocator.
- **CPU frequency and migration.** Pin the CPU; do not compare runs on
  different cores.
- **Cache warming.** A one-shot microbenchmark may measure cold caches while
  the production path is warm, or the reverse. State which one the scenario
  models.
- **Workload change disguised as an optimization.** If the scenario now matches
  fewer entries, report matches per operation alongside nanoseconds.
- **Neutral results.** A neutral result is still useful evidence; it prevents a
  future repeat. Do not omit it to make the change look stronger.
- **By-value `self` is not automatically a copy.** Zig's ABI passes large
  aggregates by reference on x86-64; a 1 KiB struct called by value measured
  the same as a pointer call in a noinline micro-test. Measure before
  converting receivers. The reproducible cost is returning or copying
  per-result structs such as entries and match records.

## 9. Quick reference

```sh
# Focused correctness while iterating
zig build test-lib -Dtest-filter=mqtt -Dtest-filter=retained --summary all

# Full library suite (isolated caches avoid cross-session lock contention)
zig build test-lib --summary all \
  --cache-dir /tmp/netz-cache --global-cache-dir /tmp/netz-global

# Microbenchmark
zig build bench-mqtt-retained -Doptimize=ReleaseFast

# Sampler-backed baseline and gate. The steps are serialized in build.zig;
# a quiet host is still required for a gate verdict.
zig build bench-record -Doptimize=ReleaseFast
zig build bench-gate -Doptimize=ReleaseFast
# Loaded-host diagnostics only; this reports the same rows without failing.
zig build bench-gate -Doptimize=ReleaseFast -- --warn-only

# Evidence audit
zig build verify-evidence
```

See `docs/benchmark-baseline.md` for the historical record and
`docs/architecture.md` for the invariants a change must preserve.
