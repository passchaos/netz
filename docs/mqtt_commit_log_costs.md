# MQTT snapshot and commit-log costs

The durable broker journal records complete v7 state images. Each synchronous
transaction serializes retained messages, Sessions, Wills, pending incoming
QoS 2 and bridge QoS 2 state, then writes and fsyncs the journal before exposing
its acknowledgement boundary. Snapshot capture and serialization hold the
state mutex; journal append remains serialized by the persistence mutex.

`bench-mqtt-commit-log` measures fixed-time snapshot capture/encoding,
append of an already encoded payload, and live-time `Broker.appendCommit`.
Run it with:

```sh
zig build bench-mqtt-commit-log -Doptimize=ReleaseFast -- --iterations=5 --samples=3 --metadata-bytes=64
```

All three cases have eight queued QoS 1 messages per offline Session and a
256-byte payload. All five snapshot sections contain data. The benchmark
restores the latest journal payload, checks every queue entry and metadata,
and verifies allocation teardown before emitting completed records.

The optimized serializer writes each section into the final envelope and
patches its length and CRC after the owning writer finishes. Property blobs
likewise write into their caller's buffer with rollback on error. This removes
the per-publication temporary property allocation and the five intermediate
section buffers. Section order, big-endian fields, checksums, v7 bytes, journal
records and filesystem durability remain the same.

An unlocked protocol commit also waits for an overlapping provisional CONNECT
to attach or roll back before capturing a coherent image. It releases both
broker mutexes during that wait. Explicit snapshot/append APIs retain their
`SnapshotBusy` contract, and encoder or filesystem errors still propagate.
A replacement connection attaches after its successful CONNACK and before
waiting for the displaced connection's writer. This lets an old durable writer
finish its admission-dependent commit without creating a takeover lock cycle.
The overlap regressions pause actual DISCONNECT reception and CONNACK writes,
observe broker retirement through a delegated socket-close callback, and reopen
the journal to verify Session and Will state. Raw MQTT packets keep the test
client's transport open while observing the peer.

Four alternating pairs of fixed old/new ReleaseFast executables produced:

| Offline Sessions | Snapshot bytes | Allocations per encode, old/new | Extra peak bytes, old/new | Paired median encoding speedup |
| --- | --- | --- | --- | --- |
| 1 | 3,271 | 23 / 5 | 12,235 / 3,965 | 1.586x |
| 32 | 92,935 | 274 / 9 | 251,514 / 112,938 | 1.107x |
| 256 | 742,819 | 2,066 / 9 | 1,965,323 / 860,646 | 1.082x |

The optimized encoder won all four pairs at each size. Every fixed snapshot
SHA-256 matched the old encoder. The small old image is also committed as a
3,271-byte golden fixture; quiescent and live re-encoding must reproduce it
byte for byte, including all five nonempty sections. Allocation-failure tests
exercise rollback and cleanup, and a pre-reserved property destination remains
usable while further allocator calls fail.

These encoding measurements do not predict durable network throughput. The
separate delegated fsync measurement varied substantially even within each
run. Full-state serialization remains O(persisted state), and snapshot bytes
still repeat publication payloads across queued destinations. Incremental
journaling or group commit would need to preserve pending state before PUBREC,
durable release/completion before PUBCOMP, and stable outgoing identifiers and
inflight state before PUBLISH. Mosquitto's built-in interval/shutdown autosave
has a different acknowledgement durability boundary.

Logs, executable hashes, measurements and paired comparisons are under
`docs/evidence/mqtt_commit_log/2026-11-07/`. Optional `--snapshot-output=PATH`
exports the deterministic one-Session snapshot through exclusive creation.
The benchmark creates and removes its own unique child directory under the
selected `--directory` parent; ordinary runs print records without retaining
their temporary journals.

Focused snapshot, journal, property, CONNACK and takeover validation passed
355/355 tests in both Debug and ReleaseSafe. The rebuilt ReleaseSafe broker
also passed the full `interop-mqtt-commit-log` SIGKILL recovery gate, including
QoS 1/2, retained deletion/authorization, Session expiry, delayed Wills and
clean-Session normal-DISCONNECT Will cancellation. The independent Python wire
fixture and its existing deadlines were unchanged.
