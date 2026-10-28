# MQTT shared Publication metadata ownership

An owned MQTT PUBLISH can transfer its allocation into a shared broker
Publication. That transfer compacts Topic Name and payload in place. The old
parser's property slices can then point at overwritten packet bytes. A real
QoS 1 offline fanout/restart regression observed Content Type change from
`application/octet-stream` to `loadication/octet-stream` in both the baseline
and the initial optimization candidate.

The broker now captures the complete property descriptor view before adoption
and binds forwarding values to the resulting Publication. Subsequent Session
routes and delivery ACLs use that stable view, including its new Topic/payload
locations. Connection-scoped Topic Alias and Subscription Identifier scalars
stay in the source context for ACL consistency; ordinary forwarding still
filters them before queueing. Eight descriptors fit in stack storage, with an
exact overflow allocation reserved before packet ownership changes. Allocation
failure therefore cannot leave a partly adopted source view.

Session fanout also reuses immutable string and binary values already retained
by Publication. Each Session keeps its own property descriptor array, QoS,
Retain flag, Subscription Identifiers, expiry accounting, Packet Identifier
state and logical byte budget. Pointer containment proves backing ownership;
equal bytes in an unrelated caller buffer still take the deep-copy path.
Ordered broker forwarding walks Publication descriptors with a monotonic
cursor. Reordered caller metadata safely falls back to independent copying.
Numeric fields remain local descriptors, so different Session expiry intervals
and subscription identifiers cannot affect another destination.

The existing shared-message reference keeps its property values alive through
queueing, outgoing acknowledgement and Session destruction. No new owner
pointer is stored in each queued message. A reserved allocation-length tag
distinguishes borrowed property values from independently allocated values;
destruction frees the descriptor array and releases Publication once. Logical
Session memory limits still charge the full property bytes per destination.
Snapshot bytes are identical to independent ownership, and restored snapshots
remain independently owned across broker generations.

`bench-mqtt-shared-properties` holds 256 messages for 64 Sessions and validates
16,384 exact deliveries after measuring enqueueing. It compares metadata and
empty-property controls, each with independent or shared message backing. The
metadata has Content Type, Response Topic, 1,024-byte binary Correlation Data
and a 512-byte User Property value. A fixed baseline/candidate binary capture
uses one CPU, four alternating AB/BA pairs and seven internal samples for each
shape per arm. Every arm checks content, logical byte accounting and zero
remaining allocator bytes after teardown.

| Metadata shared fanout | Baseline | Candidate | Reduction |
| --- | ---: | ---: | ---: |
| Backing allocations | 100,608 | 18,688 | 81.4% |
| Incremental live bytes | 32,520,448 | 6,650,112 | 79.6% |
| Logical Session bytes | 33,440,438 | 33,440,438 | 0% |

The paired median enqueue-time ratio is 0.2975 (70.2% lower enqueue time), recorded with all raw samples in
[the evidence file](evidence/mqtt_shared_properties/2026-10-28.json). All four
metadata/shared pairs improved; empty-property controls retain identical
allocation counts and bytes. This is a Session store enqueue/memory result,
not an end-to-end broker throughput or process RSS comparison. The independent
metadata control also has no allocation or byte change.

Run the benchmark and its fixed-binary comparison with:

```sh
zig build bench-mqtt-shared-properties -Doptimize=ReleaseFast
python3 tools/interop/mqtt_shared_properties_ab.py BASELINE CANDIDATE --output NEW_DIRECTORY
```

`interop-mqtt-shared-properties` runs QoS 1 and 2 through two persistent
subscribers and three configured broker generations. The source packet carries
Content Type, Response Topic, binary Correlation Data, two ordered User
Properties and a Topic Alias; each destination has its own Subscription
Identifier, 17 or 29. Exact packet equality checks every property after the
publisher exits and the broker restarts. The first consumer completes before
the second reconnects, so the latter cannot rely on the former's lifetime.
The final generation checks Session removal and absence of duplicate delivery.
This gate also runs in the default configured-broker matrix.

```sh
zig build interop-mqtt-shared-properties -Doptimize=ReleaseFast
```

Adjacent Session and broker tests cover source teardown, independent
descriptors, unrelated and reordered caller values, 128 ordered User
Properties, allocation/quota failure, unchanged snapshot encoding, and
recovery with downtime expiry. The existing finite-listener regression now
waits for broker connection retirement before testing replacement admission;
local client DISCONNECT/EOF alone does not establish that server boundary.
