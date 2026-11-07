# Subscription identifiers and durable disconnect

MQTT 5 subscriptions retain an identifier for every matching filter. A client
that subscribes to `a/#`, `a/+` and `a/x` with Subscription Identifier 7 must
receive all three identifier occurrences when the broker coalesces delivery of
`a/x` into one PUBLISH. Equal values describe distinct matched subscriptions;
they remain repeated. This follows MQTT-3.3.4-4. Brokers that choose separate
per-filter copies may carry one identifier in each copy.

Netz applies the same rule to transient fanout and Session delivery planning.
QoS 1 offline queues, journal restore and DUP replay preserve the complete
identifier sequence. Acknowledgement removes the inflight delivery according
to the existing durable Session rules.

Broker-attached connections distinguish a received DISCONNECT from physical
transport shutdown. Successful persistent Session/Will cancellation commits
before the owner releases the socket shutdown. A concurrent writer cannot
interrupt that pending decision automatically, and a logically terminated
connection contributes no further Keep Alive deadline. The owner shuts down
before joining writers, then retains the socket and connection storage until
writer quiescence permits unregister and slot reuse. Standalone runtime
connections perform their normal immediate transport termination.

If encoding or sync fails after an in-memory cancellation, completion preserves
the first error and attempts a coherent current-image commit through the
existing journal coordinator before shutdown. Repeated storage failure remains
a failed termination. An old Will handle already canceled by takeover still
requires a journal barrier, without inventing another mutation generation.

Native tests intercept the actual `netShutdown` call and inspect synced journal
state there. They cover successful cancellation, one-shot/repeated sync failure
and a held writer. Independent raw-wire vectors send explicit MQTT 5 packets
and inspect identifier occurrences across live delivery and process restart.
