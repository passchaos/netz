# Targeted QUIC and WebTransport stream events

QUIC `Connection.receiveStreamId*` delivers receive-side data and RESET events.
A locally initiated unidirectional stream has no receive side, so these
blocking methods return `StreamStateError` before a packet wait. Empty output
and invalid deadlines keep their existing validation precedence.
`pollStreamId` retains its nullable query contract for unknown streams and
streams with no new reportable receive event. Valid future receive streams can
still be awaited with a shared absolute deadline.

WebTransport `readStreamId*` delivers data, RESET and sending-side STOP events.
A local unidirectional stream can therefore wait for peer STOP_SENDING. A
bidirectional stream whose receive data belongs to a whole reader can also
report STOP to a targeted caller. Sending-side event handling precedes receive
mode filtering and preserves the whole reader's bytes and mode. The same
constant-time event helper serves whichever-ready and targeted polling.

For detached protocol adapters, the H3 server request router preserves reverse
traffic on a known locally sent server bidirectional stream. Its reverse
direction carries application bytes directly, so classifying it as a new
client request would reject a valid extension stream. STREAM, RESET and STOP
remain with the adapter; ordinary H3 message role validation still rejects
server bidirectional request streams. The router uses established QUIC send
state or compacted local stream history, without a second ownership map.

[Operation admission](webtransport_operation_admission.md) defines callback,
dispatcher, output-buffer and deadline requirements before these operations.
