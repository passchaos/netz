# gRPC Channelz validation

`grpc.channelz` implements the standard `grpc.channelz.v1.Channelz` unary
admin surface without a protobuf code generator. A registry owns top-level
channel and server entries, call counters are atomic, and response encoding is
serialized with registry mutation.

| Gate | Result | Evidence |
| --- | --- | --- |
| Focused Channelz Debug | 175/175 tests | `channelz.Debug.log` |
| Official grpc-js Channelz interop | all methods + NOT_FOUND | `interop.Debug.json` |

The focused run covers independent wire decoding of paginated top channels and
servers, single-entity lookup, ids/names/targets/connectivity state, call
started/succeeded/failed counters, last-call timestamps, default and capped page
sizes, unknown methods, unknown ids, invalid pages and channel removal. A real
loopback gRPC unary server/client test dispatches `GetTopChannels` through
`channelz.serve`, decodes the response, and verifies `NOT_FOUND` status mapping
for an unknown channel id. The same fixture exercises `channelz.Client` for
top-channel and server pages, single server/channel lookup, server sockets,
socket lookup and client-side `NOT_FOUND` mapping. TCP/IP, Unix-domain and
opaque socket addresses are encoded and decoded, with stream/message counters
and sorted listen-socket pagination. Bounded channel/subchannel/server traces
cover severity, timestamps, creation time, total-event counting and oldest-event
eviction after the 16-entry ring fills. Subchannel lookup covers independent
ids/names/targets/state/counters/traces and channel-side subchannel refs. The
server observer regression verifies automatic started/succeeded/failed counters
for unary calls and a duplex terminal response; the client observer regression
does the same for `runtime.Client.unary` and client duplex terminal status.

Subchannels are application-registered; the library does not discover internal
transport subchannels automatically. Socket security details, socket options,
flow-control windows and server connection sockets are not synthesized.
Applications may register connection sockets explicitly when they own them.

The official interop gate loads `@grpc/grpc-js/proto/channelz.proto` with
`@grpc/grpc-js` 1.14.7 and calls every supported method against the native
server. It verifies channel/subchannel/server/socket fields, traces, counters,
listen-socket refs, socket addresses and `NOT_FOUND` statuses. This gate caught
the earlier omission of `Server.listen_socket` refs; the native encoder and
client decoder now cover them.

Reproduce with:

```sh
zig build test-lib -Dtest-filter=Channelz --summary all
zig build interop-grpc-channelz --summary all
```
