# gRPC Channelz validation

`grpc.channelz` implements the standard `grpc.channelz.v1.Channelz` unary
admin surface without a protobuf code generator. A registry owns top-level
channel and server entries, call counters are atomic, and response encoding is
serialized with registry mutation.

| Gate | Result | Evidence |
| --- | --- | --- |
| Focused Channelz Debug | 169/169 tests | `channelz.Debug.log` |

The focused run covers independent wire decoding of paginated top channels and
servers, single-entity lookup, ids/names/targets/connectivity state, call
started/succeeded/failed counters, last-call timestamps, default and capped page
sizes, unknown methods, unknown ids, invalid pages and channel removal. A real
loopback gRPC unary server/client test dispatches `GetTopChannels` through
`channelz.serve`, decodes the response, and verifies `NOT_FOUND` status mapping
for an unknown channel id.

`GetSubchannel` and `GetSocket` return `NOT_FOUND`, and `GetServerSockets`
returns an empty final page, because this library does not expose stable
subchannel or socket object models. Channel traces and socket security details
are not synthesized.

Reproduce with:

```sh
zig build test-lib -Dtest-filter=Channelz --summary all
```
