# gRPC Channelz

`grpc.channelz` implements the server side of the standard
`grpc.channelz.v1.Channelz` admin service without a protobuf code generator.
Applications own a `Registry`, register their top-level channels and servers,
update lock-free counters from the call path, and dispatch unary requests
through the registry.

```zig
var registry = grpc.channelz.Registry.init(allocator, io);
defer registry.deinit();

const channel = try registry.addChannel("frontend", "dns:///backend:443");
channel.setState(.ready);
channel.callStarted();
channel.callSucceeded();

const server = try registry.addServer("frontend-listener");
server.callStarted();
server.callFailed();
```

## Methods

| Method | Behavior |
| --- | --- |
| `GetTopChannels` | Paginated top-level channels ordered by ascending id. |
| `GetServers` | Paginated servers ordered by ascending id. |
| `GetServer` | One server, or `NOT_FOUND`. |
| `GetChannel` | One channel, or `NOT_FOUND`. |
| `GetServerSockets` | Empty socket page for a known server, or `NOT_FOUND`. |
| `GetSubchannel` | `NOT_FOUND`; the library has no stable subchannel object model. |
| `GetSocket` | `NOT_FOUND`; the library has no stable socket object model. |

Pagination follows the standard request fields. `start_*_id` is inclusive,
`max_results = 0` selects a default page of 100 entries, the page is capped at
1000 entries, and `end` is true when no later entry exists. Negative ids or
page sizes are rejected as `INVALID_ARGUMENT`.

`Registry.handle` returns the encoded response bytes or `null` for an unrelated
path. `channelz.serve` performs the same dispatch for an already-read
`grpc.runtime.OwnedUnaryRequest`:

```zig
if (try grpc.channelz.serve(&registry, &connection, &request)) continue;
// The path is not Channelz; dispatch it normally.
```

`serve` converts `NotFound`, `Unimplemented` and `InvalidRequest` into the
corresponding gRPC statuses. Transport failures are returned to the caller.

## Client

`channelz.Client` wraps one connected `grpc.runtime.Client` and returns
arena-owned decoded pages:

```zig
var admin = grpc.channelz.Client{
    .allocator = allocator,
    .connection = &client,
};
var channels = try admin.getTopChannels(0, 0);
defer channels.deinit();
for (channels.channels) |channel| {
    // channel.id, channel.name, channel.data.calls_started, ...
}
```

`getServers`, `getServer`, `getChannel` and `getServerSockets` follow the same
pattern. `TopChannels`, `ServersPage`, `OwnedChannel` and `OwnedServer` own
their arena and must be deinitialized. Client status mapping returns
`NotFound`, `Unimplemented` or `InvalidRequest`; other non-OK statuses return
`RpcFailed`. A successful response without a message returns `InvalidResponse`.

## Ownership and concurrency

`addChannel` and `addServer` return handles that remain valid until
`removeChannel`/`removeServer` or registry teardown. Names, targets and handles
are registry-owned. Counters and channel connectivity state are atomic, so call
paths can update them concurrently with admin reads. Registry mutation and
response encoding are serialized by the registry mutex. Do not use a handle
after removal or registry `deinit`.

## Limits

The implementation reports channel/server ids, names, targets, connectivity
state, call started/succeeded/failed counters and the last call-start timestamp.
Channel traces, socket counters, security details, subchannel inventories and
server listen-socket details are not synthesized. `GetServerSockets` therefore
returns an empty page with `end = true`; `GetSubchannel` and `GetSocket` return
`NOT_FOUND`. This keeps the admin surface honest rather than inventing objects
the transport does not own.

Focused coverage is available with:

```sh
zig build test-lib -Dtest-filter=Channelz --summary all
```

The tests decode the emitted wire bytes independently and cover pagination,
single-entity lookup, counter/timestamp encoding, unknown methods, unknown ids,
invalid page sizes and channel removal.
