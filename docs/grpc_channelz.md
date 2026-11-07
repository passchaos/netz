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

const listen = try registry.addSocket(
    "frontend-listen",
    .{ .tcpip = listener.address() },
    null,
);
try server.addListenSocket(listen);
```

## Methods

| Method | Behavior |
| --- | --- |
| `GetTopChannels` | Paginated top-level channels ordered by ascending id. |
| `GetServers` | Paginated servers ordered by ascending id. |
| `GetServer` | One server, or `NOT_FOUND`. |
| `GetChannel` | One channel, or `NOT_FOUND`. |
| `GetServerSockets` | Paginated listen-socket refs for a known server, or `NOT_FOUND`. |
| `GetSocket` | One socket, or `NOT_FOUND`. |
| `GetSubchannel` | `NOT_FOUND`; the library has no stable subchannel object model. |

Pagination follows the standard request fields. `start_*_id` is inclusive,
`max_results = 0` selects a default page of 100 entries, the page is capped at
1000 entries, and `end` is true when no later entry exists. Negative ids or
page sizes are rejected as `INVALID_ARGUMENT`.

Sockets accept TCP/IP, Unix-domain and opaque `other` addresses. TCP/IP
addresses keep their binary form. Stream and message counters are atomic, and
`addListenSocket` keeps the server's socket ids sorted for pagination.

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

`getServers`, `getServer`, `getChannel`, `getServerSockets` and `getSocket`
follow the same pattern. `TopChannels`, `ServersPage`, `OwnedChannel`,
`OwnedServer`, `SocketPage` and `OwnedSocket` own their arena and must be
deinitialized. Client status mapping returns `NotFound`, `Unimplemented` or
`InvalidRequest`; other non-OK statuses return `RpcFailed`. A successful
response without a message returns `InvalidResponse`.

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
Sockets report ids, names, TCP/IP, Unix or opaque addresses, and stream/message/
keep-alive counters. Channel traces, socket security details, socket options,
flow-control windows, subchannel inventories and server connection sockets are
not synthesized. `GetSubchannel` returns `NOT_FOUND`. Server connection sockets
can be registered explicitly when the application owns them; the listener
socket alone is enough for the standard listen-socket page.

Focused coverage is available with:

```sh
zig build test-lib -Dtest-filter=Channelz --summary all
```

The tests decode the emitted wire bytes independently and cover pagination,
single-entity lookup, counter/timestamp encoding, unknown methods, unknown ids,
invalid page sizes and channel removal.
