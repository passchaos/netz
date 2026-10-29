//! SharedChannel client for independent too_many_pings throttling evidence.
const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var channel = try netz.grpc.SharedChannel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(port) } } },
        .{
            .channel = .{ .backoff = .{
                .initial_backoff = .fromMilliseconds(1),
                .multiplier = 1,
                .jitter = 0,
                .max_backoff = .fromMilliseconds(1),
                .min_connect_timeout = .fromSeconds(1),
            } },
            .keepalive = .{
                .interval = .fromMilliseconds(100),
                .timeout = .fromSeconds(1),
                .permit_without_calls = true,
            },
        },
    );
    defer channel.deinit();
    channel.connect();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    while (true) {
        const stats = channel.keepAliveStats();
        if (stats.throttles == 1 and stats.acknowledgements == 1) {
            if (stats.probes_sent != 1 or stats.timeouts != 0 or
                channel.keepAliveInterval().?.nanoseconds !=
                    std.Io.Duration.fromMilliseconds(200).nanoseconds)
            {
                return error.InvalidKeepAliveThrottle;
            }
            break;
        }
        if (deadline.durationFromNow(io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    std.debug.print(
        "netz gRPC SharedChannel throttled keepalive from Rust HTTP/2 GOAWAY: configured_ms=100 effective_ms=200 throttles=1 acknowledged=1 client_io=zio-std-io server_io=rust-tokio\n",
        .{},
    );
}
