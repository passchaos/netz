const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");
const allocator = std.testing.allocator;

test "gRPC shared update rolls back after partial task admission" {
    var threaded = std.Io.Threaded.init(allocator, .{ .concurrent_limit = .limited(2) });
    defer threaded.deinit();
    const io = threaded.io();
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer client.deinit();
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(2) } } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(3) } } },
    };
    try std.testing.expectError(error.ConcurrencyUnavailable, client.update(.{ .target = .{ .resolved = .{ .endpoints = &endpoints } } }));
    try std.testing.expectEqual(@as(u64, 1), client.configurationRevision());
    try std.testing.expectEqual(@as(usize, 1), client.configuredEndpointCount());
    try std.testing.expectEqual(@as(usize, 1), client.endpointCount());
}

test "gRPC shared update validates deadline and closed retained state" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = client.sender();
    defer sender.deinit();
    try std.testing.expectError(error.Timeout, client.updateWithTimeout(.{}, .zero));
    try std.testing.expectError(error.Timeout, client.updateWithDeadline(.{}, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) })));
    client.state.mutex.lockUncancelable(io);
    try std.testing.expectError(error.Timeout, client.updateWithTimeout(.{}, .fromMilliseconds(1)));
    client.state.mutex.unlock(io);
    try std.testing.expectEqual(@as(u64, 1), client.configurationRevision());
    client.deinit();
    const retained = shared.SharedChannel{ .state = sender.state };
    try std.testing.expectError(error.SharedChannelClosed, retained.update(.{}));
}

test "gRPC shared update retains concurrent method policy readers" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{ .service_config_json = "{\"methodConfig\":[{\"name\":[{}],\"maxRequestMessageBytes\":3}]}" });
    defer client.deinit();
    var stop: std.atomic.Value(bool) = .init(false);
    var entered: std.Io.Event = .unset;
    const Reader = struct {
        fn run(state: *@import("../state.zig").State, done: *std.atomic.Value(bool), started: *std.Io.Event) !void {
            while (!done.load(.acquire)) {
                const generation = state.retainConfig().?;
                defer generation.release();
                started.set(state.io);
                const resolved = try generation.config.resolveUnary(.{ .path = "/demo.Update/Unary", .message = "one" });
                const size = resolved.options.requestMessageLimit();
                try std.testing.expect(size == 3 or size == 5);
            }
        }
    };
    var reader = try io.concurrent(Reader.run, .{ client.state, &stop, &entered });
    defer {
        stop.store(true, .release);
        _ = reader.cancel(io) catch {};
    }
    try entered.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
    for (0..30) |index| {
        _ = try client.update(.{ .service_config = .{ .replace = if (index % 2 == 0) "{\"methodConfig\":[{\"name\":[{}],\"maxRequestMessageBytes\":5}]}" else "{\"methodConfig\":[{\"name\":[{}],\"maxRequestMessageBytes\":3}]}" } });
    }
    stop.store(true, .release);
    try reader.await(io);
    try std.testing.expectEqual(@as(u64, 31), client.configurationRevision());
}
