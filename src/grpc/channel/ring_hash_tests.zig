const std = @import("std");
const grpc = @import("../mod.zig");
const channel = @import("../channel.zig");
const shared = @import("shared.zig");

const allocator = std.testing.allocator;

test "gRPC ordinary ring hash requires a key and walks a failed endpoint" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer server.deinit();
    var peer = io.async(Peer.run, .{ &server, "b", 2 });
    defer _ = peer.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{
            .address = .{ .ip4 = .loopback(1) },
            .ring_hash_key = "a",
        } },
        .{ .cleartext_ip = .{
            .address = server.address(),
            .ring_hash_key = "b",
        } },
    };
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{
        \\ "minRingSize":8,"maxRingSize":8}}]}
    );
    errdefer config.deinit();
    var client = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{ .connection_attempt_delay = null },
        &config,
    );
    config.deinit();
    defer client.deinit();
    try std.testing.expectEqual(
        grpc.ChannelSelectionPolicy.ring_hash,
        client.selectionPolicy(),
    );
    try std.testing.expectError(
        error.MissingRequestHash,
        client.unary(request(null, "missing")),
    );
    // a is unavailable, so grpc-core's clockwise failure walk reaches b.
    var failed_primary = try client.unary(request(
        grpc.ringHash("a_0"),
        "first",
    ));
    defer failed_primary.deinit();
    try expectBackend(&failed_primary, "b");
    var exact = try client.unary(request(
        grpc.ringHash("b_0"),
        "second",
    ));
    defer exact.deinit();
    try expectBackend(&exact, "b");
    try peer.await(io);
}

test "gRPC SharedChannel ring hash uses configured metadata and deduplicates endpoints" {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer a_server.deinit();
    var b_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer b_server.deinit();
    var a_peer = io.async(Peer.run, .{ &a_server, "a", 3 });
    defer _ = a_peer.cancel(io) catch {};
    var b_peer = io.async(Peer.run, .{ &b_server, "b", 1 });
    defer _ = b_peer.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{
            .address = a_server.address(),
            .ring_hash_key = "a",
            .ring_hash_weight = 1,
        } },
        .{ .cleartext_ip = .{
            .address = a_server.address(),
            .ring_hash_key = "a",
            .ring_hash_weight = 2,
        } },
        .{ .cleartext_ip = .{
            .address = b_server.address(),
            .ring_hash_key = "b",
        } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{ .service_config_json =
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{
        \\ "minRingSize":16,"maxRingSize":16,
        \\ "requestHashHeader":"x-shard"}}]}
        },
    );
    defer client.deinit();
    try std.testing.expectEqual(
        grpc.ChannelSelectionPolicy.ring_hash,
        client.selectionPolicy(),
    );
    try std.testing.expectEqual(@as(usize, 2), client.endpointCount());
    try client.connectWithTimeout(.fromSeconds(3));
    var sender = client.sender();
    defer sender.deinit();
    var a_first = try sender.unary(headerRequest("a_0", grpc.ringHash("b_0")));
    defer a_first.deinit();
    try expectBackend(&a_first, "a");
    var b = try sender.unary(headerRequest("b_0", grpc.ringHash("a_0")));
    defer b.deinit();
    try expectBackend(&b, "b");
    var a_second = try sender.unary(headerRequest("a_1", null));
    defer a_second.deinit();
    try expectBackend(&a_second, "a");
    var stream = try sender.startDuplex(.{
        .path = "/demo.RingHash/Duplex",
        .authority = "localhost",
        .request_hash = grpc.ringHash("b_0"),
        .metadata = &.{.{ .name = "x-shard", .value = "a_0" }},
        .wait_for_ready = true,
        .timeout = grpc.Timeout.init(5, .second) catch unreachable,
    });
    defer stream.deinit();
    var writer = stream.writer();
    defer writer.deinit();
    var reader = stream.reader();
    defer reader.deinit();
    try writer.writeFinalMessage("stream");
    var messages: usize = 0;
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(5));
        defer event.deinit(allocator);
        switch (event) {
            .message => |message| {
                try std.testing.expectEqualStrings("a", message.payload);
                messages += 1;
            },
            .terminal => |response| {
                try std.testing.expectEqual(grpc.Status.ok, response.status);
                try std.testing.expectEqual(@as(usize, 1), messages);
                break;
            },
            else => {},
        }
    }
    try a_peer.await(io);
    try b_peer.await(io);
}

fn request(hash: ?u64, message: []const u8) grpc.UnaryCallOptions {
    return .{
        .path = "/demo.RingHash/Unary",
        .authority = "localhost",
        .message = message,
        .request_hash = hash,
        .wait_for_ready = true,
        .timeout = grpc.Timeout.init(5, .second) catch unreachable,
    };
}

fn headerRequest(
    key: []const u8,
    ignored_explicit_hash: ?u64,
) grpc.UnaryCallOptions {
    return .{
        .path = "/demo.RingHash/Unary",
        .authority = "localhost",
        .message = key,
        .request_hash = ignored_explicit_hash,
        .metadata = &.{.{ .name = "x-shard", .value = key }},
        .wait_for_ready = true,
        .timeout = grpc.Timeout.init(5, .second) catch unreachable,
    };
}

fn expectBackend(
    response: *const grpc.UnaryResponse,
    expected: []const u8,
) !void {
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings(expected, response.message.?.payload);
}

const Peer = struct {
    fn run(
        listener: *grpc.runtime.Server,
        label: []const u8,
        count: usize,
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        for (0..count) |_| {
            var accepted = try connection.readUnaryWithTimeout(
                .fromSeconds(5),
            );
            defer accepted.deinit();
            try connection.writeUnary(accepted.request.stream_id, .{
                .message = label,
            });
        }
    }
};
