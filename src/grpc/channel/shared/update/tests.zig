const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");
const support = @import("../resolution/test_support.zig");
const allocator = std.testing.allocator;

test {
    _ = @import("policy_tests.zig");
    _ = @import("admission_tests.zig");
    _ = @import("health_tests.zig");
    _ = @import("stream_tests.zig");
    _ = @import("late_admission_tests.zig");
    _ = @import("override_tests.zig");
    _ = @import("selection_tests.zig");
}

fn unary(sender: shared.Sender, message: []const u8) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Update/Unary", .authority = "localhost", .message = message, .wait_for_ready = true });
}

test "gRPC shared update adopts method config and preserves an active RPC and connection" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var entered: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server, admitted: *std.Io.Event, finish: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var first = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer first.deinit();
            admitted.set(connection.connection.io);
            var second = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer second.deinit();
            try std.testing.expectEqualStrings("new", second.request.message.payload);
            try connection.writeUnary(second.request.stream_id, .{ .message = "new" });
            try support.wait(finish, connection.connection.io);
            try connection.writeUnary(first.request.stream_id, .{ .message = "old" });
            var third = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer third.deinit();
            try std.testing.expectEqualStrings("restored", third.request.message.payload);
            try connection.writeUnary(third.request.stream_id, .{ .message = "restored" });
            try support.closed(&connection);
        }
    };
    var peer = io.async(Peer.run, .{ &server, &entered, &release });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{
        .service_config_json = "{\"methodConfig\":[{\"name\":[{}],\"timeout\":\"5s\",\"maxRequestMessageBytes\":16}]}",
    });
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var pending = try io.concurrent(unary, .{ sender, "old" });
    defer _ = pending.cancel(io) catch {};
    try support.wait(&entered, io);
    const original_source = client.state.sources[0];
    const original_generation = client.state.retainConfig().?;
    defer original_generation.release();
    try std.testing.expectEqual(@as(u64, 2), try client.updateWithTimeout(.{ .service_config = .{ .replace = "{\"loadBalancingConfig\":[{\"least_request_experimental\":{}}],\"methodConfig\":[{\"name\":[{}],\"timeout\":\"2s\",\"maxRequestMessageBytes\":3}]}" } }, .fromSeconds(3)));
    try std.testing.expect(client.state.sources[0] == original_source);
    try std.testing.expectError(error.GrpcMessageTooLarge, unary(sender, "four"));
    var second = try unary(sender, "new");
    defer second.deinit();
    try std.testing.expectEqualStrings("new", second.message.?.payload);
    // The retained prior arena still resolves the old size policy.
    const prior = try original_generation.config.resolveUnary(.{ .path = "/demo.Update/Unary", .message = "four" });
    try std.testing.expectEqual(@as(usize, 16), prior.options.requestMessageLimit());
    try std.testing.expectEqual(@as(u64, 3), try client.update(.{ .service_config = .{ .replace = null } }));
    release.set(io);
    var first = try pending.await(io);
    defer first.deinit();
    try std.testing.expectEqualStrings("old", first.message.?.payload);
    var third = try unary(sender, "restored");
    defer third.deinit();
    try std.testing.expectEqualStrings("restored", third.message.?.payload);
    client.deinit();
    live = false;
    try peer.await(io);
}

test "gRPC shared update switches endpoints and drains the removed active owner" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var entered: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    var a_peer = support.Peer{ .server = &a, .authority = "localhost", .reply = "A", .requests = 1, .admitted = &entered, .release = &release };
    var b_peer = support.Peer{ .server = &b, .authority = "localhost", .reply = "B", .requests = 1 };
    var a_task = io.async(support.Peer.run, .{&a_peer});
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = a.address() } }, .{ .service_config_json = "{\"methodConfig\":[{\"name\":[{}],\"timeout\":\"5s\"}]}" });
    defer client.deinit();
    var old_watch = client.watchEndpointConnectivity(0).?;
    defer old_watch.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var pending = try io.concurrent(unary, .{ sender, "active" });
    defer _ = pending.cancel(io) catch {};
    try support.wait(&entered, io);
    try std.testing.expectEqual(@as(u64, 2), try client.update(.{ .target = .{ .cleartext_ip = .{ .address = b.address() } } }));
    try std.testing.expectEqual(grpc.ChannelConnectivityState.shutdown, (try old_watch.nextWithTimeout(.fromSeconds(3))).state);
    var response = try unary(sender, "new");
    defer response.deinit();
    try std.testing.expectEqualStrings("B", response.message.?.payload);
    try std.testing.expectEqual(@as(u64, 3), try client.update(.{ .target = .{ .resolved = .{ .endpoints = &.{} } } }));
    try std.testing.expectEqual(@as(usize, 0), client.configuredEndpointCount());
    try std.testing.expectEqual(@as(usize, 0), client.endpointCount());
    try std.testing.expectError(error.ConnectionUnavailable, sender.unary(.{ .path = "/demo.Update/Unary", .message = "rejected", .wait_for_ready = false }));
    release.set(io);
    var first = try pending.await(io);
    defer first.deinit();
    try std.testing.expectEqualStrings("A", first.message.?.payload);
    try a_task.await(io);
    try b_task.await(io);
}

test "gRPC shared update rolls back malformed config and exhausted task admission" {
    var threaded = std.Io.Threaded.init(allocator, .{ .concurrent_limit = .limited(1) });
    defer threaded.deinit();
    const io = threaded.io();
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer client.deinit();
    const original = client.state.sources[0];
    try std.testing.expectError(error.InvalidServiceConfig, client.update(.{ .service_config = .{ .replace = "{" } }));
    try std.testing.expectEqual(@as(u64, 1), client.configurationRevision());
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(2) } } },
    };
    try std.testing.expectError(error.ConcurrencyUnavailable, client.update(.{ .target = .{ .resolved = .{ .endpoints = &endpoints } } }));
    try std.testing.expectEqual(@as(u64, 1), client.configurationRevision());
    try std.testing.expectEqual(@as(usize, 1), client.endpointCount());
    try std.testing.expectEqual(@as(usize, 1), client.configuredEndpointCount());
    try std.testing.expect(client.state.sources[0] == original);
    try std.testing.expect(!original.retired);
    try std.testing.expect(!client.state.demand);
}

test "gRPC shared update allocation failure preserves the published snapshot" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, io: std.Io) !void {
            var client = try shared.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
            defer client.deinit();
            const original = client.state.sources[0];
            const endpoints = [_]grpc.ChannelEndpoint{
                .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } },
                .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(2) } } },
            };
            _ = client.update(.{
                .target = .{ .resolved = .{ .endpoints = &endpoints } },
                .service_config = .{ .replace = "{\"loadBalancingConfig\":[{\"round_robin\":{}}],\"methodConfig\":[{\"name\":[{}],\"timeout\":\"1s\"}]}" },
            }) catch |err| {
                try std.testing.expectEqual(@as(u64, 1), client.configurationRevision());
                try std.testing.expect(client.state.sources[0] == original);
                try std.testing.expectEqual(@as(usize, 1), client.endpointCount());
                return err;
            };
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{threaded.io()});
}
