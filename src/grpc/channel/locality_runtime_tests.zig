//! Real socket coverage for generated locality policies and resolver updates.
const std = @import("std");
const grpc = @import("../mod.zig");
const shared = @import("shared.zig");
const Peer = @import("shared/weighted_target/test_support.zig").Peer;
const allocator = std.testing.allocator;
const config_json = @import("locality_tests.zig").json;

fn invoke(client: anytype) !grpc.UnaryResponse {
    return client.unary(.{ .path = "/demo.Locality/Unary", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
}

fn count(client: anytype, total: usize) ![3]usize {
    var result = [_]usize{ 0, 0, 0 };
    for (0..total) |_| {
        var response = try invoke(client);
        defer response.deinit();
        const payload = response.message.?.payload;
        const index: usize = if (std.mem.eql(u8, payload, "a1")) 0 else if (std.mem.eql(u8, payload, "a2")) 1 else if (std.mem.eql(u8, payload, "b")) 2 else return error.UnexpectedBackend;
        result[index] += 1;
    }
    return result;
}

fn exercise(comptime is_shared: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a1 = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a1.deinit();
    var a2 = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a2.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var stop: std.Io.Event = .unset;
    var a1_task = io.async(Peer.run, .{ &a1, &stop, "a1", null });
    defer _ = a1_task.cancel(io) catch {};
    var a2_task = io.async(Peer.run, .{ &a2, &stop, "a2", null });
    defer _ = a2_task.cancel(io) catch {};
    var b_task = io.async(Peer.run, .{ &b, &stop, "b", null });
    defer _ = b_task.cancel(io) catch {};
    const initial = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a1.address(), .hierarchical_path = &.{"a"}, .locality_weight = 1 } },
        .{ .cleartext_ip = .{ .address = a2.address(), .hierarchical_path = &.{"a"}, .locality_weight = 1 } },
        .{ .cleartext_ip = .{ .address = b.address(), .hierarchical_path = &.{"b"}, .locality_weight = 3 } },
    };
    var config = try grpc.ServiceConfig.parse(allocator, config_json);
    defer config.deinit();
    var client = if (is_shared) try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &initial } }, .{ .service_config_json = config_json }) else try grpc.Channel.initWithServiceConfig(allocator, io, .{ .resolved = .{ .endpoints = &initial } }, .{}, &config);
    var client_live = true;
    defer if (client_live) client.deinit();
    var sender = if (is_shared) client.sender() else {};
    defer if (is_shared) sender.deinit();
    if (is_shared) {
        client.connect();
        for (0..3) |index| {
            var watch = client.watchEndpointConnectivity(index).?;
            defer watch.deinit();
            while (watch.snapshot().state != .ready) _ = try watch.nextWithTimeout(.fromSeconds(3));
        }
    }
    const before = try count(if (is_shared) sender else &client, 400);
    try std.testing.expect(before[2] > 240 and before[2] < 360);
    const delta = if (before[0] > before[1]) before[0] - before[1] else before[1] - before[0];
    try std.testing.expect(delta <= 1);
    if (is_shared) {
        const source_a = client.state.sources[0];
        const source_b = client.state.sources[2];
        const worker_a = source_a.current[0];
        const worker_b = source_b.current[0];
        var changed = initial;
        changed[0].cleartext_ip.locality_weight = 3;
        changed[1].cleartext_ip.locality_weight = 3;
        changed[2].cleartext_ip.locality_weight = 1;
        _ = try client.updateWithTimeout(.{ .target = .{ .resolved = .{ .endpoints = &changed } } }, .fromSeconds(3));
        try std.testing.expect(client.state.sources[0] == source_a and client.state.sources[2] == source_b);
        try std.testing.expect(source_a.current[0] == worker_a and source_b.current[0] == worker_b);
        const after = try count(sender, 400);
        try std.testing.expect(after[0] + after[1] > 240 and after[0] + after[1] < 360);
        // Zero locality weight suspends its membership; restoration rebuilds
        // targets even though the service-config generation is kept.
        var removed = changed;
        removed[0].cleartext_ip.locality_weight = 0;
        removed[1].cleartext_ip.locality_weight = 0;
        _ = try client.updateWithTimeout(.{ .target = .{ .resolved = .{ .endpoints = &removed } } }, .fromSeconds(3));
        const only_b = try count(sender, 20);
        try std.testing.expectEqual(@as(usize, 20), only_b[2]);
        _ = try client.updateWithTimeout(.{ .target = .{ .resolved = .{ .endpoints = &changed } } }, .fromSeconds(3));
        const restored = try count(sender, 100);
        try std.testing.expect(restored[0] + restored[1] > 50);
    }
    client.deinit();
    client_live = false;
    stop.set(io);
    try a1_task.await(io);
    try a2_task.await(io);
    try b_task.await(io);
}

test "gRPC xDS locality ordinary channel distributes localities then balances endpoints" {
    try exercise(false);
}

test "gRPC xDS locality SharedChannel applies weight removal and restoration without reconnect" {
    try exercise(true);
}

test "gRPC xDS locality update lets admitted RPC finish after its locality is removed" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var entered: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    const HeldPeer = struct {
        fn run(server: *grpc.runtime.Server, admitted: *std.Io.Event, finish: *std.Io.Event, label: []const u8) !void {
            var connection = try server.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var request = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer request.deinit();
            admitted.set(connection.connection.io);
            try finish.waitTimeout(connection.connection.io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
            try connection.writeUnary(request.request.stream_id, .{ .message = label });
            var terminal = try connection.readUnaryWithTimeout(.fromSeconds(3));
            terminal.deinit();
            return error.UnexpectedRequest;
        }
        fn ended(server: *grpc.runtime.Server, admitted: *std.Io.Event, finish: *std.Io.Event, label: []const u8) !void {
            run(server, admitted, finish, label) catch |err| switch (err) {
                error.ConnectionClosed, error.ConnectionResetByPeer, error.UnexpectedEof, error.SocketUnconnected => return,
                else => return err,
            };
        }
    };
    var a_task = io.async(HeldPeer.ended, .{ &a, &entered, &release, "a1" });
    defer _ = a_task.cancel(io) catch {};
    var b_entered: std.Io.Event = .unset;
    var b_release: std.Io.Event = .unset;
    b_release.set(io);
    var b_task = io.async(HeldPeer.ended, .{ &b, &b_entered, &b_release, "b" });
    defer _ = b_task.cancel(io) catch {};
    var endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a.address(), .hierarchical_path = &.{"a"}, .locality_weight = 1 } },
        .{ .cleartext_ip = .{ .address = b.address(), .hierarchical_path = &.{"b"}, .locality_weight = 0 } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = config_json });
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var pending = try io.concurrent(struct {
        fn call(value: shared.Sender) !grpc.UnaryResponse {
            return invoke(value);
        }
    }.call, .{sender});
    defer _ = pending.cancel(io) catch {};
    try entered.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
    endpoints[0].cleartext_ip.locality_weight = 0;
    endpoints[1].cleartext_ip.locality_weight = 1;
    _ = try client.updateWithTimeout(.{ .target = .{ .resolved = .{ .endpoints = &endpoints } } }, .fromSeconds(3));
    var new_response = try invoke(sender);
    defer new_response.deinit();
    try std.testing.expectEqualStrings("b", new_response.message.?.payload);
    release.set(io);
    var old_response = try pending.await(io);
    defer old_response.deinit();
    try std.testing.expectEqualStrings("a1", old_response.message.?.payload);
    client.deinit();
    live = false;
    try a_task.await(io);
    try b_task.await(io);
}

test "gRPC xDS locality ordinary and shared initialization clean every allocation failure" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, io: std.Io) !void {
            var config = try grpc.ServiceConfig.parse(gpa, config_json);
            defer config.deinit();
            const target: grpc.ChannelTarget = .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"a"}, .locality_weight = 1 } };
            var ordinary = try grpc.Channel.initWithServiceConfig(gpa, io, target, .{}, &config);
            defer ordinary.deinit();
            var shared_channel = try shared.SharedChannel.init(gpa, io, target, .{ .service_config_json = config_json });
            defer shared_channel.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{threaded.io()});
}

test "gRPC xDS locality ordinary hostname resolves after lazy initialization" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var stop: std.Io.Event = .unset;
    var peer = io.async(Peer.run, .{ &server, &stop, "a1", null });
    defer _ = peer.cancel(io) catch {};
    var config = try grpc.ServiceConfig.parse(allocator, config_json);
    var config_live = true;
    defer if (config_live) config.deinit();
    var client = try grpc.Channel.initWithServiceConfig(allocator, io, .{ .cleartext_host = .{
        .host = "127.0.0.1",
        .port = server.address().getPort(),
        .hierarchical_path = &.{"a"},
        .locality_weight = 1,
    } }, .{}, &config);
    var live = true;
    defer if (live) client.deinit();
    config.deinit();
    config_live = false;
    try std.testing.expectEqual(@as(usize, 0), client.slots.len);
    var response = try invoke(&client);
    defer response.deinit();
    try std.testing.expectEqualStrings("a1", response.message.?.payload);
    try std.testing.expectEqual(@as(u32, 1), client.slots[0].endpoint.localityWeight());
    client.deinit();
    live = false;
    stop.set(io);
    try peer.await(io);
}
