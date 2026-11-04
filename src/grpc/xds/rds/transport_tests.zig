const std = @import("std");
const grpc = @import("../../mod.zig");
const rds = @import("../rds.zig");
const fixture = @import("testing.zig");
const gpa = std.testing.allocator;
const Peer = @import("../../channel/shared/weighted_target/test_support.zig").Peer;
const config = "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"cluster:a\":{\"childPolicy\":[{\"round_robin\":{}}]},\"cluster:b\":{\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
test "gRPC RDS automatic shared unary and streaming routing retains snapshot ownership across updates" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var stop: std.Io.Event = .unset;
    var a_peer = io.async(Peer.run, .{ &a, &stop, "a", null });
    defer _ = a_peer.cancel(io) catch {};
    var b_peer = io.async(Peer.run, .{ &b, &stop, "b", null });
    defer _ = b_peer.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{ .{ .cleartext_ip = .{ .address = a.address(), .hierarchical_path = &.{"cluster:a"} } }, .{ .cleartext_ip = .{ .address = b.address(), .hierarchical_path = &.{"cluster:b"} } } };
    var client = try grpc.SharedChannel.init(gpa, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = config });
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    const first = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(first);
    const snapshot = try rds.Snapshot.create(gpa, first, .{}, .{ .authority = "backend.test" });
    _ = try snapshot.publishWithDeadline(client, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    snapshot.release();
    var response = try sender.unary(.{ .path = "/demo.Service/Get", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
    defer response.deinit();
    try std.testing.expectEqualStrings("a", response.message.?.payload);
    const storage = client.state.config.load(.acquire).?.storage;
    const second = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "b" }}, null);
    defer gpa.free(second);
    const next = try rds.Snapshot.create(gpa, second, .{}, .{ .authority = "backend.test" });
    _ = try next.publishWithDeadline(client, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    next.release();
    try std.testing.expect(client.state.config.load(.acquire).?.storage == storage);
    var duplex = try sender.startDuplex(.{ .path = "/demo.Service/Stream", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
    defer duplex.deinit();
    var writer = duplex.writer();
    defer writer.deinit();
    var reader = duplex.reader();
    defer reader.deinit();
    try writer.writeFinalMessage("request");
    try @import("../../channel/shared/stream/testing.zig").readReply(reader, "b");
    _ = try client.updateWithTimeout(.{ .call_selector = .{ .replace = null } }, .fromSeconds(3));
    try std.testing.expectError(error.UnknownCluster, sender.unary(.{ .path = "/demo.Service/Get", .message = "request" }));
    client.deinit();
    live = false;
    stop.set(io);
    try a_peer.await(io);
    try b_peer.await(io);
}
test "gRPC RDS rewrites path and authority on the wire" {
    const RewritePeer = struct {
        fn run(listener: *grpc.runtime.Server, stop: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            while (!stop.isSet()) {
                var request = connection.acceptDuplexWithTimeout(.fromMilliseconds(100)) catch |err| switch (err) {
                    error.Timeout => continue,
                    error.ConnectionClosed,
                    error.ConnectionResetByPeer,
                    error.SocketUnconnected,
                    error.UnexpectedEof,
                    => return,
                    else => return err,
                };
                defer request.deinit();
                const Consumer = struct {
                    seen: *bool,
                    fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                        if (self.seen.* or
                            !std.mem.eql(u8, "request", message.payload))
                        {
                            return error.UnexpectedPayload;
                        }
                        self.seen.* = true;
                    }
                };
                var seen = false;
                var consumer = Consumer{ .seen = &seen };
                while (true) {
                    var event = try request.readRequestEventWithTimeout(
                        .fromSeconds(3),
                        &consumer,
                        Consumer.consume,
                    );
                    defer event.deinit();
                    switch (event) {
                        .messages => {},
                        .finished => break,
                        .reset => return error.UnexpectedReset,
                    }
                }
                if (!seen) return error.UnexpectedPayload;
                var reply: [512]u8 = undefined;
                const text = try std.fmt.bufPrint(
                    &reply,
                    "{s}\n{s}",
                    .{ request.path, request.transport.authority orelse "" },
                );
                try request.startResponse(.{});
                if (try request.writeMessage(text) != .complete) {
                    return error.UnexpectedFlowControl;
                }
                try request.finishOk();
            }
        }
    };
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var stop: std.Io.Event = .unset;
    var peer = io.async(RewritePeer.run, .{ &server, &stop });
    defer _ = peer.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{.{ .cleartext_ip = .{
        .address = server.address(),
        .authority = "endpoint.example",
        .hierarchical_path = &.{"cluster:a"},
    } }};
    var client = try grpc.SharedChannel.init(
        gpa,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{ .service_config_json = config },
    );
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var action = fixture.Builder{ .allocator = gpa };
    defer action.deinit();
    try action.bytes(5, "/api");
    try action.bytes(6, "rewritten.example");
    const bytes = try fixture.encode(
        gpa,
        "routes",
        &.{"backend.test"},
        &.{.{ .prefix = "/demo", .action_extra = action.data.items }},
        null,
    );
    defer gpa.free(bytes);
    const snapshot = try rds.Snapshot.create(gpa, bytes, .{}, .{ .authority = "backend.test" });
    _ = try snapshot.publishWithDeadline(
        client,
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }),
    );
    snapshot.release();
    var response = try sender.unary(.{
        .path = "/demo.Service/Get",
        .message = "request",
        .wait_for_ready = true,
        .timeout = .{ .value = 3, .unit = .second },
    });
    defer response.deinit();
    try std.testing.expectEqualStrings(
        "/api.Service/Get\nrewritten.example",
        response.message.?.payload,
    );

    var auto_action = fixture.Builder{ .allocator = gpa };
    defer auto_action.deinit();
    try auto_action.wrapper(7, 1);
    const auto_bytes = try fixture.encode(
        gpa,
        "routes",
        &.{"backend.test"},
        &.{.{ .prefix = "/", .action_extra = auto_action.data.items }},
        null,
    );
    defer gpa.free(auto_bytes);
    const auto_snapshot = try rds.Snapshot.create(gpa, auto_bytes, .{}, .{ .authority = "backend.test" });
    _ = try auto_snapshot.publishWithDeadline(
        client,
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }),
    );
    auto_snapshot.release();
    var auto_response = try sender.unary(.{
        .path = "/demo.Service/Auto",
        .authority = "original.example",
        .message = "request",
        .wait_for_ready = true,
        .timeout = .{ .value = 3, .unit = .second },
    });
    defer auto_response.deinit();
    try std.testing.expectEqualStrings(
        "/demo.Service/Auto\nendpoint.example",
        auto_response.message.?.payload,
    );

    client.deinit();
    live = false;
    stop.set(io);
    try peer.await(io);
}
