//! Actual RPC permits share identity and survive changed limits until transport completion.
const std = @import("std");
const grpc = @import("../mod.zig");
const shared = @import("shared.zig");
const circuit = @import("circuit_breaker.zig");
const allocator = std.testing.allocator;
fn options(maximum: u32) circuit.Options {
    return .{ .cluster = "runtime-cluster", .eds_service_name = "runtime-eds", .max_concurrent_requests = maximum };
}
fn call(sender: shared.Sender, payload: []const u8) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Circuit/Unary", .message = payload, .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
}
fn wait(io: std.Io, event: *std.Io.Event) !void {
    try event.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(5) } });
}
fn dropped(response: *grpc.UnaryResponse) !void {
    try std.testing.expect(response.was_dropped and response.transport == null);
    try std.testing.expectEqual(grpc.Status.unavailable, response.status);
    try std.testing.expectEqualStrings("circuit breaker drop", response.status_message);
}
fn closed(connection: anytype) !void {
    var request = connection.readUnaryWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
        error.ConnectionClosed, error.ConnectionResetByPeer, error.UnexpectedEof, error.SocketUnconnected => return,
        else => return err,
    };
    request.deinit();
    return error.UnexpectedRequest;
}

test "gRPC circuit breaker ordinary and shared channels retain in-flight budget through limit changes" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var first_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer first_server.deinit();
    var other_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer other_server.deinit();
    var first_seen: std.Io.Event = .unset;
    var second_seen: std.Io.Event = .unset;
    var release_first: std.Io.Event = .unset;
    var release_second: std.Io.Event = .unset;
    const Peer = struct {
        fn serveFirst(listener: *grpc.runtime.Server, a: *std.Io.Event, b: *std.Io.Event, finish_a: *std.Io.Event, finish_b: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var first = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer first.deinit();
            a.set(connection.connection.io);
            var second = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer second.deinit();
            b.set(connection.connection.io);
            try wait(connection.connection.io, finish_b);
            try connection.writeUnary(second.request.stream_id, .{ .message = "second" });
            try wait(connection.connection.io, finish_a);
            try connection.writeUnary(first.request.stream_id, .{ .message = "first" });
            try closed(&connection);
        }
        fn other(listener: *grpc.runtime.Server) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer request.deinit();
            try connection.writeUnary(request.request.stream_id, .{ .message = "other" });
            try closed(&connection);
        }
    };
    var peer = io.async(Peer.serveFirst, .{ &first_server, &first_seen, &second_seen, &release_first, &release_second });
    defer _ = peer.cancel(io) catch {};
    var other_peer = io.async(Peer.other, .{&other_server});
    defer _ = other_peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = first_server.address() } }, .{ .channel = .{ .circuit_breaker = options(1) } });
    var live = true;
    defer if (live) client.deinit();
    var ordinary = try grpc.Channel.init(allocator, io, .{ .cleartext_ip = .{ .address = other_server.address() } }, .{ .circuit_breaker = options(1) });
    var ordinary_live = true;
    defer if (ordinary_live) ordinary.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var first = try io.concurrent(call, .{ sender, "first" });
    defer _ = first.cancel(io) catch {};
    try wait(io, &first_seen);
    try std.testing.expectEqual(@as(u32, 1), ordinary.circuitStats().active);
    var refused = try ordinary.unaryWithRetry(.{ .path = "/demo.Circuit/Unary", .message = "blocked", .wait_for_ready = true }, .{ .max_attempts = 5, .initial_backoff = .fromMilliseconds(1), .max_backoff = .fromMilliseconds(1), .backoff_multiplier = 1, .retryable_status_codes = &.{.unavailable} });
    defer refused.deinit();
    try dropped(&refused);
    _ = try client.updateWithTimeout(.{ .circuit_breaker = .{ .replace = options(0) } }, .fromSeconds(3));
    try std.testing.expectEqual(@as(u32, 1), client.circuitStats().active);
    var zero = try call(sender, "blocked");
    defer zero.deinit();
    try dropped(&zero);
    _ = try client.updateWithTimeout(.{ .circuit_breaker = .{ .replace = options(2) } }, .fromSeconds(3));
    var second = try io.concurrent(call, .{ sender, "second" });
    defer _ = second.cancel(io) catch {};
    try wait(io, &second_seen);
    try std.testing.expectEqual(@as(u32, 2), client.circuitStats().active);
    _ = try client.updateWithTimeout(.{ .circuit_breaker = .{ .replace = options(1) } }, .fromSeconds(3));
    var lowered = try call(sender, "blocked");
    defer lowered.deinit();
    try dropped(&lowered);
    release_second.set(io);
    var finished_second = try second.await(io);
    defer finished_second.deinit();
    try std.testing.expectEqualStrings("second", finished_second.message.?.payload);
    try std.testing.expectEqual(@as(u32, 1), client.circuitStats().active);
    release_first.set(io);
    var finished_first = try first.await(io);
    defer finished_first.deinit();
    try std.testing.expectEqualStrings("first", finished_first.message.?.payload);
    try std.testing.expectEqual(@as(u32, 0), client.circuitStats().active);
    var resumed = try ordinary.unary(.{ .path = "/demo.Circuit/Unary", .message = "resumed", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
    defer resumed.deinit();
    try std.testing.expectEqualStrings("other", resumed.message.?.payload);
    client.deinit();
    live = false;
    ordinary.deinit();
    ordinary_live = false;
    try peer.await(io);
    try other_peer.await(io);
}

test "gRPC circuit breaker shared streaming cancellation releases the permit for another channel" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var entered: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server, seen: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer request.deinit();
            seen.set(connection.connection.io);
            var reset = try connection.connection.readResetStreamWithTimeout(.fromSeconds(5));
            defer reset.deinit(allocator);
            try std.testing.expectEqual(@import("../../http2/mod.zig").ErrorCode.cancel, reset.reset.error_code);
            try closed(&connection);
        }
    };
    var peer = io.async(Peer.run, .{ &server, &entered });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{ .channel = .{ .circuit_breaker = options(1) } });
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var observer = try circuit.Policy.init(options(1));
    defer observer.deinit();
    var stream = try sender.startDuplex(.{ .path = "/demo.Circuit/Stream", .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
    defer stream.deinit();
    var writer = stream.writer();
    defer writer.deinit();
    try writer.writeFinalMessage("request");
    try wait(io, &entered);
    try std.testing.expectEqual(@as(u32, 1), observer.stats().active);
    try std.testing.expectError(error.CallDropped, sender.startDuplex(.{ .path = "/demo.Circuit/Stream" }));
    try stream.cancelWithTimeout(.fromSeconds(3));
    try std.testing.expectEqual(@as(u32, 0), observer.stats().active);
    client.deinit();
    live = false;
    try peer.await(io);
}

test "gRPC circuit breaker channel construction and invalid replacement roll back" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, active_io: std.Io) !void {
            const config = circuit.Options{ .cluster = "channel-allocation", .eds_service_name = "eds", .max_concurrent_requests = 1 };
            var ordinary = try grpc.Channel.init(gpa, active_io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{ .circuit_breaker = config });
            defer ordinary.deinit();
            var shared_client = try shared.SharedChannel.init(gpa, active_io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{ .channel = .{ .circuit_breaker = config } });
            defer shared_client.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{io});
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{ .channel = .{ .circuit_breaker = options(1) } });
    defer client.deinit();
    const revision = client.configurationRevision();
    try std.testing.expectError(error.InvalidCircuitBreaker, client.updateWithTimeout(.{ .circuit_breaker = .{ .replace = .{ .cluster = "" } } }, .fromSeconds(3)));
    try std.testing.expectEqual(revision, client.configurationRevision());
    try std.testing.expectEqual(@as(u32, 0), client.circuitStats().active);
}
