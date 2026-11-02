//! Ordinary streaming completion and shared shutdown settle active circuit permits.
const std = @import("std");
const grpc = @import("../mod.zig");
const circuit = @import("circuit_breaker.zig");
const allocator = std.testing.allocator;
fn wait(io: std.Io, event: *std.Io.Event) !void {
    try event.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(5) } });
}

test "gRPC circuit breaker ordinary duplex retains permit through messages until terminal" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn consume(_: *bool, _: grpc.StreamingMessage) !void {}
        fn run(listener: *grpc.runtime.Server, finish: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var request = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
            defer request.deinit();
            var seen = false;
            while (true) {
                var event = try request.readRequestEventWithTimeout(.fromSeconds(5), &seen, consume);
                defer event.deinit();
                if (event == .finished) break;
                if (event == .reset) return error.UnexpectedReset;
            }
            try request.startResponse(.{});
            try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try request.writeMessage("message"));
            try wait(connection.connection.io, finish);
            try request.finishOk();
        }
    };
    var peer = io.async(Peer.run, .{ &server, &release });
    defer _ = peer.cancel(io) catch {};
    const options: circuit.Options = .{ .cluster = "ordinary-duplex", .max_concurrent_requests = 1 };
    var client = try grpc.Channel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{ .circuit_breaker = options });
    defer client.deinit();
    var observer = try circuit.Policy.init(options);
    defer observer.deinit();
    var stream = try client.startDuplex(.{ .path = "/demo.Circuit/Duplex", .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
    defer stream.deinit();
    try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream.writeFinalMessage("request"));
    const Consumer = struct {
        count: usize = 0,
        fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("message", message.payload);
            self.count += 1;
        }
    };
    var consumer: Consumer = .{};
    while (consumer.count == 0) {
        var event = try stream.readResponseEventWithTimeout(.fromSeconds(5), &consumer, Consumer.consume);
        defer event.deinit(allocator);
        if (event == .terminal) return error.EarlyTerminal;
    }
    try std.testing.expectEqual(@as(u32, 1), observer.stats().active);
    try std.testing.expect(observer.acquire() == null);
    release.set(io);
    while (true) {
        var event = try stream.readResponseEventWithTimeout(.fromSeconds(5), &consumer, Consumer.consume);
        defer event.deinit(allocator);
        if (event == .terminal) {
            try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
            break;
        }
    }
    try std.testing.expectEqual(@as(u32, 0), observer.stats().active);
    try peer.await(io);
}

test "gRPC circuit breaker shared shutdown and failed peer release active permits" {
    for ([_]bool{ false, true }) |shutdown| {
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
        defer server.deinit();
        var entered: std.Io.Event = .unset;
        var release: std.Io.Event = .unset;
        const Peer = struct {
            fn run(listener: *grpc.runtime.Server, seen: *std.Io.Event, finish: *std.Io.Event) !void {
                var connection = try listener.acceptWithTimeout(.fromSeconds(5));
                defer connection.deinit();
                var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
                defer request.deinit();
                seen.set(connection.connection.io);
                try wait(connection.connection.io, finish);
            }
        };
        var peer = io.async(Peer.run, .{ &server, &entered, &release });
        defer _ = peer.cancel(io) catch {};
        const options: circuit.Options = .{ .cluster = if (shutdown) "shutdown-permit" else "failed-permit", .max_concurrent_requests = 1 };
        var client = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{ .channel = .{ .circuit_breaker = options } });
        var live = true;
        defer if (live) client.deinit();
        var sender = client.sender();
        defer sender.deinit();
        var observer = try circuit.Policy.init(options);
        defer observer.deinit();
        const Call = struct {
            fn run(value: grpc.SharedChannelSender) !grpc.UnaryResponse {
                return value.unary(.{ .path = "/demo.Circuit/Unary", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
            }
        };
        var active = try io.concurrent(Call.run, .{sender});
        defer _ = active.cancel(io) catch {};
        try wait(io, &entered);
        try std.testing.expectEqual(@as(u32, 1), observer.stats().active);
        if (shutdown) {
            client.deinit();
            live = false;
            release.set(io);
        } else release.set(io);
        if (active.await(io)) |value| {
            var response = value;
            defer response.deinit();
            try std.testing.expect(response.status != .ok);
        } else |err| {
            if (shutdown) try std.testing.expectEqual(error.SharedChannelClosed, err) else try std.testing.expect(err != error.CallDropped);
        }
        try std.testing.expectEqual(@as(u32, 0), observer.stats().active);
        try peer.await(io);
    }
}

test "gRPC circuit breaker EDS publication installs requested cluster limit before backend admission" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const eds = grpc.xds.eds;
    const fixture = @import("../xds/eds/testing.zig");
    const bytes = try fixture.encode(allocator, "eds-resource", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1 }} }}, null);
    defer allocator.free(bytes);
    const snapshot = try eds.Snapshot.create(allocator, bytes, .{}, .{ .authority = "localhost", .cluster = "logical-cluster", .max_concurrent_requests = 0 });
    defer snapshot.release();
    var client = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer client.deinit();
    _ = try snapshot.publishWithDeadline(client, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    var sender = client.sender();
    defer sender.deinit();
    var response = try sender.unary(.{ .path = "/demo.Circuit/Unary", .message = "request", .wait_for_ready = true });
    defer response.deinit();
    try std.testing.expect(response.was_dropped and response.status == .unavailable);
    try std.testing.expectEqualStrings("circuit breaker drop", response.status_message);
    var observer = try circuit.Policy.init(.{ .cluster = "logical-cluster", .eds_service_name = "eds-resource", .max_concurrent_requests = 1 });
    defer observer.deinit();
    try std.testing.expectEqual(@as(u64, 1), observer.stats().rejected);
    try std.testing.expectEqual(@as(u32, 0), observer.stats().active);
}

test "gRPC circuit breaker ordinary client streaming keeps permit after request FIN until response completion" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        fn consume(count: *usize, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("request", message.payload);
            count.* += 1;
        }
        fn run(listener: *grpc.runtime.Server) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var count: usize = 0;
            var request = try connection.readStreamingWithTimeout(.fromSeconds(5), &count, consume);
            defer request.deinit();
            try std.testing.expectEqual(@as(usize, 1), count);
            try connection.writeUnary(request.transport.stream_id, .{ .message = "request" });
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    const options: circuit.Options = .{ .cluster = "ordinary-streaming", .max_concurrent_requests = 1 };
    var client = try grpc.Channel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{ .circuit_breaker = options });
    defer client.deinit();
    var observer = try circuit.Policy.init(options);
    defer observer.deinit();
    var writer = try client.startStreaming(.{ .path = "/demo.Circuit/Streaming", .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
    defer writer.deinit();
    try writer.writeMessage("request");
    try writer.finish();
    try std.testing.expectEqual(@as(u32, 1), observer.stats().active);
    var count: usize = 0;
    var response = try writer.readResponse(&count, Peer.consume);
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(u32, 0), observer.stats().active);
    try peer.await(io);
}
