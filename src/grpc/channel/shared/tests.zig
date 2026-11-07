const std = @import("std");
const grpc = @import("../../mod.zig");
const shared = @import("../shared.zig");
const allocator = std.testing.allocator;

const Call = struct {
    fn run(sender: shared.Sender, message: []const u8) !grpc.UnaryResponse {
        return sender.unary(.{ .path = "/demo.Shared/Unary", .message = message, .timeout = .{ .value = 3, .unit = .second }, .wait_for_ready = true });
    }
};

const PriorityPeer = struct {
    fn run(
        server: *grpc.runtime.Server,
        stop: *std.Io.Event,
        label: []const u8,
    ) !void {
        var connection = try server.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        while (!stop.isSet()) {
            var request = connection.readUnaryWithTimeout(.fromMilliseconds(100)) catch |err| switch (err) {
                error.Timeout => continue,
                error.ConnectionClosed,
                error.ConnectionResetByPeer,
                error.SocketUnconnected,
                error.UnexpectedEof,
                => return,
                else => return err,
            };
            defer request.deinit();
            try connection.writeUnary(request.request.stream_id, .{ .message = label });
        }
    }
};

test "gRPC shared background channel multiplexes concurrent unary calls on one connection" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        const Collector = struct {
            bodies: [2]std.ArrayList(u8) = .{ .empty, .empty },
            fn consume(self: *@This(), id: u31, bytes: []const u8) !void {
                const index = (id - 1) / 2;
                if (index >= 2) return error.UnexpectedStream;
                try self.bodies[index].appendSlice(allocator, bytes);
            }
        };
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var collector: Collector = .{};
            defer for (&collector.bodies) |*body| body.deinit(allocator);
            var requests: [2]@import("../../../http2/mod.zig").runtime.StreamingRequest = undefined;
            try connection.connection.readRequestBatchStreamingIntoWithTimeout(&requests, .fromSeconds(3), &collector, Collector.consume);
            defer for (&requests) |*request| request.deinit(allocator);
            for ([_]usize{ 1, 0 }) |index| {
                var iterator = grpc.MessageIterator.init(collector.bodies[index].items, 4096);
                const message = (try iterator.next()).?;
                try std.testing.expect((try iterator.next()) == null);
                try connection.writeUnary(requests[index].stream_id, .{ .message = message.payload });
            }
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    defer client.deinit();
    var a_sender = client.sender();
    defer a_sender.deinit();
    var b_sender = a_sender.clone();
    defer b_sender.deinit();
    var a_call = io.async(Call.run, .{ a_sender, "a" });
    defer _ = a_call.cancel(io) catch {};
    var b_call = io.async(Call.run, .{ b_sender, "b" });
    defer _ = b_call.cancel(io) catch {};
    var a = try a_call.await(io);
    defer a.deinit();
    var b = try b_call.await(io);
    defer b.deinit();
    try std.testing.expectEqualStrings("a", a.message.?.payload);
    try std.testing.expectEqualStrings("b", b.message.?.payload);
    try std.testing.expectEqual(grpc.Status.ok, a.status);
    try std.testing.expectEqual(grpc.Status.ok, b.status);
    try peer.await(io);
}

test "gRPC shared channel unary accepts prefix-reserved request storage" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var request = try connection.readUnary();
            defer request.deinit();
            if (!std.mem.eql(u8, request.request.message.payload, "shared-owned")) {
                return error.InvalidGrpcRequest;
            }
            try connection.writeUnary(request.request.stream_id, .{ .message = "ok" });
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var owned = try grpc.OwnedRequestMessage.init(allocator, "shared-owned".len);
    defer owned.deinit();
    @memcpy(owned.payload(), "shared-owned");
    var response = try sender.unary(.{
        .path = "/demo.Shared/Unary",
        .owned_message = &owned,
        .timeout = .{ .value = 3, .unit = .second },
        .wait_for_ready = true,
    });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings("ok", response.message.?.payload);
    try peer.await(io);
}

test "gRPC shared channel writes a large borrowed request without staging" {
    const large_request = "shared-borrowed-large-" ** 8192;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 16 * 1024, .max_body_bytes = large_request.len + 16 },
        large_request.len + 16,
    );
    defer server.deinit();
    const Peer = struct {
        server: *grpc.runtime.Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings(self.expected, message.payload);
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
            defer stream.deinit();
            var finished = false;
            while (!finished) {
                var event = try stream.readRequestEventWithTimeout(.fromSeconds(5), self, consume);
                defer event.deinit();
                switch (event) {
                    .messages => {},
                    .finished => finished = true,
                    .reset => return error.UnexpectedReset,
                }
            }
            try stream.startResponse(.{});
            _ = try stream.writeMessage("ok");
            try stream.finishOk();
        }
    };
    var peer = Peer{ .server = &server, .expected = large_request };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();

    const Tracker = struct {
        child: std.mem.Allocator,
        threshold: usize,
        large_allocations: usize = 0,

        fn asAllocator(self: *@This()) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &vtable };
        }

        fn alloc(pointer: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            if (len >= self.threshold) self.large_allocations += 1;
            return self.child.rawAlloc(len, alignment, ret);
        }

        fn resize(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) bool {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            return self.child.rawResize(bytes, alignment, len, ret);
        }

        fn remap(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            return self.child.rawRemap(bytes, alignment, len, ret);
        }

        fn free(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            self.child.rawFree(bytes, alignment, ret);
        }

        const vtable: std.mem.Allocator.VTable = .{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        };
    };
    var tracker = Tracker{ .child = allocator, .threshold = large_request.len };
    var client = try shared.SharedChannel.init(
        tracker.asAllocator(),
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{},
    );
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var duplex = try sender.startDuplex(.{
        .path = "/demo.Shared/Borrowed",
        .timeout = .{ .value = 5, .unit = .second },
        .wait_for_ready = true,
    });
    defer duplex.deinit();
    var writer = duplex.writer();
    defer writer.deinit();
    var reader = duplex.reader();
    defer reader.deinit();
    const storage = try allocator.alloc(u8, 5 + large_request.len);
    defer allocator.free(storage);
    @memcpy(storage[5..], large_request);
    tracker.large_allocations = 0;
    try writer.writeFinalBorrowedMessage(storage);
    try std.testing.expectEqual(@as(usize, 0), tracker.large_allocations);

    var terminal = false;
    while (!terminal) {
        var event = try reader.nextWithTimeout(.fromSeconds(5));
        defer event.deinit(allocator);
        switch (event) {
            .terminal => |value| {
                try std.testing.expectEqual(grpc.Status.ok, value.status);
                terminal = true;
            },
            else => {},
        }
    }

    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "gRPC shared send handles and connectivity watches survive channel destruction" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = client.sender();
    defer sender.deinit();
    var watch = client.watchConnectivity();
    defer watch.deinit();
    client.deinit();
    try std.testing.expectError(error.SharedChannelClosed, sender.unary(.{ .path = "/demo.Shared/Unary", .message = "a" }));
    try std.testing.expectEqual(grpc.ChannelConnectivityState.shutdown, (try watch.nextWithTimeout(.fromSeconds(1))).state);
}

test "gRPC shared channel health gates later calls and switches ready endpoints" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a_server.deinit();
    var b_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b_server.deinit();
    var switched: std.Io.Event = .unset;
    const Peer = struct {
        fn consume(_: void, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("demo.Shared", (try grpc.health.decodeRequest(message.payload)).service);
        }
        fn status(writer: *grpc.stream.ServerWriter, value: grpc.health.ServingStatus) !void {
            const encoded = try grpc.health.encodeResponseAlloc(allocator, .{ .status = value });
            defer allocator.free(encoded);
            try writer.writeMessage(encoded);
        }
        fn reply(connection: *grpc.runtime.ServerConnection, value: []const u8) !void {
            var request = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer request.deinit();
            try connection.writeUnary(request.request.stream_id, .{ .message = value });
        }
        fn run(server_ptr: *grpc.runtime.Server, event: *std.Io.Event, first: bool) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var health_request = try connection.readStreamingWithTimeout(.fromSeconds(3), {}, consume);
            defer health_request.deinit();
            var writer = try connection.startStreamingResponse(health_request.transport.stream_id, .{});
            defer writer.deinit();
            try status(&writer, if (first) .serving else .not_serving);
            if (first) try reply(&connection, "A");
            try event.waitTimeout(connection.connection.io, .{ .deadline = .fromNow(connection.connection.io, .{ .raw = .fromSeconds(3), .clock = .awake }) });
            try status(&writer, if (first) .not_serving else .serving);
            if (!first) try reply(&connection, "B");
            var reset = connection.connection.readResetStreamWithTimeout(.fromSeconds(3)) catch |err| switch (err) {
                error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => {
                    writer.transport.finished = true;
                    return;
                },
                else => return err,
            };
            defer reset.deinit(allocator);
            try std.testing.expectEqual(health_request.transport.stream_id, reset.reset.stream_id);
            writer.transport.finished = true;
        }
    };
    var a_peer = io.async(Peer.run, .{ &a_server, &switched, true });
    defer _ = a_peer.cancel(io) catch {};
    var b_peer = io.async(Peer.run, .{ &b_server, &switched, false });
    defer _ = b_peer.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a_server.address() } },
        .{ .cleartext_ip = .{ .address = b_server.address() } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{
        .service_config_json = "{\"healthCheckConfig\":{\"serviceName\":\"demo.Shared\"}}",
    });
    var client_live = true;
    defer if (client_live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var a_watch = client.watchEndpointConnectivity(0).?;
    defer a_watch.deinit();
    var b_watch = client.watchEndpointConnectivity(1).?;
    defer b_watch.deinit();
    var first = try Call.run(sender, "first");
    defer first.deinit();
    try std.testing.expectEqualStrings("A", first.message.?.payload);
    while ((try b_watch.nextWithTimeout(.fromSeconds(3))).state != .transient_failure) {}
    switched.set(io);
    while ((try a_watch.nextWithTimeout(.fromSeconds(3))).state != .transient_failure) {}
    while ((try b_watch.nextWithTimeout(.fromSeconds(3))).state != .ready) {}
    var second = try Call.run(sender, "second");
    defer second.deinit();
    try std.testing.expectEqualStrings("B", second.message.?.payload);
    client.deinit();
    client_live = false;
    try a_peer.await(io);
    try b_peer.await(io);
}

test "gRPC shared caller cancellation joins retirement and preserves channel reuse" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var admitted: std.Io.Event = .unset;
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server, signal: *std.Io.Event) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var first = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer first.deinit();
            signal.set(connection.connection.io);
            var reset = try connection.connection.readResetStreamWithTimeout(.fromSeconds(3));
            defer reset.deinit(allocator);
            try std.testing.expectEqual(first.request.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(@import("../../../http2/mod.zig").ErrorCode.cancel, reset.reset.error_code);
            var second = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer second.deinit();
            try connection.writeUnary(second.request.stream_id, .{ .message = "reused" });
        }
    };
    var peer = io.async(Peer.run, .{ &server, &admitted });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var pending = try io.concurrent(Call.run, .{ sender, "cancel" });
    try admitted.waitTimeout(io, .{ .deadline = .fromNow(io, .{ .raw = .fromSeconds(3), .clock = .awake }) });
    try std.testing.expectError(error.Canceled, pending.cancel(io));
    var response = try Call.run(sender, "next");
    defer response.deinit();
    try std.testing.expectEqualStrings("reused", response.message.?.payload);
    try peer.await(io);
}

test "gRPC shared channel applies configured retry and previous-attempt metadata" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var first = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer first.deinit();
            try std.testing.expect(grpc.call.headerValue(first.request.headers, "grpc-previous-rpc-attempts") == null);
            try connection.writeUnary(first.request.stream_id, .{ .status = .unavailable, .retry_pushback_ms = 0, .trailers_only = true });
            var second = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer second.deinit();
            try std.testing.expectEqualStrings("1", grpc.call.headerValue(second.request.headers, "grpc-previous-rpc-attempts").?);
            try connection.writeUnary(second.request.stream_id, .{ .message = "retried" });
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{
        .service_config_json =
        \\{"methodConfig":[{"name":[{}],"retryPolicy":{"maxAttempts":2,
        \\"initialBackoff":"0.001s","maxBackoff":"0.01s","backoffMultiplier":2,
        \\"retryableStatusCodes":["UNAVAILABLE"]}}]}
        ,
    });
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var response = try Call.run(sender, "retry");
    defer response.deinit();
    try std.testing.expectEqualStrings("retried", response.message.?.payload);
    try peer.await(io);
}

test "gRPC staged final-message polling retains exact suffix without reading for credit" {
    const http2 = @import("../../../http2/mod.zig");
    const Fixture = @import("../../../http2/runtime/duplex/testing.zig").Fixture;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var stream = try grpc.startDuplex(&fixture.connection, allocator, .{ .path = "/demo.Shared/Unary", .authority = "localhost" });
    defer stream.deinit();
    try stream.stageFinalMessage("body", .{});
    (try http2.runtime.testing.sendStreamWindow(&fixture.connection, stream.streamId())).value = 1;
    const until = std.Io.Clock.Timestamp.fromNow(fixture.io, .{ .raw = .fromSeconds(1), .clock = .awake });
    try std.testing.expectEqual(@import("../../stream/duplex.zig").PollWriteResult.blocked, try stream.pollResumeMessageWithDeadline(until, 64));
    try std.testing.expectEqual(@as(usize, 1), stream.transport.requestCommittedBytes());
    try fixture.frame(.window_update, 0, stream.streamId(), &.{ 0, 0, 0, 8 });
    const before = fixture.connection.frame_reader.start;
    try std.testing.expectEqual(@import("../../stream/duplex.zig").PollWriteResult.blocked, try stream.pollResumeMessageWithDeadline(until, 64));
    try std.testing.expectEqual(before, fixture.connection.frame_reader.start);
    _ = try fixture.connection.pumpClientDuplexWithDeadline(until);
    try std.testing.expectEqual(@import("../../stream/duplex.zig").PollWriteResult.complete, try stream.pollResumeMessageWithDeadline(until, 64));
    try std.testing.expectEqual(@as(usize, 9), stream.transport.requestCommittedBytes());
    try std.testing.expect(stream.requestFinished());
}

test "gRPC shared health changes gate admission without canceling an active RPC" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn consume(_: void, message: grpc.StreamingMessage) !void {
            _ = try grpc.health.decodeRequest(message.payload);
        }
        fn send(writer: *grpc.stream.ServerWriter, status: grpc.health.ServingStatus) !void {
            const message = try grpc.health.encodeResponseAlloc(allocator, .{ .status = status });
            defer allocator.free(message);
            try writer.writeMessage(message);
        }
        fn run(server_ptr: *grpc.runtime.Server, released: *std.Io.Event) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var request = try connection.readStreamingWithTimeout(.fromSeconds(3), {}, consume);
            defer request.deinit();
            var writer = try connection.startStreamingResponse(request.transport.stream_id, .{});
            defer writer.deinit();
            try send(&writer, .serving);
            var rpc = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer rpc.deinit();
            try send(&writer, .not_serving);
            try released.waitTimeout(connection.connection.io, .{ .deadline = .fromNow(connection.connection.io, .{ .raw = .fromSeconds(3), .clock = .awake }) });
            try connection.writeUnary(rpc.request.stream_id, .{ .message = "active-completed" });
            var reset = connection.connection.readResetStreamWithTimeout(.fromSeconds(3)) catch |err| switch (err) {
                error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => {
                    writer.transport.finished = true;
                    return;
                },
                else => return err,
            };
            defer reset.deinit(allocator);
            writer.transport.finished = true;
        }
    };
    var peer = io.async(Peer.run, .{ &server, &release });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{ .health_service = "" });
    var client_live = true;
    defer if (client_live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var states = client.watchEndpointConnectivity(0).?;
    defer states.deinit();
    var active = try io.concurrent(Call.run, .{ sender, "active" });
    defer _ = active.cancel(io) catch {};
    while ((try states.nextWithTimeout(.fromSeconds(3))).state != .transient_failure) {}
    try std.testing.expectError(error.ConnectionUnavailable, sender.unary(.{ .path = "/demo.Shared/Unary", .message = "fail-fast", .wait_for_ready = false }));
    try std.testing.expectError(error.Timeout, sender.unary(.{ .path = "/demo.Shared/Unary", .message = "queued", .wait_for_ready = true, .timeout = .{ .value = 10, .unit = .millisecond } }));
    release.set(io);
    var response = try active.await(io);
    defer response.deinit();
    try std.testing.expectEqualStrings("active-completed", response.message.?.payload);
    client.deinit();
    client_live = false;
    try peer.await(io);
}

test "gRPC shared channel constructor releases resources on allocation and admission failure" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, io: std.Io) !void {
            var channel = try shared.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{
                .service_config_json = "{\"healthCheckConfig\":{\"serviceName\":\"demo.Shared\"}}",
            });
            defer channel.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{threaded.io()});
    var limited = std.Io.Threaded.init(allocator, .{ .concurrent_limit = .limited(1) });
    defer limited.deinit();
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(2) } } },
    };
    try std.testing.expectError(error.ConcurrencyUnavailable, shared.SharedChannel.init(allocator, limited.io(), .{ .resolved = .{ .endpoints = &endpoints } }, .{}));
}

test "gRPC shared channel transparent refusal recovery retains the logical attempt" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var first = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer first.deinit();
            try connection.connection.sendResetStream(first.request.stream_id, .refused_stream);
            var second = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer second.deinit();
            try std.testing.expect(grpc.call.headerValue(second.request.headers, "grpc-previous-rpc-attempts") == null);
            try connection.writeUnary(second.request.stream_id, .{ .message = "transparent" });
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var response = try Call.run(sender, "request");
    defer response.deinit();
    try std.testing.expectEqualStrings("transparent", response.message.?.payload);
    try peer.await(io);
}

test "gRPC shared channel UNIMPLEMENTED disables health checking for its connection" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        fn consume(_: void, message: grpc.StreamingMessage) !void {
            _ = try grpc.health.decodeRequest(message.payload);
        }
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var request = try connection.readStreamingWithTimeout(.fromSeconds(3), {}, consume);
            defer request.deinit();
            try connection.writeUnary(request.transport.stream_id, .{ .status = .unimplemented, .trailers_only = true });
            var rpc = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer rpc.deinit();
            try connection.writeUnary(rpc.request.stream_id, .{ .message = "health-disabled" });
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{ .health_service = "" });
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var response = try Call.run(sender, "request");
    defer response.deinit();
    try std.testing.expectEqualStrings("health-disabled", response.message.?.payload);
    try peer.await(io);
}

test "gRPC shared priority selects the highest ready child" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var high_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer high_server.deinit();
    var low_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer low_server.deinit();
    var stop: std.Io.Event = .unset;
    var high_peer = io.async(PriorityPeer.run, .{ &high_server, &stop, "high" });
    defer _ = high_peer.cancel(io) catch {};
    var low_peer = io.async(PriorityPeer.run, .{ &low_server, &stop, "low" });
    defer _ = low_peer.cancel(io) catch {};
    const high_path = [_][]const u8{"high"};
    const low_path = [_][]const u8{"low"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = high_server.address(), .hierarchical_path = &high_path } },
        .{ .cleartext_ip = .{ .address = low_server.address(), .hierarchical_path = &low_path } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .service_config_json =
            \\{"loadBalancingConfig":[{"priority_experimental":{
            \\ "children":{
            \\  "high":{"config":[{"round_robin":{}}]},
            \\  "low":{"config":[{"round_robin":{}}]}},
            \\ "priorities":["high","low"]}}]}
            ,
        },
    );
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    client.connect();
    var high_watch = client.watchEndpointConnectivity(0).?;
    defer high_watch.deinit();
    while ((try high_watch.nextWithTimeout(.fromSeconds(3))).state != .ready) {}
    for (0..10) |_| {
        var response = try Call.run(sender, "request");
        defer response.deinit();
        try std.testing.expectEqualStrings("high", response.message.?.payload);
    }
    stop.set(io);
    try high_peer.await(io);
}

test "gRPC shared priority falls back to the lower ready child" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var low_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer low_server.deinit();
    var stop: std.Io.Event = .unset;
    var low_peer = io.async(PriorityPeer.run, .{ &low_server, &stop, "low" });
    defer _ = low_peer.cancel(io) catch {};
    const high_path = [_][]const u8{"high"};
    const low_path = [_][]const u8{"low"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &high_path } },
        .{ .cleartext_ip = .{ .address = low_server.address(), .hierarchical_path = &low_path } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .priority_failover_timeout = .fromNanoseconds(0),
            .service_config_json =
            \\{"loadBalancingConfig":[{"priority_experimental":{
            \\ "children":{
            \\  "high":{"config":[{"round_robin":{}}]},
            \\  "low":{"config":[{"round_robin":{}}]}},
            \\ "priorities":["high","low"]}}]}
            ,
        },
    );
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    client.connect();
    var low_watch = client.watchEndpointConnectivity(1).?;
    defer low_watch.deinit();
    while ((try low_watch.nextWithTimeout(.fromSeconds(3))).state != .ready) {}
    for (0..5) |_| {
        var response = try Call.run(sender, "request");
        defer response.deinit();
        try std.testing.expectEqualStrings("low", response.message.?.payload);
    }
    stop.set(io);
    try low_peer.await(io);
}

test "gRPC shared priority accepts least-request and WRR children" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var high_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer high_server.deinit();
    var low_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer low_server.deinit();
    var stop: std.Io.Event = .unset;
    var high_peer = io.async(PriorityPeer.run, .{ &high_server, &stop, "high" });
    defer _ = high_peer.cancel(io) catch {};
    var low_peer = io.async(PriorityPeer.run, .{ &low_server, &stop, "low" });
    defer _ = low_peer.cancel(io) catch {};
    const high_path = [_][]const u8{"high"};
    const low_path = [_][]const u8{"low"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = high_server.address(), .hierarchical_path = &high_path } },
        .{ .cleartext_ip = .{ .address = low_server.address(), .hierarchical_path = &low_path } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .service_config_json =
            \\{"loadBalancingConfig":[{"priority_experimental":{
            \\ "children":{
            \\  "high":{"config":[{"least_request_experimental":{"choiceCount":2}}]},
            \\  "low":{"config":[{"weighted_round_robin":{}}]}},
            \\ "priorities":["high","low"]}}]}
            ,
        },
    );
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    client.connect();
    var high_watch = client.watchEndpointConnectivity(0).?;
    defer high_watch.deinit();
    while ((try high_watch.nextWithTimeout(.fromSeconds(3))).state != .ready) {}
    for (0..5) |_| {
        var response = try Call.run(sender, "request");
        defer response.deinit();
        try std.testing.expectEqualStrings("high", response.message.?.payload);
    }
    stop.set(io);
    try high_peer.await(io);
}

test "gRPC shared priority supports nested priority children" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var high1_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer high1_server.deinit();
    var high2_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer high2_server.deinit();
    var low_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer low_server.deinit();
    var stop: std.Io.Event = .unset;
    var high1_peer = io.async(PriorityPeer.run, .{ &high1_server, &stop, "high1" });
    defer _ = high1_peer.cancel(io) catch {};
    var high2_peer = io.async(PriorityPeer.run, .{ &high2_server, &stop, "high2" });
    defer _ = high2_peer.cancel(io) catch {};
    var low_peer = io.async(PriorityPeer.run, .{ &low_server, &stop, "low" });
    defer _ = low_peer.cancel(io) catch {};
    const high1_path = [_][]const u8{ "high", "high1" };
    const high2_path = [_][]const u8{ "high", "high2" };
    const low_path = [_][]const u8{"low"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = high1_server.address(), .hierarchical_path = &high1_path } },
        .{ .cleartext_ip = .{ .address = high2_server.address(), .hierarchical_path = &high2_path } },
        .{ .cleartext_ip = .{ .address = low_server.address(), .hierarchical_path = &low_path } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .service_config_json =
            \\{"loadBalancingConfig":[{"priority_experimental":{
            \\ "children":{
            \\  "high":{"config":[{"priority_experimental":{
            \\   "children":{
            \\    "high1":{"config":[{"round_robin":{}}]},
            \\    "high2":{"config":[{"round_robin":{}}]}},
            \\   "priorities":["high1","high2"]}}]},
            \\  "low":{"config":[{"round_robin":{}}]}},
            \\ "priorities":["high","low"]}}]}
            ,
        },
    );
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    client.connect();
    var high1_watch = client.watchEndpointConnectivity(0).?;
    defer high1_watch.deinit();
    while ((try high1_watch.nextWithTimeout(.fromSeconds(3))).state != .ready) {}
    for (0..5) |_| {
        var response = try Call.run(sender, "request");
        defer response.deinit();
        try std.testing.expectEqualStrings("high1", response.message.?.payload);
    }
    stop.set(io);
    try high1_peer.await(io);
}

test "gRPC shared priority honors the failover timeout" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    // The high child accepts TCP but never completes the HTTP/2 handshake, so
    // it stays CONNECTING for the whole failover window.
    var high_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer high_server.deinit();
    var low_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer low_server.deinit();
    var stop: std.Io.Event = .unset;
    var low_peer = io.async(PriorityPeer.run, .{ &low_server, &stop, "low" });
    defer _ = low_peer.cancel(io) catch {};
    const high_path = [_][]const u8{"high"};
    const low_path = [_][]const u8{"low"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = high_server.address(), .hierarchical_path = &high_path } },
        .{ .cleartext_ip = .{ .address = low_server.address(), .hierarchical_path = &low_path } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .priority_failover_timeout = .fromSeconds(10),
            .service_config_json =
            \\{"loadBalancingConfig":[{"priority_experimental":{
            \\ "children":{
            \\  "high":{"config":[{"round_robin":{}}]},
            \\  "low":{"config":[{"round_robin":{}}]}},
            \\ "priorities":["high","low"]}}]}
            ,
        },
    );
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    try std.testing.expectError(
        error.Timeout,
        sender.unary(.{
            .path = "/demo.Shared/Unary",
            .message = "request",
            .wait_for_ready = true,
            .timeout = try grpc.Timeout.init(200, .millisecond),
        }),
    );
    stop.set(io);
}

test "gRPC shared priority falls back immediately when the high child fails" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var low_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer low_server.deinit();
    var stop: std.Io.Event = .unset;
    var low_peer = io.async(PriorityPeer.run, .{ &low_server, &stop, "low" });
    defer _ = low_peer.cancel(io) catch {};
    const high_path = [_][]const u8{"high"};
    const low_path = [_][]const u8{"low"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &high_path } },
        .{ .cleartext_ip = .{ .address = low_server.address(), .hierarchical_path = &low_path } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .priority_failover_timeout = .fromSeconds(10),
            .service_config_json =
            \\{"loadBalancingConfig":[{"priority_experimental":{
            \\ "children":{
            \\  "high":{"config":[{"round_robin":{}}]},
            \\  "low":{"config":[{"round_robin":{}}]}},
            \\ "priorities":["high","low"]}}]}
            ,
        },
    );
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var response = try Call.run(sender, "request");
    defer response.deinit();
    try std.testing.expectEqualStrings("low", response.message.?.payload);
    stop.set(io);
    try low_peer.await(io);
}

test "gRPC shared priority restarts the failover timer after the high child was ready" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var high_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer high_server.deinit();
    var low_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer low_server.deinit();
    const HighPeer = struct {
        fn run(server: *grpc.runtime.Server, served: *std.Io.Event, release: *std.Io.Event) !void {
            var connection = try server.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer request.deinit();
            try connection.writeUnary(request.request.stream_id, .{ .message = "high" });
            served.set(connection.connection.io);
            try release.wait(connection.connection.io);
        }
    };
    var served: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    var high_peer = io.async(HighPeer.run, .{ &high_server, &served, &release });
    defer _ = high_peer.cancel(io) catch {};
    var stop: std.Io.Event = .unset;
    var low_peer = io.async(PriorityPeer.run, .{ &low_server, &stop, "low" });
    defer _ = low_peer.cancel(io) catch {};
    const high_path = [_][]const u8{"high"};
    const low_path = [_][]const u8{"low"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = high_server.address(), .hierarchical_path = &high_path } },
        .{ .cleartext_ip = .{ .address = low_server.address(), .hierarchical_path = &low_path } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .priority_failover_timeout = .fromSeconds(10),
            .service_config_json =
            \\{"loadBalancingConfig":[{"priority_experimental":{
            \\ "children":{
            \\  "high":{"config":[{"round_robin":{}}]},
            \\  "low":{"config":[{"round_robin":{}}]}},
            \\ "priorities":["high","low"]}}]}
            ,
        },
    );
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    client.connect();
    var high_watch = client.watchEndpointConnectivity(0).?;
    defer high_watch.deinit();
    while ((try high_watch.nextWithTimeout(.fromSeconds(3))).state != .ready) {}
    var first = try Call.run(sender, "request");
    defer first.deinit();
    try std.testing.expectEqualStrings("high", first.message.?.payload);
    try served.waitTimeout(io, .{ .deadline = .fromNow(io, .{ .raw = .fromSeconds(3), .clock = .awake }) });
    release.set(io);
    try high_peer.await(io);
    while ((try high_watch.nextWithTimeout(.fromSeconds(5))).state != .connecting) {}
    try std.testing.expectError(
        error.Timeout,
        sender.unary(.{
            .path = "/demo.Shared/Unary",
            .message = "request",
            .wait_for_ready = true,
            .timeout = try grpc.Timeout.init(300, .millisecond),
        }),
    );
    stop.set(io);
}

test "gRPC shared nested pick_first shuffle keeps sibling subsets ordered" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const high_path = [_][]const u8{"high"};
    const low_path = [_][]const u8{"low"};
    var high_addresses: [8]std.Io.net.IpAddress = undefined;
    var low_addresses: [2]std.Io.net.IpAddress = undefined;
    var endpoints: [10]grpc.ChannelEndpoint = undefined;
    for (0..8) |index| {
        high_addresses[index] = .{ .ip4 = .loopback(@intCast(1000 + index)) };
        endpoints[index] = .{ .cleartext_ip = .{
            .address = high_addresses[index],
            .hierarchical_path = &high_path,
        } };
    }
    for (0..2) |index| {
        low_addresses[index] = .{ .ip4 = .loopback(@intCast(2000 + index)) };
        endpoints[8 + index] = .{ .cleartext_ip = .{
            .address = low_addresses[index],
            .hierarchical_path = &low_path,
        } };
    }
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .service_config_json =
            \\{"loadBalancingConfig":[{"priority_experimental":{
            \\ "children":{
            \\  "high":{"config":[{"pick_first":{"shuffleAddressList":true}}]},
            \\  "low":{"config":[{"round_robin":{}}]}},
            \\ "priorities":["high","low"]}}]}
            ,
        },
    );
    defer client.deinit();
    try std.testing.expectEqual(@as(usize, 10), client.state.sources.len);
    for (client.state.sources[0..8]) |source| {
        try std.testing.expect(std.mem.eql(
            u8,
            "high",
            source.endpoint.hierarchicalPath()[0],
        ));
    }
    for (client.state.sources[8..], 0..) |source, index| {
        try std.testing.expect(std.mem.eql(
            u8,
            "low",
            source.endpoint.hierarchicalPath()[0],
        ));
        try std.testing.expect(source.endpoint.cleartext_ip.address.eql(
            &low_addresses[index],
        ));
    }
}

test "gRPC shared priority deactivates a lower child after the higher child recovers" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var high_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer high_server.deinit();
    var low_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer low_server.deinit();
    var stop: std.Io.Event = .unset;
    var low_peer = io.async(PriorityPeer.run, .{ &low_server, &stop, "low" });
    defer _ = low_peer.cancel(io) catch {};
    const high_path = [_][]const u8{"high"};
    const low_path = [_][]const u8{"low"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = high_server.address(), .hierarchical_path = &high_path } },
        .{ .cleartext_ip = .{ .address = low_server.address(), .hierarchical_path = &low_path } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .priority_failover_timeout = .fromNanoseconds(0),
            .removed_child_retention = .fromMilliseconds(200),
            .service_config_json =
            \\{"loadBalancingConfig":[{"priority_experimental":{
            \\ "children":{
            \\  "high":{"config":[{"round_robin":{}}]},
            \\  "low":{"config":[{"round_robin":{}}]}},
            \\ "priorities":["high","low"]}}]}
            ,
        },
    );
    defer client.deinit();
    client.connect();
    var low_watch = client.watchEndpointConnectivity(1).?;
    defer low_watch.deinit();
    while ((try low_watch.nextWithTimeout(.fromSeconds(3))).state != .ready) {}
    // The high listener did not accept before this point, so the high worker
    // stayed CONNECTING and the zero failover timeout activated the low child.
    var high_peer = io.async(PriorityPeer.run, .{ &high_server, &stop, "high" });
    defer _ = high_peer.cancel(io) catch {};
    var high_watch = client.watchEndpointConnectivity(0).?;
    defer high_watch.deinit();
    while ((try high_watch.nextWithTimeout(.fromSeconds(3))).state != .ready) {}
    // The higher child is now READY, so the low transport must close after the
    // configured retention interval.
    while ((try low_watch.nextWithTimeout(.fromSeconds(3))).state != .idle) {}
    stop.set(io);
}
