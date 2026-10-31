const std = @import("std");
const grpc = @import("../../../../mod.zig");
const http2 = @import("../../../../../http2/mod.zig");
const duplex = @import("../../../../stream/duplex.zig");
const State = @import("../../state.zig").State;
const Owner = @import("../owner.zig").Owner(State);
const stream = @import("../../stream.zig");
const connectivity = @import("../../../connectivity.zig");
const allocator = std.testing.allocator;

test "gRPC shared final DATA commits buffered terminal before RPC deadline expiry" {
    try run(false);
}

test "gRPC shared final DATA preserves truncated-message error after terminal commitment" {
    try run(true);
}

fn run(comptime truncated: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_concurrent_streams = 1 }, 4096);
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var first = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer first.deinit();
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(allocator);
            try grpc.wire.writeMessage(&body, allocator, "received-before-deadline", false);
            if (truncated) body.items.len -= 1;
            // A valid gRPC envelope with HTTP/2 DATA END_STREAM and no
            // grpc-status commits the standard UNKNOWN fallback terminal.
            try connection.connection.writeResponseWithTimeout(first.request.stream_id, .{
                .headers = &.{.{ .name = "content-type", .value = "application/grpc" }},
                .body = body.items,
            }, .fromSeconds(5));
            var second = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer second.deinit();
            try std.testing.expectEqualStrings("next", second.request.message.payload);
            try connection.writeUnary(second.request.stream_id, .{ .message = "reused" });
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var connection = try http2.runtime.Client.connectWithTimeout(allocator, io, server.address(), .{}, .fromSeconds(5));
    defer connection.close();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromMilliseconds(500), .clock = .awake });
    const options: grpc.StreamingRequestOptions = .{ .path = "/demo.Shared/Committed", .max_message_size = 4096 };
    var wire = try duplex.startDuplexWithDeadlines(&connection, allocator, options, deadline, deadline);
    var wire_owned = true;
    defer if (wire_owned) wire.deinit();
    try wire.transport.deferResponseStreamCredit();
    try std.testing.expectEqual(duplex.WriteResult.complete, try wire.writeFinalMessage("first"));

    // Drive the real endpoint owner against real TCP input one turn at a
    // time, holding exactly the boundary after final DATA enters the ring.
    var state = State{
        .allocator = allocator,
        .io = io,
        .options = .{},
        .policy = .pick_first,
        .tracker = try connectivity.Tracker.create(allocator, io),
    };
    defer state.tracker.release();
    const call = try State.StreamCall.create(&state, options, deadline);
    defer {
        state.lock();
        call.retireLocked(error.Canceled);
        state.unlock();
        call.release();
    }
    call.bytes = try allocator.alloc(u8, 65535);
    const Worker = struct {
        parent: *State,
        outstanding_requests: usize = 1,
        streams: std.ArrayList(Owner.Active) = .empty,
    };
    var worker = Worker{ .parent = &state };
    defer worker.streams.deinit(allocator);
    try worker.streams.ensureUnusedCapacity(allocator, 1);
    call.retain();
    worker.streams.appendAssumeCapacity(.{ .call = call, .stream = wire });
    wire_owned = false;
    defer while (worker.streams.items.len != 0) Owner.fail(&worker, 0, error.Canceled);
    while (call.len == 0 and !call.retired) {
        if (!try Owner.tick(&worker, deadline)) {
            _ = try connection.pumpClientDuplexWithDeadline(deadline);
        }
    }
    try std.testing.expect(call.len != 0);
    try std.testing.expectEqual(@as(?anyerror, null), call.failureValue());
    try std.Io.sleep(io, .fromMilliseconds(550), .awake);
    try std.testing.expect(deadline.durationFromNow(io).raw.nanoseconds <= 0);
    const operation = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake });
    _ = try Owner.tick(&worker, operation);
    try std.testing.expectEqual(@as(?anyerror, null), call.failureValue());
    const reader = stream.Reader{ .call = call };
    var initial = try reader.next();
    defer initial.deinit(allocator);
    try std.testing.expect(initial == .initial_metadata);
    if (truncated) {
        try std.testing.expectError(error.BufferTooShort, reader.next());
    } else {
        var messages: usize = 0;
        while (true) {
            var event = try reader.next();
            defer event.deinit(allocator);
            switch (event) {
                .message => |message| {
                    try std.testing.expectEqualStrings("received-before-deadline", message.payload);
                    messages += 1;
                },
                .terminal => |response| {
                    try std.testing.expectEqual(grpc.Status.unknown, response.status);
                    try std.testing.expect(response.status_message.len != 0);
                    try std.testing.expectEqual(@as(usize, 1), messages);
                    break;
                },
                else => return error.UnexpectedResponseEvent,
            }
        }
    }
    var next = try duplex.startDuplexWithIoDeadline(&connection, allocator, .{ .path = "/demo.Shared/Next" }, operation);
    defer next.deinit();
    try std.testing.expectEqual(duplex.WriteResult.complete, try next.writeFinalMessage("next"));
    const Collector = struct {
        calls: usize = 0,
        fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("reused", message.payload);
            self.calls += 1;
        }
    };
    var collector: Collector = .{};
    while (true) {
        var event = try next.readResponseEventWithDeadline(operation, &collector, Collector.consume);
        defer event.deinit(allocator);
        if (event == .terminal) {
            try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
            try std.testing.expectEqual(@as(usize, 1), collector.calls);
            break;
        }
    }
    try peer.await(io);
}
