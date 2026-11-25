//! Actual raw UDP submission, ownership rollback, and completion races.
const std = @import("std");
const quic = @import("../../../../quic/mod.zig");
const Probe = @import("../../../../internal/testing/udp_deadline_probe.zig").Probe;
const packetizer = @import("../packetizer.zig");
const development = @import("../../development/send.zig");
const scratch = @import("../scratch.zig");
const outbound = @import("../../stream/outbound_body.zig");
const allocator = std.testing.allocator;
const app_runtime = @import("../../../../runtime.zig");
const until: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1000000) };

const Pair = struct {
    probe: Probe,
    sender: quic.runtime.Endpoint,
    receiver: quic.runtime.Endpoint,
    peer_backend: app_runtime.Backend,

    fn init(self: *Pair, emit_prefix: bool) !void {
        self.probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .expected_messages = 1, .emit_prefix = emit_prefix };
        errdefer self.probe.backend.deinit();
        self.peer_backend = try app_runtime.Backend.initWithExecutors(allocator, 1);
        errdefer self.peer_backend.deinit();
        self.receiver = try quic.runtime.Endpoint.bind(allocator, self.peer_backend.io(), .{ .ip4 = .loopback(0) }, .{});
        errdefer self.receiver.deinit();
        self.sender = try quic.runtime.Endpoint.bind(allocator, self.probe.io(), .{ .ip4 = .loopback(0) }, .{});
    }

    fn deinit(self: *Pair) void {
        self.sender.deinit();
        self.receiver.deinit();
        self.peer_backend.deinit();
        self.probe.backend.deinit();
    }

    fn expectNoPacket(self: *Pair) !void {
        try std.testing.expectError(error.Timeout, self.receiver.receiveWithTimeout(.{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(20) } }));
    }
};

fn blockedSend(failure: ?std.Io.net.Socket.SendError) !void {
    var pair: Pair = undefined;
    try pair.init(false);
    defer pair.deinit();
    pair.probe.forced_error = failure;
    var attempted = false;
    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 0, .data = "abc", .fin = true } }};
    const expected: anyerror = if (failure) |err| err else error.Timeout;
    try std.testing.expectError(expected, packetizer.sendEndpointUntil(allocator, &pair.sender, pair.receiver.address(), &frames, 1, &attempted, until));
    try std.testing.expect(attempted);
    try std.testing.expect(pair.probe.joined.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), pair.probe.send_calls.load(.acquire));
    try pair.expectNoPacket();

    // Cancellation has joined and released the endpoint's send mutex.
    try packetizer.sendEndpoint(allocator, &pair.sender, pair.receiver.address(), &frames, 1, null);
    var packet = try pair.receiver.receiveWithTimeout(.{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), packet.frames.len);
    try std.testing.expectEqualStrings("abc", packet.frames[0].stream.data);
    try std.testing.expect(packet.frames[0].stream.fin);
}

test "HTTP/3 development socket deadline cancels actual blocked send and joins" {
    try blockedSend(null);
}

test "HTTP/3 development socket deadline preserves actual network error" {
    try blockedSend(error.NetworkDown);
}

test "HTTP/3 development socket deadline keeps completed RESET STOP race successful" {
    var pair: Pair = undefined;
    try pair.init(true);
    defer pair.deinit();
    var attempted = false;
    try development.requestCancellationUntil(&pair.sender, pair.receiver.address(), 0, 0x10c, 7, true, until, &attempted);
    try std.testing.expect(attempted);
    try std.testing.expect(pair.probe.joined.load(.acquire));
    var packet = try pair.receiver.receiveWithTimeout(.{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), packet.frames.len);
    try std.testing.expectEqual(@as(u64, 7), packet.frames[0].reset_stream.final_size);
    try std.testing.expectEqual(@as(u64, 0x10c), packet.frames[0].reset_stream.application_error_code);
    try std.testing.expectEqual(@as(u64, 0x10c), packet.frames[1].stop_sending.application_error_code);
    try std.testing.expectEqual(@as(usize, 1), pair.probe.send_calls.load(.acquire));
}

test "HTTP/3 development socket deadline keeps original budget across head packets" {
    var pair: Pair = undefined;
    try pair.init(true);
    defer pair.deinit();
    var message: scratch.Message = .{};
    defer message.deinit(allocator);
    try message.encoded.appendSlice(allocator, "abcdef");
    var bodies = outbound.Set.init(allocator, 2);
    defer bodies.deinit();
    var attempted = false;
    try std.testing.expectError(error.Timeout, development.streamingHeadAtOffsetUntil(&pair.sender, pair.receiver.address(), &message, 0, 0, 4, true, 3, &bodies, &attempted, until));
    try std.testing.expect(attempted);
    try std.testing.expect(pair.probe.joined.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), pair.probe.send_calls.load(.acquire));
    // A partially submitted head stays owned for the caller's terminal
    // cleanup; it cannot be rolled back to an empty request stream.
    try std.testing.expect(bodies.find(0) != null);
    var packet = try pair.receiver.receiveWithTimeout(.{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), packet.frames.len);
    try std.testing.expectEqualStrings("abc", packet.frames[0].stream.data);
    try std.testing.expectEqual(@as(u64, 0), packet.frames[0].stream.offset);
    try std.testing.expect(!packet.frames[0].stream.fin);
    try pair.expectNoPacket();
}

test "HTTP/3 development socket deadline rolls back head and DATA on unavailable watcher" {
    var pair: Pair = undefined;
    try pair.init(false);
    defer pair.deinit();
    pair.probe.table.groupConcurrent = std.Io.failingGroupConcurrent;
    var message: scratch.Message = .{};
    defer message.deinit(allocator);
    try message.encoded.appendSlice(allocator, "head");
    var bodies = outbound.Set.init(allocator, 2);
    defer bodies.deinit();
    var attempted = true;
    try std.testing.expectError(error.ConcurrencyUnavailable, development.streamingHeadAtOffsetUntil(&pair.sender, pair.receiver.address(), &message, 0, 0, 4, true, 8, &bodies, &attempted, until));
    try std.testing.expect(!attempted);
    try std.testing.expect(bodies.find(0) == null);

    try bodies.reserveOpen(4);
    bodies.appendOpenAssumeCapacity(4, quic.stream_state.SendState.init(4), 4);
    attempted = true;
    try std.testing.expectError(error.ConcurrencyUnavailable, development.bodyChunkWithDeadline(&pair.sender, pair.receiver.address(), &bodies, 4, "data", true, 8, &attempted, until));
    try std.testing.expect(!attempted);
    try std.testing.expectEqual(@as(usize, 0), bodies.find(4).?.written);
    try std.testing.expectEqual(@as(u64, 0), bodies.find(4).?.send.next_offset);
    try std.testing.expectEqual(@as(usize, 0), pair.probe.send_calls.load(.acquire));
    try pair.expectNoPacket();
}

test "HTTP/3 development socket deadline rejects expired and foreign clocks before send" {
    var pair: Pair = undefined;
    try pair.init(false);
    defer pair.deinit();
    for ([_]std.Io.Clock.Timestamp{ .{ .clock = .awake, .raw = .zero }, .{ .clock = .real, .raw = until.raw } }) |invalid| {
        var attempted = false;
        try std.testing.expectError(error.Timeout, development.requestCancellationUntil(&pair.sender, pair.receiver.address(), 0, 0x10c, 0, true, invalid, &attempted));
        try std.testing.expect(!attempted);
    }
    try std.testing.expectEqual(@as(usize, 0), pair.probe.send_calls.load(.acquire));
    try pair.expectNoPacket();
}
