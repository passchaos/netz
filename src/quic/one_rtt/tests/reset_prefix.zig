const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");
const ObservedBatchSend = @import("observed_batch_send.zig").ObservedBatchSend;

const Pair = struct {
    sender_endpoint: quic.runtime.Endpoint,
    receiver_endpoint: quic.runtime.Endpoint,
    sender: one_rtt.Connection,
    receiver: one_rtt.Connection,

    fn init(self: *Pair, io: std.Io) !void {
        const allocator = std.testing.allocator;
        self.sender_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.sender_endpoint.deinit();
        self.receiver_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.receiver_endpoint.deinit();
        const keys = quic.protection.deriveAes128Keys([_]u8{0xc3} ** quic.protection.secret_len);
        self.sender = try one_rtt.Connection.init(&self.sender_endpoint, .{
            .peer = self.receiver_endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "reset-prefix-c",
            .peer_connection_id = "reset-prefix-s",
            .reliable_reset = .{ .peer = true },
            .enable_pacing = false,
        });
        errdefer self.sender.deinit();
        self.receiver = try one_rtt.Connection.init(&self.receiver_endpoint, .{
            .peer = self.sender_endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "reset-prefix-s",
            .peer_connection_id = "reset-prefix-c",
            .local_endpoint = .server,
            .reliable_reset = .{ .local = true },
            .enable_pacing = false,
        });
    }

    fn deinit(self: *Pair) void {
        self.sender.deinit();
        self.receiver.deinit();
        self.sender_endpoint.deinit();
        self.receiver_endpoint.deinit();
    }

    fn expectReset(self: *Pair, id: u64, code: u64, expected_prefix: []const u8, expect_stop: bool) !void {
        var packet = try self.receiver.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
        defer packet.deinit(std.testing.allocator);
        var prefix_found = expected_prefix.len == 0;
        var reset_found = false;
        var stop_found = false;
        for (packet.frames) |frame| switch (frame) {
            .stream => |stream| {
                try std.testing.expectEqual(id, stream.stream_id);
                try std.testing.expectEqual(@as(u64, 0), stream.offset);
                try std.testing.expectEqualSlices(u8, expected_prefix, stream.data);
                prefix_found = true;
            },
            .reset_stream_at => |reset| {
                try std.testing.expectEqual(id, reset.stream_id);
                try std.testing.expectEqual(code, reset.application_error_code);
                try std.testing.expectEqual(@as(u64, expected_prefix.len), reset.final_size);
                try std.testing.expectEqual(@as(u64, expected_prefix.len), reset.reliable_size);
                reset_found = true;
            },
            .stop_sending => |stop| {
                try std.testing.expectEqual(id, stop.stream_id);
                try std.testing.expectEqual(code, stop.application_error_code);
                stop_found = true;
            },
            .reset_stream => return error.TestUnexpectedResult,
            else => {},
        };
        try std.testing.expect(prefix_found and reset_found);
        try std.testing.expectEqual(expect_stop, stop_found);
    }
};

test "QUIC reset prefix is submitted with an unwritten stream reset in one packet" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try pair.sender.tryOpenStreamWithResetPrefix(.unidirectional, "tag");
    try std.testing.expectEqual(@as(u64, 0), pair.sender.sendStreamStats(id).?.highest_sent_offset);
    try std.testing.expectError(error.InvalidFrame, pair.sender.trySend(&.{.{ .reset_stream = .{ .stream_id = id, .application_error_code = 17, .final_size = 0 } }}));
    try std.testing.expectError(error.InvalidFrame, pair.sender.trySend(&.{.{ .reset_stream_at = .{ .stream_id = id, .application_error_code = 17, .final_size = 3, .reliable_size = 3 } }}));
    try pair.sender.tryResetStream(id, 17);
    try std.testing.expectEqual(@as(u64, 1), pair.sender.stats().packets_sent);
    try pair.expectReset(id, 17, "tag", false);
    try std.testing.expect(pair.sender.recovery.hasPendingStreamData(id));
    try pair.sender.tryResetStreamReliably(id, 17, 0);
    try std.testing.expectEqual(@as(u64, 3), pair.sender.sendStreamStats(id).?.reset.?.reliable_size);
    try std.testing.expectEqual(@as(u64, 1), pair.sender.stats().packets_sent);
}

test "QUIC reset prefix keeps atomic cancellation retryable after socket failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try pair.sender.tryOpenStreamWithResetPrefix(.bidirectional, "tag");
    const original_io = pair.sender_endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    pair.sender_endpoint.io = observed.io();
    defer pair.sender_endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, pair.sender.tryCancelStream(id, 19));
    try std.testing.expect(pair.sender.sendStreamStats(id).?.reset == null);
    try std.testing.expectEqual(@as(u64, 0), pair.sender.sendStreamStats(id).?.highest_sent_offset);
    observed.fail_on_call = null;
    try pair.sender.tryCancelStream(id, 19);
    try pair.expectReset(id, 19, "tag", true);
    const calls = observed.calls;
    try pair.sender.tryCancelStream(id, 19);
    try std.testing.expectEqual(calls, observed.calls);
    try std.testing.expect(pair.sender.recovery.hasPendingStreamData(id));
}

test "QUIC reset prefix is preserved by automatic STOP_SENDING response" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try pair.sender.tryOpenStreamWithResetPrefix(.bidirectional, "tag");
    try pair.receiver.send(&.{.{ .stop_sending = .{ .stream_id = id, .application_error_code = 23 } }});
    const deadline = std.Io.Clock.Timestamp.fromNow(pair.sender_endpoint.io, .{ .raw = .fromSeconds(1), .clock = .awake });
    try pair.sender.servicePacketServicingTimersDeadline(deadline);
    for (0..4) |_| {
        if (pair.sender.sendStreamStats(id).?.reset != null) break;
        const timer = pair.sender.nextTimerDeadline() orelse return error.TestUnexpectedResult;
        _ = try pair.sender.serviceNextTimerAt(timer.deadline_ns);
    }
    try std.testing.expectEqual(@as(u64, 3), pair.sender.sendStreamStats(id).?.reset.?.reliable_size);
    try pair.expectReset(id, 23, "tag", false);
}

test "QUIC reset prefix allocation failure and invalid prefix preserve stream cursor" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const before = pair.sender.nextLocalBidirectionalStreamId();
    try std.testing.expectError(error.InvalidFrameLength, pair.sender.tryOpenStreamWithResetPrefix(.bidirectional, "12345678901234567"));
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const original_allocator = pair.sender_endpoint.allocator;
    pair.sender_endpoint.allocator = failing.allocator();
    defer pair.sender_endpoint.allocator = original_allocator;
    try std.testing.expectError(error.OutOfMemory, pair.sender.tryOpenStreamWithResetPrefix(.bidirectional, "tag"));
    try std.testing.expectEqual(before, pair.sender.nextLocalBidirectionalStreamId());
    try std.testing.expect(pair.sender.sendStreamStats(before) == null);
}

test "QUIC reset prefix preflight accepts an earlier header packet in one batch" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try pair.sender.tryOpenStreamWithResetPrefix(.bidirectional, "tag");
    const first = [_]quic.Frame{.{ .stream = .{ .stream_id = id, .offset = 0, .data = "tag", .fin = false } }};
    const second = [_]quic.Frame{.{ .reset_stream_at = .{ .stream_id = id, .application_error_code = 31, .final_size = 3, .reliable_size = 3 } }};
    const packets = [_][]const quic.Frame{ &first, &second };
    const now = std.Io.Clock.awake.now(pair.sender_endpoint.io).nanoseconds;
    const result = try pair.sender.sendManyProgressAt(&packets, @intCast(now));
    try std.testing.expectEqual(@as(usize, 2), result.sent_count);
    try std.testing.expect(result.send_error == null);
    try std.testing.expectEqual(@as(u64, 3), pair.sender.sendStreamStats(id).?.highest_sent_offset);
}
