const std = @import("std");
const webtransport = @import("../../../mod.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;

test "WebTransport reset prefix cancels unwritten bidi and uni streams with zero data credit" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
        for ([_]bool{ false, true }) |explicit| {
            var settings = webtransport.defaultSettings(.{});
            settings.webtransport_initial_max_data = 0;
            var pair: Pair = undefined;
            try pair.initWithSettings(threaded.io(), settings, settings);
            defer pair.deinit();
            const id = switch (direction) {
                .bidirectional => try pair.client.openBidirectionalStream(),
                .unidirectional => try pair.client.openUnidirectionalStream(),
            };
            if (explicit)
                try pair.client.resetStreamReliably(id, 71, 0)
            else
                try pair.client.resetStream(id, 71);
            try std.testing.expectEqual(@as(u64, 0), pair.client.streams.flow.?.sent.data);
            try std.testing.expectEqual(@as(u64, 0), pair.client.streams.get(id).?.bytes_sent);
            try std.testing.expect(pair.client.streams.get(id).?.prefix_sent);
            const reset = pair.connection(.client).sendStreamStats(id).?.reset.?;
            try std.testing.expectEqual(@as(u64, 3), reset.reliable_size);
            try std.testing.expectEqual(@as(u64, 3), reset.final_size);
            var out: [16]u8 = undefined;
            const event = try pair.server.readStreamWithTimeout(&out, .fromSeconds(1));
            try std.testing.expect(event == .reset);
            try std.testing.expectEqual(id, event.reset.stream_id);
            try std.testing.expectEqual(@as(?u32, 71), event.reset.error_info.application_code);
            try std.testing.expectEqual(@as(u64, 0), pair.server.streams.flow.?.received.data);
        }
    }
}

const DropHeader = struct {
    delegate: std.Io,
    dropped: bool = false,

    fn netSend(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        if (!self.dropped) {
            self.dropped = true;
            return .{ null, messages.len };
        }
        return self.delegate.vtable.netSend(self.delegate.userdata, socket, messages, flags);
    }
};

test "WebTransport reset prefix recovers a lost association before delivering reset" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try pair.client.openBidirectionalStream();
    const conn = pair.connection(.client);
    const original_io = conn.endpoint.io;
    var drop = DropHeader{ .delegate = original_io };
    var vtable = original_io.vtable.*;
    vtable.netSend = DropHeader.netSend;
    conn.endpoint.io = .{ .userdata = &drop, .vtable = &vtable };
    defer conn.endpoint.io = original_io;
    try pair.client.sendStream(id, "payload", false);
    try pair.client.resetStream(id, 73);
    const receiver = pair.connection(.server);
    const deadline = std.Io.Clock.Timestamp.fromNow(receiver.endpoint.io, .{ .raw = .fromSeconds(2), .clock = .awake });
    while ((if (receiver.recvStreamStats(id)) |stats| stats.reset else null) == null) try pair.receiveProgress(.server, deadline);
    try std.testing.expectEqual(@as(u64, 3), receiver.recvStreamStats(id).?.reset.?.reliable_size);
    try std.testing.expect((receiver.retainedReceivedStream(id) orelse @as([]const u8, &.{})).len == 0);
    const Worker = struct {
        pair: *Pair,
        id: u62,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var out: [16]u8 = undefined;
            const event = try self.pair.server.readStreamWithTimeout(&out, .fromSeconds(2));
            try std.testing.expect(event == .reset);
            try std.testing.expectEqual(self.id, event.reset.stream_id);
            try std.testing.expectEqual(@as(?u32, 73), event.reset.error_info.application_code);
            try std.testing.expectEqual(@as(u64, 10), event.reset.final_size);
            _ = try self.pair.server.flushPendingAck();
        }
    };
    var worker = Worker{ .pair = &pair, .id = id };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    var sender_error: ?anyerror = null;
    pair.client.waitForRecoveryIdleWithTimeout(.fromSeconds(2)) catch |err| {
        sender_error = err;
    };
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    if (sender_error) |err| return err;
    try std.testing.expect(drop.dropped);
    try std.testing.expectEqual(@as(u64, 7), pair.client.streams.flow.?.sent.data);
    try std.testing.expectEqual(@as(u64, 7), pair.server.streams.flow.?.received.data);
}

test "WebTransport reset prefix survives STOP for an implicitly opened lower stream" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const unwritten = try pair.client.openBidirectionalStream();
    const sibling = try pair.client.openBidirectionalStream();
    try pair.client.sendStream(sibling, "live", false);
    var out: [16]u8 = undefined;
    const initial = try pair.server.readStreamWithTimeout(&out, .fromSeconds(1));
    try std.testing.expect(initial == .data and initial.data.stream_id == sibling);
    try pair.connection(.server).sendStopSending(unwritten, webtransport.applicationErrorCodeToHttp3(82));
    const deadline = std.Io.Clock.Timestamp.fromNow(pair.connection(.client).endpoint.io, .{ .raw = .fromSeconds(1), .clock = .awake });
    while (pair.connection(.client).sendStreamStats(unwritten).?.reset == null) {
        try pair.client.serviceTransportWithDeadline(deadline);
    }
    const reset = pair.connection(.client).sendStreamStats(unwritten).?.reset.?;
    try std.testing.expectEqual(@as(u64, 3), reset.reliable_size);
    const event = try pair.server.readStreamWithTimeout(&out, .fromSeconds(1));
    try std.testing.expect(event == .reset and event.reset.stream_id == unwritten);
    try std.testing.expectEqual(@as(?u32, 82), event.reset.error_info.application_code);
    try std.testing.expectEqual(@as(u64, 4), pair.server.streams.flow.?.received.data);
}

test "WebTransport reset prefix opening preserves callback receive ownership" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const before = pair.connection(.client).nextLocalBidirectionalStreamId();
    pair.client.h3.callback_reader_active = true;
    defer pair.client.h3.callback_reader_active = false;
    try std.testing.expectError(error.ConcurrentRead, pair.client.openBidirectionalStreamWithTimeout(.fromSeconds(1)));
    try std.testing.expectEqual(before, pair.connection(.client).nextLocalBidirectionalStreamId());
    try std.testing.expectEqual(@as(u64, 0), pair.client.streams.opened_local_bidi);
}
