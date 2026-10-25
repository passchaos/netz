//! Receiving a payload must not wait behind outbound QPACK backpressure.
const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const support = @import("../test_support/pair.zig");
const Pair = support.Pair;
const receive = @import("../test_support/receive.zig");

test "HTTP/3 CONNECT DATAGRAM caller buffer survives QPACK feedback backpressure" {
    try exercise(true);
}

test "HTTP/3 CONNECT DATAGRAM owning receive survives QPACK feedback backpressure" {
    try exercise(false);
}

fn exercise(into: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |pacing| {
            for ([_]bool{ false, true }) |bounded| {
                var pair: Pair = undefined;
                try pair.init(threaded.io());
                defer pair.deinit();
                const receiver = if (role == .client) &pair.client else &pair.server;
                try receiver.qpack_decode.recordStreamCancellation(0);
                try pair.sendPeer(role, &.{.{ .datagram = .{ .data = "\x00delivered" } }});
                const connection = pair.connection(role);
                const previous = connection.congestion.congestion_window;
                defer connection.congestion.congestion_window = previous;
                block(connection, threaded.io(), pacing);
                var output: receive.Output = .{};
                output.init();
                try receive.withinBudget(receiver, threaded.io(), if (into) .into else .owned, bounded, &output);
                try std.testing.expectEqualStrings("delivered", output.slices[0]);
                try std.testing.expectEqual(@as(usize, 1), output.received);
                try std.testing.expectEqual(@as(usize, 1), receiver.qpack_decode.pendingDecoderInstructions().len);
                try std.testing.expect(!connection.closing());
            }
        }
    }
}

fn block(connection: *quic.one_rtt.Connection, io: std.Io, pacing: bool) void {
    if (pacing) {
        connection.pacer.enabled = true;
        connection.setMaxPacingRateBytesPerSecond(1);
        quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(io).nanoseconds));
    } else connection.congestion.congestion_window = 0;
}

test "HTTP/3 CONNECT DATAGRAM batch receive preserves its prefix under QPACK backpressure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const receiver = if (role == .client) &pair.client else &pair.server;
        try receiver.qpack_decode.recordStreamCancellation(0);
        try pair.sendPeer(role, &.{ .{ .datagram = .{ .data = "\x00first" } }, .{ .datagram = .{ .data = "\x00second" } } });
        const connection = pair.connection(role);
        const previous = connection.congestion.congestion_window;
        defer connection.congestion.congestion_window = previous;
        block(connection, threaded.io(), false);
        var output: receive.Output = .{};
        output.init();
        try std.testing.expectError(error.Timeout, receive.withinBudget(receiver, threaded.io(), .batch, true, &output));
        try std.testing.expectEqual(@as(usize, 2), output.received);
        try std.testing.expectEqualStrings("first", output.slices[0]);
        try std.testing.expectEqualStrings("second", output.slices[1]);
        try std.testing.expectEqual(@as(usize, 1), receiver.qpack_decode.pendingDecoderInstructions().len);
        try std.testing.expect(!connection.closing());
    }
}

test "HTTP/3 CONNECT DATAGRAM short receive buffer retains payload despite QPACK backpressure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const receiver = if (role == .client) &pair.client else &pair.server;
        try receiver.qpack_decode.recordStreamCancellation(0);
        try pair.sendPeer(role, &.{.{ .datagram = .{ .data = "\x00retained" } }});
        block(pair.connection(role), threaded.io(), true);
        var output: receive.Output = .{};
        output.init();
        output.slices[0] = output.slices[0][0..2];
        try std.testing.expectError(error.BufferTooShort, receive.withinBudget(receiver, threaded.io(), .into, true, &output));
        output.init();
        try receive.withinBudget(receiver, threaded.io(), .into, true, &output);
        try std.testing.expectEqualStrings("retained", output.slices[0]);
        try std.testing.expectEqual(@as(usize, 1), receiver.qpack_decode.pendingDecoderInstructions().len);
    }
}

test "HTTP/3 CONNECT DATAGRAM receive services QPACK pacing wake without new peer traffic" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const receiver = if (role == .client) &pair.client else &pair.server;
        // Force prefix-only writes to exercise more than one feedback packet.
        receiver.options.max_stream_frame_data = 1;
        receiver.options.max_frames_per_packet = 1;
        receiver.qpack_decoder_prefix_sent = false;
        try receiver.qpack_decode.recordStreamCancellation(0);
        const connection = pair.connection(role);
        connection.pacer.enabled = true;
        connection.setMaxPacingRateBytesPerSecond(100000);
        quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(threaded.io()).nanoseconds));
        var output: receive.Output = .{};
        output.init();
        try std.testing.expectError(error.Timeout, receive.withinBudget(receiver, threaded.io(), .into, true, &output));
        try std.testing.expectEqual(@as(usize, 0), receiver.qpack_decode.pendingDecoderInstructions().len);
        try std.testing.expectEqual(@as(u64, 2), receiver.qpack_decoder_send.next_offset);
        const peer = pair.connection(if (role == .client) .server else .client);
        const decoder_id: u62 = if (role == .client) 10 else 11;
        const deadline: std.Io.Clock.Timestamp = .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        while ((if (peer.recvStreamStats(decoder_id)) |stats| stats.highest_received_offset else 0) < 2) {
            var packet = try peer.receivePacketServicingTimersDeadline(deadline);
            packet.deinit(std.testing.allocator);
        }
        try std.testing.expectEqualStrings("\x03\x40", peer.availableReceivedStream(decoder_id).?);
    }
}

test "HTTP/3 CONNECT DATAGRAM receive delivers fresh payload before newly queued QPACK feedback" {
    try newlyQueued(false);
}

test "HTTP/3 CONNECT DATAGRAM receive preserves a fulfilled payload before connection close with QPACK" {
    try newlyQueued(true);
}

fn newlyQueued(close: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.initWithSettings(threaded.io(), .{ .enable_connect_protocol = true, .h3_datagram = true, .qpack_max_table_capacity = 256 });
        defer pair.deinit();
        const receiver = if (role == .client) &pair.client else &pair.server;
        var instructions: std.ArrayList(u8) = .empty;
        defer instructions.deinit(std.testing.allocator);
        try http3.writeQpackEncoderStreamPrefix(&instructions, std.testing.allocator);
        try http3.Qpack.writeEncoderInstruction(&instructions, std.testing.allocator, .{ .set_capacity = 256 });
        try http3.Qpack.writeEncoderInstruction(&instructions, std.testing.allocator, .{ .insert_literal = .{ .name = "x-feedback", .value = "new" } });
        var frames = [_]quic.Frame{
            .{ .stream = .{ .stream_id = if (role == .client) 7 else 6, .data = instructions.items } },
            .{ .datagram = .{ .data = "\x00fresh" } },
            .{ .application_close = .{ .error_code = 91, .reason_phrase = "after delivery" } },
        };
        try pair.sendPeer(role, frames[0..if (close) 3 else 2]);
        block(pair.connection(role), threaded.io(), true);
        var output: receive.Output = .{};
        output.init();
        try receive.withinBudget(receiver, threaded.io(), .into, true, &output);
        try std.testing.expectEqualStrings("fresh", output.slices[0]);
        try std.testing.expectEqual(@as(u64, 1), receiver.qpack_decode.table.insert_count);
        try std.testing.expect(receiver.qpack_decode.pendingDecoderInstructions().len != 0);
        if (close) try std.testing.expectError(error.ConnectionClosed, receiver.pollConnectDatagram(0));
    }
}

test "HTTP/3 CONNECT DATAGRAM attached client receive preserves data under QPACK backpressure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.initWithClientDetached(threaded.io(), .{ .enable_connect_protocol = true, .h3_datagram = true }, false);
    defer pair.deinit();
    try std.testing.expect(!pair.client.connect_datagrams.streamDetached(0));
    try pair.client.qpack_decode.recordStreamCancellation(0);
    try pair.sendPeer(.client, &.{.{ .datagram = .{ .data = "\x00attached" } }});
    block(pair.connection(.client), threaded.io(), true);
    var output: receive.Output = .{};
    output.init();
    try receive.withinBudget(&pair.client, threaded.io(), .into, true, &output);
    try std.testing.expectEqualStrings("attached", output.slices[0]);
    try std.testing.expectEqual(@as(usize, 1), pair.client.qpack_decode.pendingDecoderInstructions().len);
}

test "HTTP/3 CONNECT DATAGRAM receive retains sibling payloads and Capsule bytes under QPACK pacing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.addConnect();
        const receiver = if (role == .client) &pair.client else &pair.server;
        try receiver.qpack_decode.recordStreamCancellation(0);
        const connection = pair.connection(role);
        try pair.sendPeer(role, &.{
            .{ .datagram = .{ .data = "\x01sibling" } },
            .{ .stream = .{ .stream_id = 0, .offset = connection.recvStreamStats(0).?.highest_received_offset, .data = "\x00\x07capsule" } },
            .{ .datagram = .{ .data = "\x00own" } },
        });
        block(connection, threaded.io(), true);
        var output: receive.Output = .{};
        output.init();
        try receive.withinBudget(receiver, threaded.io(), .into, true, &output);
        try std.testing.expectEqualStrings("own", output.slices[0]);
        var sibling = (try receiver.pollConnectDatagram(4)).?;
        defer sibling.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("sibling", sibling.payload);
        try std.testing.expectEqualStrings("\x00\x07capsule", connection.availableReceivedStream(0).?);
        try std.testing.expectEqual(@as(usize, 1), receiver.qpack_decode.pendingDecoderInstructions().len);
    }
}
