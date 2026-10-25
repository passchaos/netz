//! Buffered application input must not wait for an outbound credit packet.
const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const incremental = @import("../stream_incremental.zig");
const whole = @import("../stream.zig");
const association = @import("../stream_association.zig");
const prefix = @import("prefix.zig");
const ObservedBatchSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;
const allocator = std.testing.allocator;
const Mode = enum { incremental, incremental_poll, whole, whole_poll, discovered };
const Fault = enum { pacing, congestion, socket };

const Trap = struct {
    var sleeps: usize = 0;
    fn sleep(_: ?*anyopaque, _: std.Io.Timeout) std.Io.Cancelable!void {
        sleeps += 1;
        return error.Canceled;
    }
};

test "WebTransport buffered read commits data without an unbounded credit pacing wait" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var vtable = base.vtable.*;
    vtable.sleep = Trap.sleep;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x3c} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "read-credit",
        .peer_connection_id = "peer-credit",
        .local_endpoint = .server,
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = try webtransport.StreamRegistry.init(allocator, .init(0), .server, .{});
    defer registry.deinit();
    const stream = try registry.registerPeer(4, .bidirectional);
    stream.prefix_received = true;
    try quic.one_rtt.testing.applyReceivedFrames(&connection, 0, &.{.{ .stream = .{ .stream_id = 4, .data = "123456" } }}, 0, .not_ect);
    connection.pacer = quic.pacing.Pacer.initWithRateLimit(true, 4096, 1, 1);
    quic.one_rtt.testing.setPacingBudgetAt(&connection, 0, @intCast(std.Io.Clock.awake.now(base).nanoseconds));
    Trap.sleeps = 0;
    var output: [8]u8 = undefined;
    const event = try incremental.readIdWithDeadline(&connection, &registry, .init(0), 4, &output, .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(10) }));
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings("123456", output[0..event.data.bytes]);
    try std.testing.expectEqual(@as(usize, 0), Trap.sleeps);
    try std.testing.expectEqual(@as(u64, 6), connection.recvStreamStats(4).?.bytes_read);
}

test "WebTransport buffered CLOSE capsule commits without waiting for credit pacing" {
    const control_mod = @import("../session_control.zig");
    const http3 = @import("../../../http3/mod.zig");
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var vtable = base.vtable.*;
    vtable.sleep = Trap.sleep;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x3d} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "capsule-credit",
        .peer_connection_id = "peer-credit",
        .local_endpoint = .server,
        .initial_receive_max_data = 32,
        .receive_window = 32,
        .max_receive_window = 32,
        .initial_receive_max_stream_data = 32,
        .stream_receive_window = 32,
        .max_stream_receive_window = 32,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var control = try control_mod.Control.init(allocator, .init(0));
    defer control.deinit();
    var storage: [64]u8 = undefined;
    const capsule = try control_mod.writeCloseInto(&storage, 42, "buffered close reason");
    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(allocator);
    try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = capsule, .consumed = 0 }).write(&framed, allocator);
    try quic.one_rtt.testing.applyReceivedFrames(&connection, 0, &.{.{ .stream = .{ .stream_id = 0, .data = framed.items } }}, 0, .not_ect);
    connection.pacer = quic.pacing.Pacer.initWithRateLimit(true, 4096, 1, 1);
    quic.one_rtt.testing.setPacingBudgetAt(&connection, 0, @intCast(std.Io.Clock.awake.now(base).nanoseconds));
    Trap.sleeps = 0;
    const event = (try control.pollWithDeadline(&connection, .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(10) }))) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(@as(u32, 42), event.closed.code);
    try std.testing.expectEqualStrings("buffered close reason", event.closed.reason);
    try std.testing.expectEqual(@as(usize, 0), Trap.sleeps);
    try std.testing.expectEqual(@as(u64, framed.items.len), connection.recvStreamStats(0).?.bytes_read);
    try std.testing.expect(connection.receive_credit_retry_deadline_ns != null);
    try std.testing.expect((try control.pollOnce(&connection)) == null);
}

test "WebTransport received data and association commit while flow feedback is backpressured" {
    for (std.enums.values(Mode)) |mode| {
        for (std.enums.values(Fault)) |fault| {
            for (std.enums.values(webtransport.StreamDirection)) |direction| try exercise(mode, fault, direction);
        }
    }
}

fn exercise(mode: Mode, fault: Fault, direction: webtransport.StreamDirection) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer receiver_endpoint.deinit();
    var sender_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer sender_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x3e} ** quic.protection.secret_len);
    var sender = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "credit-sender",
        .peer_connection_id = "credit-receiver",
        .initial_send_max_data = 8,
        .initial_send_max_stream_data = 8,
        .enable_pacing = false,
    });
    defer sender.deinit();
    var receiver = try quic.one_rtt.Connection.init(&receiver_endpoint, .{
        .peer = sender_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "credit-receiver",
        .peer_connection_id = "credit-sender",
        .local_endpoint = .server,
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .enable_pacing = false,
    });
    defer receiver.deinit();
    const session: webtransport.SessionId = .init(64);
    var registry = try webtransport.StreamRegistry.init(allocator, session, .server, .{});
    defer registry.deinit();
    const settings = webtransport.defaultSettings(.{});
    try registry.configureFlow(settings, settings);
    const id: u62 = if (direction == .bidirectional) 4 else 2;
    const fin = mode == .whole or mode == .whole_poll;
    var header: [16]u8 = undefined;
    const encoded = try prefix.header(session, direction, &header);
    try std.testing.expectEqual(@as(usize, 4), encoded.len);
    const payload = "body";
    var wire: [8]u8 = undefined;
    @memcpy(wire[0..encoded.len], encoded);
    @memcpy(wire[encoded.len..], payload);
    try sender.send(&.{.{ .stream = .{ .stream_id = id, .data = &wire, .fin = fin } }});
    var received = try receiver.receivePacket();
    received.deinit(allocator);
    if (mode == .discovered) {
        try association.discoverBuffered(&receiver, &registry);
        try std.testing.expect(registry.get(id).?.receive_mode == .unset);
        try std.testing.expectEqual(@as(u64, 0), receiver.recvStreamStats(id).?.bytes_read);
    }
    const original_congestion = receiver.congestion.bytes_in_flight;
    var failed_send = ObservedBatchSend{ .delegate = io, .fail_after_prefix = 0 };
    var send_vtable = io.vtable.*;
    send_vtable.netSend = ObservedBatchSend.netSend;
    switch (fault) {
        .pacing => {
            receiver.pacer = quic.pacing.Pacer.initWithRateLimit(true, 4096, 1, 1);
            quic.one_rtt.testing.setPacingBudgetAt(&receiver, 0, @intCast(std.Io.Clock.awake.now(io).nanoseconds));
        },
        .congestion => receiver.congestion.bytes_in_flight = receiver.congestion.congestion_window,
        .socket => receiver.endpoint.io = .{ .userdata = &failed_send, .vtable = &send_vtable },
    }
    defer receiver.endpoint.io = io;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(100) });
    var output: [16]u8 = undefined;
    if (fin) {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        {
            receiver.endpoint.allocator = failing.allocator();
            defer receiver.endpoint.allocator = allocator;
            try std.testing.expectError(error.OutOfMemory, whole.pollOnce(&receiver, &registry, session, 16));
        }
        try std.testing.expectEqual(@as(u64, 0), quic.one_rtt.testing.receiveDataConsumed(&receiver));
        try std.testing.expectEqual(@as(u64, 0), registry.flow.?.consumed_data);
        var stream = if (mode == .whole)
            try whole.receiveWithDeadline(&receiver, &registry, session, 16, deadline)
        else
            (try whole.pollOnce(&receiver, &registry, session, 16)) orelse return error.TestUnexpectedResult;
        defer stream.deinit();
        try std.testing.expectEqualStrings(payload, stream.payload);
        try std.testing.expect(stream.fin);
    } else {
        const event = if (mode == .incremental_poll)
            (try incremental.pollOnce(&receiver, &registry, session, &output)) orelse return error.TestUnexpectedResult
        else
            try incremental.readIdWithDeadline(&receiver, &registry, session, id, &output, deadline);
        try std.testing.expect(event == .data);
        try std.testing.expectEqualStrings(payload, output[0..event.data.bytes]);
        try std.testing.expect(!event.data.fin);
    }
    try std.testing.expectEqual(@as(u64, 8), quic.one_rtt.testing.receiveDataConsumed(&receiver));
    try std.testing.expectEqual(@as(u64, 4), registry.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 4), registry.flow.?.consumed_data);
    try std.testing.expectEqual(@as(u64, 4), registry.get(id).?.bytes_received);
    try std.testing.expect(receiver.receive_credit_retry_deadline_ns != null);
    if (fault == .socket) try std.testing.expect(failed_send.calls != 0);

    receiver.endpoint.io = io;
    receiver.pacer.enabled = false;
    receiver.congestion.bytes_in_flight = original_congestion;
    // An ACK or terminal stream-credit timer may precede the retained MAX_*
    // obligation. Service the actual next timers until receive credit settles.
    for (0..16) |_| {
        if (receiver.receive_credit_retry_deadline_ns == null) break;
        const timer = receiver.nextTimerDeadline() orelse return error.TestUnexpectedResult;
        _ = try receiver.serviceNextTimerAt(timer.deadline_ns);
    }
    try std.testing.expect(receiver.receive_credit_retry_deadline_ns == null);
    var saw_data_limit = false;
    var saw_stream_limit = fin and direction == .unidirectional;
    while (!saw_data_limit or !saw_stream_limit) {
        var feedback = try sender.receivePacketTimeout(.{ .deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }) });
        defer feedback.deinit(allocator);
        for (feedback.frames) |frame| switch (frame) {
            .max_data => |value| {
                try std.testing.expectEqual(@as(u64, 16), value.maximum_data);
                saw_data_limit = true;
            },
            .max_stream_data => |value| {
                try std.testing.expectEqual(id, value.stream_id);
                try std.testing.expectEqual(@as(u64, 16), value.maximum_stream_data);
                saw_stream_limit = true;
            },
            else => {},
        };
    }
    if (!fin) {
        try std.testing.expect((try incremental.pollOnce(&receiver, &registry, session, &output)) == null);
        try sender.send(&.{.{ .stream = .{ .stream_id = id, .offset = wire.len, .data = "next", .fin = true } }});
        const next = try incremental.readIdWithDeadline(&receiver, &registry, session, id, &output, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
        try std.testing.expect(next == .data and next.data.fin);
        try std.testing.expectEqualStrings("next", output[0..next.data.bytes]);
        try std.testing.expectEqual(@as(u64, 8), registry.flow.?.consumed_data);
    }
}
