const std = @import("std");
const webtransport = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const early = @import("../early_streams.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;
const prefix = @import("../../stream/prefix.zig");
const ObservedBatchSend = @import("../../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

fn active(_: *const anyopaque, _: u64, session_id: u62) bool {
    return session_id == 0;
}

fn owned(context: *const anyopaque, _: u64, stream_id: u62) bool {
    const pair: *const Pair = @ptrCast(@alignCast(context));
    return pair.server.streams.index.contains(stream_id);
}

fn owners(pair: *Pair) early.Owners {
    return .{ .sessions = .{ .context = pair, .scope = 0, .containsFn = active }, .ownsStreamFn = owned };
}

fn open(pair: *Pair, direction: webtransport.StreamDirection, session_id: u62, body: []const u8, fin: bool) !u62 {
    const connection = pair.connection(.client);
    const id: u62 = @intCast(switch (direction) {
        .bidirectional => try connection.tryOpenStream(),
        .unidirectional => try connection.openUnidirectionalStream(),
    });
    var storage: [16]u8 = undefined;
    const header = try prefix.header(.init(session_id), direction, &storage);
    try connection.send(&.{
        .{ .stream = .{ .stream_id = id, .data = header } },
        .{ .stream = .{ .stream_id = id, .offset = header.len, .data = body, .fin = fin } },
    });
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while ((if (pair.connection(.server).recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < header.len + body.len) try pair.receiveProgress(.server, deadline);
    return id;
}

test "WebTransport early STREAM quotas reject excess streams and retain the first owner" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        var state = early.State{ .limits = .{ .max_streams = 1 } };
        defer state.deinit(std.testing.allocator);
        const first = try open(&pair, direction, 32, "first", true);
        try std.testing.expect(!try state.poll(std.testing.allocator, pair.connection(.server), owners(&pair)));
        const second = try open(&pair, direction, 36, "excess", true);
        try std.testing.expect(try state.poll(std.testing.allocator, pair.connection(.server), owners(&pair)));
        try std.testing.expectEqual(@as(usize, 1), state.entries.items.len);
        try std.testing.expectEqual(first, state.entries.items[0].stream_id);
        try std.testing.expectEqual(@as(u64, 0), pair.connection(.server).recvStreamStats(first).?.bytes_read);
        try std.testing.expectEqual(webtransport.ApplicationErrorCode.buffered_stream_rejected, pair.connection(.server).recvStreamStats(second).?.stop_sending_sent.?.application_error_code);
        if (direction == .bidirectional) try std.testing.expectEqual(webtransport.ApplicationErrorCode.buffered_stream_rejected, pair.connection(.server).sendStreamStats(second).?.reset.?.application_error_code);
        try std.testing.expect(!pair.connection(.server).closed());
    }
}

test "WebTransport early STREAM byte quota includes out-of-order gaps" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var state = early.State{ .limits = .{ .max_bytes = 16 } };
    defer state.deinit(std.testing.allocator);
    const id = try open(&pair, .unidirectional, 32, "", false);
    try pair.connection(.client).send(&.{.{ .stream = .{ .stream_id = id, .offset = 131, .data = "z" } }});
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (pair.connection(.server).recvStreamStats(id).?.highest_received_offset < 132) try pair.receiveProgress(.server, deadline);
    try std.testing.expect(try state.poll(std.testing.allocator, pair.connection(.server), owners(&pair)));
    try std.testing.expectEqual(@as(usize, 0), state.entries.items.len);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.buffered_stream_rejected, pair.connection(.server).recvStreamStats(id).?.stop_sending_sent.?.application_error_code);
}

test "WebTransport early STREAM age starts at wire receipt before discovery" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try open(&pair, .unidirectional, 32, "old", false);
    try std.Io.sleep(threaded.io(), .fromMilliseconds(1), .awake);
    var state = early.State{ .limits = .{ .max_age = .fromNanoseconds(1) } };
    defer state.deinit(std.testing.allocator);
    try std.testing.expect(try state.poll(
        std.testing.allocator,
        pair.connection(.server),
        owners(&pair),
    ));
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.buffered_stream_rejected,
        pair.connection(.server).recvStreamStats(id).?.stop_sending_sent.?.application_error_code,
    );
}

test "WebTransport early STREAM expiry remains retryable after a failed cancellation send" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var state: early.State = .{};
    defer state.deinit(std.testing.allocator);
    const id = try open(&pair, .bidirectional, 32, "body", false);
    _ = try state.poll(std.testing.allocator, pair.connection(.server), owners(&pair));
    state.entries.items[0].received_ns -= state.limits.max_age.nanoseconds;
    const connection = pair.connection(.server);
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, state.poll(std.testing.allocator, connection, owners(&pair)));
    try std.testing.expect(state.pending != null and state.entries.items.len == 1);
    try std.testing.expectEqual(@as(u64, 0), connection.recvStreamStats(id).?.bytes_read);
    connection.endpoint.io = original_io;
    try std.testing.expect(try state.poll(std.testing.allocator, connection, owners(&pair)));
    try std.testing.expect(state.pending == null and state.entries.items.len == 0);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.buffered_stream_rejected, connection.recvStreamStats(id).?.stop_sending_sent.?.application_error_code);
    try std.testing.expect(connection.recvStreamStats(id).?.bytes_read >= 7);
}

test "WebTransport early STREAM rejection recognizes a fragmented later Session ID" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var state: early.State = .{};
    defer state.deinit(std.testing.allocator);
    const id: u62 = @intCast(try pair.connection(.client).openUnidirectionalStream());
    var storage: [16]u8 = undefined;
    const header = try prefix.header(.init(32), .unidirectional, &storage);
    try pair.connection(.client).send(&.{.{ .stream = .{ .stream_id = id, .data = header[0..2] } }});
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while ((if (pair.connection(.server).recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < 2) try pair.receiveProgress(.server, deadline);
    _ = try state.poll(std.testing.allocator, pair.connection(.server), owners(&pair));
    try std.testing.expect(state.entries.items.len == 1 and state.entries.items[0].header.session_id == null);
    try state.rejectSession(std.testing.allocator, pair.connection(.server), 32);
    try pair.connection(.client).send(&.{.{ .stream = .{ .stream_id = id, .offset = 2, .data = header[2..], .fin = true } }});
    while (pair.connection(.server).recvStreamStats(id).?.highest_received_offset < header.len) try pair.receiveProgress(.server, deadline);
    try std.testing.expect(try state.poll(std.testing.allocator, pair.connection(.server), owners(&pair)));
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, pair.connection(.server).recvStreamStats(id).?.stop_sending_sent.?.application_error_code);
}

test "WebTransport early STREAM discovery leaves application-owned payload headers untouched" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try pair.client.openUnidirectionalStream();
    try pair.client.sendStream(id, "x", false);
    var output: [16]u8 = undefined;
    _ = try pair.server.readStreamWithTimeout(&output, .fromSeconds(1));
    try pair.client.sendStream(id, "\x40\x54\x20payload", false);
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (pair.connection(.server).recvStreamStats(id).?.available_bytes < 10) try pair.receiveProgress(.server, deadline);
    var state: early.State = .{};
    defer state.deinit(std.testing.allocator);
    _ = try state.poll(std.testing.allocator, pair.connection(.server), owners(&pair));
    try std.testing.expectEqual(@as(usize, 0), state.entries.items.len);
    try std.testing.expect(pair.connection(.server).recvStreamStats(id).?.stop_sending_sent == null);
}

test "WebTransport early STREAM metadata allocation failure retains transport data for retry" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try open(&pair, .unidirectional, 32, "body", false);
    var state: early.State = .{};
    defer state.deinit(std.testing.allocator);
    var buffer: [0]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&buffer);
    try std.testing.expectError(error.OutOfMemory, state.poll(fixed.allocator(), pair.connection(.server), owners(&pair)));
    try std.testing.expect(state.entries.items.len == 0 and state.pending == null);
    try std.testing.expectEqual(@as(u64, 0), pair.connection(.server).recvStreamStats(id).?.bytes_read);
    try std.testing.expect(!try state.poll(std.testing.allocator, pair.connection(.server), owners(&pair)));
    try std.testing.expectEqual(@as(usize, 1), state.entries.items.len);
    try std.testing.expectEqual(@as(u64, 7), state.bytes);
}

test "WebTransport early STREAM invalid Session ID closes with H3_ID_ERROR" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const id: u62 = @intCast(switch (direction) {
            .bidirectional => try pair.connection(.client).tryOpenStream(),
            .unidirectional => try pair.connection(.client).openUnidirectionalStream(),
        });
        const data: []const u8 = if (direction == .bidirectional) "\x40\x41\x01" else "\x40\x54\x01";
        try pair.connection(.client).send(&.{.{ .stream = .{ .stream_id = id, .data = data } }});
        const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        while ((if (pair.connection(.server).recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < data.len) try pair.receiveProgress(.server, deadline);
        var state: early.State = .{};
        defer state.deinit(std.testing.allocator);
        try std.testing.expectError(error.InvalidSessionId, state.poll(std.testing.allocator, pair.connection(.server), owners(&pair)));
        try std.testing.expect(pair.connection(.server).closing());
        try std.testing.expectEqual(@import("../../../../http3/mod.zig").ApplicationErrorCode.id_error, quic.one_rtt.testing.localCloseInfo(pair.connection(.server)).?.error_code);
    }
}

test "WebTransport early STREAM cleanup preserves a previously submitted SESSION_GONE half" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try open(&pair, .bidirectional, 32, "body", false);
    const connection = pair.connection(.server);
    try connection.tryResetStream(id, webtransport.ApplicationErrorCode.session_gone);
    const before = connection.next_packet_number;
    try std.testing.expect(try @import("../rejection.zig").advance(connection, id, .bidirectional, webtransport.ApplicationErrorCode.buffered_stream_rejected, true));
    try std.testing.expectEqual(before + 1, connection.next_packet_number);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.recvStreamStats(id).?.stop_sending_sent.?.application_error_code);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.sendStreamStats(id).?.reset.?.application_error_code);
}
