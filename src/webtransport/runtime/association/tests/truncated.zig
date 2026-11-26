const std = @import("std");
const webtransport = @import("../../../mod.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");
const fixture = @import("../../session_control/test_support/handshake_pair.zig");
const early = @import("../early_streams.zig");
const Pair = fixture.Pair;
const Role = fixture.Role;
const ObservedBatchSend = @import("../../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;
test {
    _ = @import("header_reordering.zig");
}

const Reader = enum { whole, incremental, datagram, datagram_into, poll_whole, poll_incremental, poll_datagram, early };

test "WebTransport truncated Session ID on clean FIN closes with H3_FRAME_ERROR" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |receiver| {
        for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
            for (std.enums.values(Reader)) |reader| {
                for ([_][]const u8{ "", "\x40", "\x80\x00", "\xc0\x00\x00" }) |session_bytes| {
                    var pair: Pair = undefined;
                    try pair.init(threaded.io());
                    defer pair.deinit();
                    const sender = pair.connection(if (receiver == .server) .client else .server);
                    const connection = pair.connection(receiver);
                    const id: u62 = @intCast(if (direction == .bidirectional) try sender.tryOpenStream() else try sender.openUnidirectionalStream());
                    var bytes: [16]u8 = undefined;
                    bytes[0] = 0x40;
                    bytes[1] = if (direction == .bidirectional) 0x41 else 0x54;
                    @memcpy(bytes[2..][0..session_bytes.len], session_bytes);
                    try sender.send(&.{.{ .stream = .{ .stream_id = id, .data = bytes[0 .. 2 + session_bytes.len], .fin = true } }});
                    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
                    while ((if (connection.recvStreamStats(id)) |stats| stats.final_size else null) == null) try pair.receiveProgress(receiver, deadline);
                    if (reader == .early) {
                        var pending: early.State = .{};
                        defer pending.deinit(std.testing.allocator);
                        try std.testing.expectError(error.BufferTooShort, pending.poll(std.testing.allocator, connection, .{ .sessions = .{ .context = &pair, .scope = 0, .containsFn = known } }));
                        try std.testing.expectEqual(@as(usize, 0), pending.entries.items.len);
                    } else switch (receiver) {
                        .client => try expectTruncated(&pair.client, reader),
                        .server => try expectTruncated(&pair.server, reader),
                    }
                    const close = quic.one_rtt.testing.localCloseInfo(connection) orelse return error.TestUnexpectedResult;
                    try std.testing.expect(close.application);
                    try std.testing.expectEqual(http3.ApplicationErrorCode.frame_error, close.error_code);
                    const registry = if (receiver == .client) &pair.client.streams else &pair.server.streams;
                    try std.testing.expect(registry.get(id) == null);
                }
            }
        }
    }
}

fn known(_: *const anyopaque, _: u64, id: u62) bool {
    return id == 0;
}

fn expectTruncated(session: anytype, reader: Reader) !void {
    var output: [16]u8 = undefined;
    switch (reader) {
        .whole => try std.testing.expectError(error.BufferTooShort, session.receiveStreamWithTimeout(.fromSeconds(1))),
        .incremental => try std.testing.expectError(error.BufferTooShort, session.readStreamWithTimeout(&output, .fromSeconds(1))),
        .datagram => try std.testing.expectError(error.BufferTooShort, session.receiveDatagramWithTimeout(.fromSeconds(1))),
        .datagram_into => try std.testing.expectError(error.BufferTooShort, session.receiveDatagramIntoWithTimeout(&output, .fromSeconds(1))),
        .poll_whole => try std.testing.expectError(error.BufferTooShort, session.pollCompleteStream()),
        .poll_incremental => try std.testing.expectError(error.BufferTooShort, session.pollStream(&output)),
        .poll_datagram => try std.testing.expectError(error.BufferTooShort, session.pollDatagram()),
        .early => unreachable,
    }
}

test "WebTransport early truncated Session ID after buffering closes despite socket failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const sender = pair.connection(.client);
    const connection = pair.connection(.server);
    const id: u62 = @intCast(try sender.tryOpenStream());
    const bytes = "\x40\x41\xc0";
    try sender.send(&.{.{ .stream = .{ .stream_id = id, .data = bytes } }});
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while ((if (connection.recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < bytes.len) try pair.receiveProgress(.server, deadline);
    var pending: early.State = .{};
    defer pending.deinit(std.testing.allocator);
    const owners: early.Owners = .{ .sessions = .{ .context = &pair, .scope = 0, .containsFn = known } };
    try std.testing.expect(!try pending.poll(std.testing.allocator, connection, owners));
    try std.testing.expectEqual(@as(usize, 1), pending.entries.items.len);
    try std.testing.expect(pending.entries.items[0].header.session_id == null);
    // A later empty FIN proves that the eight-byte Session ID cannot fit.
    try sender.send(&.{.{ .stream = .{ .stream_id = id, .offset = bytes.len, .data = "", .fin = true } }});
    while (connection.recvStreamStats(id).?.final_size == null) try pair.receiveProgress(.server, deadline);
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.BufferTooShort, pending.poll(std.testing.allocator, connection, owners));
    try std.testing.expectEqual(@as(usize, 1), observed.calls);
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(http3.ApplicationErrorCode.frame_error, quic.one_rtt.testing.localCloseInfo(connection).?.error_code);
    try std.testing.expectEqual(@as(u64, 0), connection.recvStreamStats(id).?.bytes_read);
    try std.testing.expect(pair.server.streams.get(id) == null);
}
