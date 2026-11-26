const std = @import("std");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");
const webtransport = @import("../../../mod.zig");
const fixture = @import("../../session_control/test_support/handshake_pair.zig");
const Pair = fixture.Pair;
const Role = fixture.Role;
const ObservedBatchSend = @import("../../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;
test {
    _ = @import("truncated.zig");
}

const Reader = enum {
    whole,
    incremental,
    poll_whole,
    poll_incremental,
    datagram,
    datagram_into,
    poll_datagram,
};

fn expectInvalid(session: anytype, reader: Reader) !void {
    var output: [16]u8 = undefined;
    switch (reader) {
        .whole => try std.testing.expectError(error.InvalidSessionId, session.receiveStreamWithTimeout(.fromSeconds(1))),
        .incremental => try std.testing.expectError(error.InvalidSessionId, session.readStreamWithTimeout(&output, .fromSeconds(1))),
        .poll_whole => try std.testing.expectError(error.InvalidSessionId, session.pollCompleteStream()),
        .poll_incremental => try std.testing.expectError(error.InvalidSessionId, session.pollStream(&output)),
        .datagram => try std.testing.expectError(error.InvalidSessionId, session.receiveDatagramWithTimeout(.fromSeconds(1))),
        .datagram_into => try std.testing.expectError(error.InvalidSessionId, session.receiveDatagramIntoWithTimeout(&output, .fromSeconds(1))),
        .poll_datagram => try std.testing.expectError(error.InvalidSessionId, session.pollDatagram()),
    }
}

fn checkReaders(readers: []const Reader, fail_close: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |receiver| {
        for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
            for (readers) |reader| {
                var pair: Pair = undefined;
                try pair.init(threaded.io());
                defer pair.deinit();
                const sender = pair.connection(if (receiver == .client) .server else .client);
                const id: u62 = @intCast(switch (direction) {
                    .bidirectional => try sender.tryOpenStream(),
                    .unidirectional => try sender.openUnidirectionalStream(),
                });
                const data: []const u8 = if (direction == .bidirectional) "\x40\x41\x01body" else "\x40\x54\x01body";
                // Bypass the compliant WebTransport sender. The ready DATAGRAM
                // must not allow automatic discovery to skip the invalid ID.
                try sender.send(&.{
                    .{ .stream = .{ .stream_id = id, .data = data, .fin = true } },
                    .{ .datagram = .{ .data = "\x00marker" } },
                });
                const connection = pair.connection(receiver);
                const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
                while ((if (connection.recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < data.len) try pair.receiveProgress(receiver, deadline);
                const original_io = connection.endpoint.io;
                var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
                if (fail_close) connection.endpoint.io = observed.io();
                defer connection.endpoint.io = original_io;
                switch (receiver) {
                    .client => try expectInvalid(&pair.client, reader),
                    .server => try expectInvalid(&pair.server, reader),
                }
                try std.testing.expect(connection.closing());
                const close = quic.one_rtt.testing.localCloseInfo(connection) orelse return error.TestUnexpectedResult;
                try std.testing.expectEqual(http3.ApplicationErrorCode.id_error, close.error_code);
                if (fail_close) try std.testing.expectEqual(@as(usize, 1), observed.calls);
                // A malformed association never consumes application data or
                // creates an owning registry entry before connection rejection.
                try std.testing.expectEqual(@as(u64, 0), connection.recvStreamStats(id).?.bytes_read);
                const registered = switch (receiver) {
                    .client => pair.client.streams.index.contains(id),
                    .server => pair.server.streams.index.contains(id),
                };
                try std.testing.expect(!registered);
            }
        }
    }
}

test "WebTransport owning stream readers invalid Session ID closes with H3_ID_ERROR" {
    try checkReaders(&.{ .whole, .incremental }, false);
}

test "WebTransport stream polls invalid Session ID closes with H3_ID_ERROR" {
    try checkReaders(&.{ .poll_whole, .poll_incremental }, false);
}

test "WebTransport DATAGRAM discovery invalid Session ID closes with H3_ID_ERROR" {
    try checkReaders(&.{ .datagram, .datagram_into, .poll_datagram }, false);
}

test "WebTransport invalid Session ID closes with H3_ID_ERROR despite a socket failure" {
    try checkReaders(&.{ .poll_incremental, .poll_datagram }, true);
}

test "WebTransport fragmented invalid Session ID closes only after its varint completes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |receiver| {
        for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
            var pair: Pair = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            const sender = pair.connection(if (receiver == .client) .server else .client);
            const id: u62 = @intCast(switch (direction) {
                .bidirectional => try sender.tryOpenStream(),
                .unidirectional => try sender.openUnidirectionalStream(),
            });
            // Session ID 1 encoded in two bytes. The first byte alone must
            // remain unclaimed until the varint's final byte arrives.
            const data: []const u8 = if (direction == .bidirectional) "\x40\x41\x40\x01" else "\x40\x54\x40\x01";
            try sender.send(&.{.{ .stream = .{ .stream_id = id, .data = data[0..3] } }});
            const connection = pair.connection(receiver);
            const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            while ((if (connection.recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < 3) try pair.receiveProgress(receiver, deadline);
            var output: [16]u8 = undefined;
            const incomplete = switch (receiver) {
                .client => try pair.client.pollStream(&output),
                .server => try pair.server.pollStream(&output),
            };
            try std.testing.expect(incomplete == null and !connection.closing());
            try std.testing.expectEqual(@as(u64, 0), connection.recvStreamStats(id).?.bytes_read);
            try sender.send(&.{.{ .stream = .{ .stream_id = id, .offset = 3, .data = data[3..], .fin = true } }});
            while (connection.recvStreamStats(id).?.highest_received_offset < data.len) try pair.receiveProgress(receiver, deadline);
            switch (receiver) {
                .client => try expectInvalid(&pair.client, .poll_incremental),
                .server => try expectInvalid(&pair.server, .poll_incremental),
            }
            try std.testing.expect(connection.closing());
            try std.testing.expectEqual(http3.ApplicationErrorCode.id_error, quic.one_rtt.testing.localCloseInfo(connection).?.error_code);
        }
    }
}
