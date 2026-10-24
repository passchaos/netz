const std = @import("std");
const webtransport = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const fixture = @import("../../session_control/test_support/handshake_pair.zig");
const header = @import("../header.zig");
const early = @import("../early_streams.zig");
const Pair = fixture.Pair;
const Role = fixture.Role;

test "WebTransport header FIN reordering preserves missing type and Session ID bytes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |receiver| {
        for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
            for ([_]bool{ false, true }) |missing_type| {
                var pair: Pair = undefined;
                try pair.init(threaded.io());
                defer pair.deinit();
                const sender = pair.connection(if (receiver == .client) .server else .client);
                const connection = pair.connection(receiver);
                const id: u62 = @intCast(if (direction == .bidirectional) try sender.tryOpenStream() else try sender.openUnidirectionalStream());
                // Session ID 0 in a two-byte varint. FIN establishes final
                // size 8 before the missing association bytes arrive.
                const bytes = [_]u8{ 0x40, if (direction == .bidirectional) 0x41 else 0x54, 0x40, 0x00, 'b', 'o', 'd', 'y' };
                if (missing_type) {
                    try sender.send(&.{.{ .stream = .{ .stream_id = id, .offset = 3, .data = bytes[3..], .fin = true } }});
                } else {
                    try sender.send(&.{
                        .{ .stream = .{ .stream_id = id, .data = bytes[0..3] } },
                        .{ .stream = .{ .stream_id = id, .offset = 4, .data = bytes[4..], .fin = true } },
                    });
                }
                const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
                while ((if (connection.recvStreamStats(id)) |stats| stats.final_size else null) == null) try pair.receiveProgress(receiver, deadline);
                const prefix = try header.peek(connection, id);
                if (missing_type) try std.testing.expect(prefix == null) else try std.testing.expect(prefix.?.session_id == null);
                var pending: early.State = .{};
                defer pending.deinit(std.testing.allocator);
                try std.testing.expect(!try pending.poll(std.testing.allocator, connection, .{ .sessions = .{ .context = &pair, .scope = 0, .containsFn = known } }));
                var output: [8]u8 = undefined;
                const available = if (receiver == .client) try pair.client.pollStream(&output) else try pair.server.pollStream(&output);
                try std.testing.expect(available == null and !connection.closing());
                if (missing_type) try sender.send(&.{.{ .stream = .{ .stream_id = id, .data = bytes[0..3] } }}) else try sender.send(&.{.{ .stream = .{ .stream_id = id, .offset = 3, .data = bytes[3..4] } }});
                const received = if (receiver == .client) try pair.client.readStreamIdWithTimeout(id, &output, .fromSeconds(1)) else try pair.server.readStreamIdWithTimeout(id, &output, .fromSeconds(1));
                try std.testing.expect(received == .data and received.data.fin);
                try std.testing.expectEqualStrings("body", output[0..received.data.bytes]);
                try std.testing.expect(!connection.closing());
            }
        }
    }
}

test "WebTransport header RESET before Session ID completion does not fabricate a FIN error" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |receiver| {
        for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
            var pair: Pair = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            const sender = pair.connection(if (receiver == .client) .server else .client);
            const connection = pair.connection(receiver);
            const id: u62 = @intCast(if (direction == .bidirectional) try sender.tryOpenStream() else try sender.openUnidirectionalStream());
            const bytes = [_]u8{ 0x40, if (direction == .bidirectional) 0x41 else 0x54, 0xc0 };
            // RESET_STREAM can erase an incomplete association before any WT
            // owner exists. Its final size must never become clean-FIN proof.
            try quic.one_rtt.testing.applyReceivedFrames(connection, 10, &.{
                .{ .stream = .{ .stream_id = id, .data = &bytes } },
                .{ .reset_stream = .{ .stream_id = id, .final_size = bytes.len, .application_error_code = 0 } },
            }, null, .not_ect);
            const parsed = (try header.peek(connection, id)) orelse return error.TestUnexpectedResult;
            try std.testing.expect(parsed.session_id == null);
            var pending: early.State = .{};
            defer pending.deinit(std.testing.allocator);
            try std.testing.expect(!try pending.poll(std.testing.allocator, connection, .{ .sessions = .{ .context = &pair, .scope = 0, .containsFn = known } }));
            try std.testing.expect(!connection.closing());
            var marker = [_]u8{ 0x00, 'o', 'k' };
            if (receiver == .client) {
                try pair.client.h3.connect_datagrams.route(&marker);
                var datagram = (try pair.client.pollDatagram()) orelse return error.TestUnexpectedResult;
                defer datagram.deinit(std.testing.allocator);
                try std.testing.expectEqualStrings("ok", datagram.datagram.payload);
            } else {
                try pair.server.h3.connect_datagrams.route(&marker);
                var datagram = (try pair.server.pollDatagram()) orelse return error.TestUnexpectedResult;
                defer datagram.deinit(std.testing.allocator);
                try std.testing.expectEqualStrings("ok", datagram.datagram.payload);
            }
        }
    }
}

fn known(_: *const anyopaque, _: u64, id: u62) bool {
    return id == 0;
}
