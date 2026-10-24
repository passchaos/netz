const std = @import("std");
const webtransport = @import("../../../mod.zig");
const association = @import("../../stream_association.zig");
test {
    _ = @import("datagram_abandoned.zig");
}
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;
const Role = @import("../../session_control/test_support/handshake_pair.zig").Role;
const DatagramReader = enum { owned, into, poll };

fn expectDatagramViolation(session: anytype, reader: DatagramReader, deadline: std.Io.Clock.Timestamp) !void {
    switch (reader) {
        .owned => try std.testing.expectError(error.FlowControlViolation, session.receiveDatagramWithDeadline(deadline)),
        .into => {
            var output: [16]u8 = undefined;
            try std.testing.expectError(error.FlowControlViolation, session.receiveDatagramIntoWithDeadline(&output, deadline));
        },
        .poll => try std.testing.expectError(error.FlowControlViolation, session.pollDatagram()),
    }
}

test "WebTransport automatic association keeps whole and incremental reader choices" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |whole| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const id = try pair.client.openUnidirectionalStream();
        try pair.client.sendStream(id, "body", true);
        try pair.client.sendDatagram("marker");
        var marker = try pair.server.receiveDatagramWithTimeout(.fromSeconds(1));
        defer marker.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("marker", marker.datagram.payload);
        const stream = pair.server.streams.get(id) orelse return error.TestUnexpectedResult;
        try std.testing.expect(stream.receive_mode == .unset);
        try std.testing.expectEqual(@as(u64, 4), pair.server.streams.flow.?.received.data);
        try std.testing.expectEqual(@as(u64, 0), pair.connection(.server).recvStreamStats(id).?.bytes_read);
        if (whole) {
            var received = try pair.server.receiveStreamWithTimeout(.fromSeconds(1));
            defer received.deinit();
            try std.testing.expectEqualStrings("body", received.payload);
        } else {
            var output: [16]u8 = undefined;
            const received = try pair.server.readStreamWithTimeout(&output, .fromSeconds(1));
            try std.testing.expect(received == .data and received.data.stream_id == id and received.data.fin);
            try std.testing.expectEqualStrings("body", output[0..received.data.bytes]);
        }
    }
}

test "WebTransport automatic association detects data violations while waiting only for DATAGRAM" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var settings = webtransport.defaultSettings(.{});
    settings.webtransport_initial_max_data = 1;
    for ([_]Role{ .client, .server }) |receiver| {
        for ([_]DatagramReader{ .owned, .into, .poll }) |reader| {
            for ([_]bool{ false, true }) |buffered| {
                if (reader == .poll and !buffered) continue;
                var pair: Pair = undefined;
                try pair.initWithSettings(threaded.io(), settings, settings);
                defer pair.deinit();
                const sender: Role = if (receiver == .client) .server else .client;
                const id = switch (sender) {
                    .client => try pair.client.openUnidirectionalStream(),
                    .server => try pair.server.openUnidirectionalStream(),
                };
                var storage: [16]u8 = undefined;
                const prefix = try @import("../../stream/prefix.zig").header(pair.client.session_id, .unidirectional, &storage);
                // Both frames arrive in the same QUIC packet. A ready DATAGRAM
                // must not skip discovery/accounting of the associated STREAM.
                try pair.connection(sender).send(&.{
                    .{ .stream = .{ .stream_id = id, .data = prefix } },
                    .{ .stream = .{ .stream_id = id, .offset = prefix.len, .data = "too much", .fin = true } },
                    .{ .datagram = .{ .data = "\x00marker" } },
                });
                const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
                if (buffered) {
                    while ((if (pair.connection(receiver).recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < prefix.len + 8) try pair.receiveProgress(receiver, deadline);
                }
                switch (receiver) {
                    .client => {
                        try expectDatagramViolation(&pair.client, reader, deadline);
                        try std.testing.expect(pair.client.streams.flow_violation);
                    },
                    .server => {
                        try expectDatagramViolation(&pair.server, reader, deadline);
                        try std.testing.expect(pair.server.streams.flow_violation);
                    },
                }
                try std.testing.expectEqual(webtransport.ApplicationErrorCode.flow_control_error, pair.connection(receiver).sendStreamStats(0).?.reset.?.application_error_code);
                try std.testing.expect(!pair.connection(receiver).closing());
            }
        }
    }
}

test "WebTransport automatic association enforces stream limits before DATAGRAM delivery" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var settings = webtransport.defaultSettings(.{});
    settings.webtransport_initial_max_streams_bidi = 1;
    settings.webtransport_initial_max_streams_uni = 1;
    for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
        var pair: Pair = undefined;
        try pair.initWithSettings(threaded.io(), settings, settings);
        defer pair.deinit();
        const connection = pair.connection(.client);
        // Bypass the compliant Session sender to inject a peer opening beyond
        // the negotiated WT_MAX_STREAMS limit while QUIC still permits it.
        const first = switch (direction) {
            .bidirectional => try connection.tryOpenStream(),
            .unidirectional => try connection.openUnidirectionalStream(),
        };
        const second = switch (direction) {
            .bidirectional => try connection.tryOpenStream(),
            .unidirectional => try connection.openUnidirectionalStream(),
        };
        var storage: [16]u8 = undefined;
        const prefix = try @import("../../stream/prefix.zig").header(pair.client.session_id, direction, &storage);
        try connection.send(&.{
            .{ .stream = .{ .stream_id = first, .data = prefix } },
            .{ .stream = .{ .stream_id = second, .data = prefix } },
            .{ .datagram = .{ .data = "\x00marker" } },
        });
        var output: [16]u8 = undefined;
        try std.testing.expectError(error.FlowControlViolation, pair.server.receiveDatagramIntoWithTimeout(&output, .fromSeconds(1)));
        try std.testing.expect(pair.server.streams.flow_violation);
        try std.testing.expectEqual(webtransport.ApplicationErrorCode.flow_control_error, pair.connection(.server).sendStreamStats(0).?.reset.?.application_error_code);
        try std.testing.expect(!pair.connection(.server).closing());
    }
}

test "WebTransport automatic association preserves a later RESET event and final-size accounting" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try pair.client.openUnidirectionalStream();
    try pair.client.sendStream(id, "body", false);
    try pair.client.sendDatagram("before");
    var before = try pair.server.receiveDatagramWithTimeout(.fromSeconds(1));
    defer before.deinit(std.testing.allocator);
    try std.testing.expect(pair.server.streams.get(id).?.receive_mode == .unset);
    try pair.client.resetStream(id, 71);
    try pair.client.sendDatagram("after");
    var after = try pair.server.receiveDatagramWithTimeout(.fromSeconds(1));
    defer after.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("after", after.datagram.payload);
    var output: [16]u8 = undefined;
    const event = try pair.server.readStreamWithTimeout(&output, .fromSeconds(1));
    try std.testing.expect(event == .reset and event.reset.stream_id == id);
    try std.testing.expectEqual(@as(?u32, 71), event.reset.error_info.application_code);
    try std.testing.expectEqual(@as(u64, 4), pair.server.streams.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 4), pair.server.streams.flow.?.consumed_data);
}

test "WebTransport automatic association does not consume a prefix twice after STOP abandonment" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try pair.client.openBidirectionalStream();
    try pair.client.sendStream(id, "body", false);
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while ((if (pair.connection(.server).recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < 7) try pair.receiveProgress(.server, deadline);
    try association.discoverBuffered(pair.connection(.server), &pair.server.streams);
    try pair.server.stopStream(id, 72);
    try std.testing.expect(pair.connection(.server).recvStreamStats(id).?.bytes_read >= 3);
    _ = try association.identifyOnce(pair.connection(.server), &pair.server.streams, pair.server.session_id, id, .incremental);
    try std.testing.expectEqual(@as(usize, 0), pair.server.streams.get(id).?.receive_prefix_len);
}
