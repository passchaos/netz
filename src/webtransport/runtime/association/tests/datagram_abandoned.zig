const std = @import("std");
const webtransport = @import("../../../mod.zig");
const Role = @import("../../session_control/test_support/handshake_pair.zig").Role;
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;

const Reader = enum { owned, into, poll, write };

test "WebTransport DATAGRAM maintenance settles reset DATA credit and preserves its event" {
    for ([_]Role{ .client, .server }) |receiver| {
        for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
            for ([_]Reader{ .owned, .into, .poll }) |reader| try exercise(receiver, direction, reader);
        }
    }
}

test "WebTransport sibling stream writes maintain abandoned receive credit without stream reads" {
    for ([_]Role{ .client, .server }) |receiver| {
        for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| try exercise(receiver, direction, .write);
    }
}

fn exercise(receiver: Role, direction: webtransport.StreamDirection, reader: Reader) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var settings = webtransport.defaultSettings(.{});
    settings.webtransport_initial_max_data = 4;
    var pair: Pair = undefined;
    try pair.initWithSettings(io, settings, settings);
    defer pair.deinit();
    const id = switch (receiver) {
        .server => if (direction == .bidirectional) try pair.client.openBidirectionalStream() else try pair.client.openUnidirectionalStream(),
        .client => if (direction == .bidirectional) try pair.server.openBidirectionalStream() else try pair.server.openUnidirectionalStream(),
    };
    switch (receiver) {
        .server => {
            try pair.client.sendStream(id, "body", false);
            try pair.client.sendDatagram("before");
        },
        .client => {
            try pair.server.sendStream(id, "body", false);
            try pair.server.sendDatagram("before");
        },
    }
    try receive(&pair, receiver, .owned, "before");
    const registry = if (receiver == .server) &pair.server.streams else &pair.client.streams;
    try std.testing.expect(registry.get(id).?.receive_mode == .unset);
    try std.testing.expectEqual(@as(u64, 4), registry.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 0), registry.flow.?.consumed_data);
    switch (receiver) {
        .server => {
            try pair.client.resetStream(id, 71);
            try pair.client.sendDatagram("after");
        },
        .client => {
            try pair.server.resetStream(id, 71);
            try pair.server.sendDatagram("after");
        },
    }
    if (reader == .poll or reader == .write) {
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake });
        const h3 = if (receiver == .server) &pair.server.h3.connect_datagrams else &pair.client.h3.connect_datagrams;
        while (pair.connection(receiver).recvStreamStats(id).?.reset == null or try h3.queuedCount(0) == 0) try pair.receiveProgress(receiver, deadline);
    }
    try receive(&pair, receiver, reader, "after");
    try std.testing.expectEqual(@as(u64, 4), registry.flow.?.consumed_data);
    try std.testing.expectEqual(@as(u64, 8), registry.flow.?.receive_limit.data);
    // The sender exhausted its initial Session budget. A new stream write
    // can continue only once the DATAGRAM receiver emitted WT_MAX_DATA.
    var committed: usize = 99;
    const sibling = switch (receiver) {
        .server => if (direction == .bidirectional) try pair.client.openBidirectionalStream() else try pair.client.openUnidirectionalStream(),
        .client => if (direction == .bidirectional) try pair.server.openBidirectionalStream() else try pair.server.openUnidirectionalStream(),
    };
    switch (receiver) {
        .server => try pair.client.sendStreamWithTimeout(sibling, "next", true, &committed, .fromSeconds(1)),
        .client => try pair.server.sendStreamWithTimeout(sibling, "next", true, &committed, .fromSeconds(1)),
    }
    try std.testing.expectEqual(@as(usize, 4), committed);
    var output: [8]u8 = undefined;
    const event = if (receiver == .server) try pair.server.readStreamWithTimeout(&output, .fromSeconds(1)) else try pair.client.readStreamWithTimeout(&output, .fromSeconds(1));
    try std.testing.expect(event == .reset and event.reset.stream_id == id);
    try std.testing.expectEqual(@as(?u32, 71), event.reset.error_info.application_code);
    var received: usize = 0;
    while (true) {
        const data = if (receiver == .server) try pair.server.readStreamIdWithTimeout(sibling, &output, .fromSeconds(1)) else try pair.client.readStreamIdWithTimeout(sibling, &output, .fromSeconds(1));
        try std.testing.expect(data == .data and data.data.stream_id == sibling);
        try std.testing.expectEqualStrings("next"[received..][0..data.data.bytes], output[0..data.data.bytes]);
        received += data.data.bytes;
        if (data.data.fin) break;
    }
    try std.testing.expectEqual(@as(usize, 4), received);
    try std.testing.expect(!pair.connection(receiver).closing());
}

fn receive(pair: *Pair, receiver: Role, reader: Reader, expected: []const u8) !void {
    switch (reader) {
        .owned => {
            var datagram = if (receiver == .server) try pair.server.receiveDatagramWithTimeout(.fromSeconds(1)) else try pair.client.receiveDatagramWithTimeout(.fromSeconds(1));
            defer datagram.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings(expected, datagram.datagram.payload);
        },
        .into => {
            var output: [16]u8 = undefined;
            const data = if (receiver == .server) try pair.server.receiveDatagramIntoWithTimeout(&output, .fromSeconds(1)) else try pair.client.receiveDatagramIntoWithTimeout(&output, .fromSeconds(1));
            try std.testing.expectEqualStrings(expected, data);
        },
        .poll => {
            var datagram = (if (receiver == .server) try pair.server.pollDatagram() else try pair.client.pollDatagram()) orelse return error.TestUnexpectedResult;
            defer datagram.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings(expected, datagram.datagram.payload);
        },
        .write => {
            // This owner only sends on a different associated stream. Its
            // ordinary maintenance must settle received reset bytes without
            // making the application poll the abandoned stream first.
            const id = if (receiver == .server) try pair.server.openUnidirectionalStream() else try pair.client.openUnidirectionalStream();
            var committed: usize = 0;
            if (receiver == .server) try pair.server.sendStreamWithTimeout(id, "sent", true, &committed, .fromSeconds(1)) else try pair.client.sendStreamWithTimeout(id, "sent", true, &committed, .fromSeconds(1));
            try std.testing.expectEqual(@as(usize, 4), committed);
        },
    }
}

test "WebTransport DATAGRAM maintenance preserves a reliable application prefix before RESET" {
    for ([_]Role{ .client, .server }) |receiver| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const id = if (receiver == .server) try pair.client.openUnidirectionalStream() else try pair.server.openUnidirectionalStream();
        if (receiver == .server) {
            try pair.client.sendStream(id, "body", false);
            try pair.client.sendDatagram("before");
        } else {
            try pair.server.sendStream(id, "body", false);
            try pair.server.sendDatagram("before");
        }
        try receive(&pair, receiver, .owned, "before");
        if (receiver == .server) {
            try pair.client.resetStreamReliablyWithTimeout(id, 71, 2, .fromSeconds(1));
            try pair.client.sendDatagram("after");
        } else {
            try pair.server.resetStreamReliablyWithTimeout(id, 71, 2, .fromSeconds(1));
            try pair.server.sendDatagram("after");
        }
        try receive(&pair, receiver, .owned, "after");
        const registry = if (receiver == .server) &pair.server.streams else &pair.client.streams;
        try std.testing.expectEqual(@as(u64, 4), registry.flow.?.received.data);
        try std.testing.expectEqual(@as(u64, 0), registry.flow.?.consumed_data);
        try std.testing.expect(registry.get(id).?.receive_reset == null);
        var output: [8]u8 = undefined;
        const prefix = if (receiver == .server) try pair.server.readStreamIdWithTimeout(id, &output, .fromSeconds(1)) else try pair.client.readStreamIdWithTimeout(id, &output, .fromSeconds(1));
        try std.testing.expect(prefix == .data and prefix.data.bytes == 2 and !prefix.data.fin);
        try std.testing.expectEqualStrings("bo", output[0..2]);
        const reset = if (receiver == .server) try pair.server.readStreamIdWithTimeout(id, &output, .fromSeconds(1)) else try pair.client.readStreamIdWithTimeout(id, &output, .fromSeconds(1));
        try std.testing.expect(reset == .reset and reset.reset.error_info.application_code == 71);
        try std.testing.expectEqual(@as(u64, 4), registry.flow.?.consumed_data);
    }
}
