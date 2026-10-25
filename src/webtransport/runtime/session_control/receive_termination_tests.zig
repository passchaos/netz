const std = @import("std");
const support = @import("test_support/handshake_pair.zig");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");

fn peerTerminatesConnect(pair: *support.Pair, receiver: support.Role, reset: bool) !void {
    const sender = pair.connection(if (receiver == .client) .server else .client);
    if (reset) {
        try sender.tryResetStream(0, webtransport.ApplicationErrorCode.session_gone);
    } else {
        try sender.send(&.{.{ .stream = .{
            .stream_id = 0,
            .offset = sender.sendStreamStats(0).?.highest_sent_offset,
            .data = &.{},
            .fin = true,
        } }});
    }
    const connection = pair.connection(receiver);
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (connection.recvStreamStats(0).?.final_size == null) try pair.receiveProgress(receiver, deadline);
    try std.testing.expect(connection.sendStreamStats(0).?.final_size == null);
    try std.testing.expect(connection.sendStreamStats(0).?.reset == null);
}

fn blocksNewStreams(reset: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ true, false }) |session_flow| {
        var settings = webtransport.defaultSettings(.{});
        if (!session_flow) {
            settings.webtransport_initial_max_data = 0;
            settings.webtransport_initial_max_streams_bidi = 0;
            settings.webtransport_initial_max_streams_uni = 0;
        }
        for ([_]support.Role{ .client, .server }) |role| {
            var pair: support.Pair = undefined;
            try pair.initWithSettings(threaded.io(), settings, settings);
            defer pair.deinit();
            try std.testing.expectEqual(session_flow, pair.client.streams.flow != null);
            try std.testing.expectEqual(session_flow, pair.server.streams.flow != null);
            const existing = switch (role) {
                .client => try pair.client.openBidirectionalStream(),
                .server => try pair.server.openBidirectionalStream(),
            };
            try peerTerminatesConnect(&pair, role, reset);
            const before = pair.connection(role).next_packet_number;
            switch (role) {
                .client => {
                    try std.testing.expectError(error.InvalidSessionState, pair.client.openBidirectionalStream());
                    try std.testing.expectError(error.InvalidSessionState, pair.client.sendStream(existing, "late", false));
                    try std.testing.expectError(error.InvalidSessionState, pair.client.sendDatagram("late"));
                    try std.testing.expectError(error.ConnectDatagramAssociationClosed, pair.client.pollDatagram());
                },
                .server => {
                    try std.testing.expectError(error.InvalidSessionState, pair.server.openBidirectionalStream());
                    try std.testing.expectError(error.InvalidSessionState, pair.server.sendStream(existing, "late", false));
                    try std.testing.expectError(error.InvalidSessionState, pair.server.sendDatagram("late"));
                    try std.testing.expectError(error.ConnectDatagramAssociationClosed, pair.server.pollDatagram());
                },
            }
            try std.testing.expectEqual(before, pair.connection(role).next_packet_number);
            try std.testing.expect(!pair.control(role).terminal_reported);
            const event = try pair.receiveWithTimeout(role, .fromSeconds(1));
            if (reset) {
                try std.testing.expect(event == .reset);
                try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), event.reset.http3_code);
            } else {
                try std.testing.expect(event == .closed);
                try std.testing.expectEqual(@as(u32, 0), event.closed.code);
            }
            const registry = if (role == .client) &pair.client.streams else &pair.server.streams;
            try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), registry.get(existing).?.send_reset.?.http3_code);
        }
    }
}

test "WebTransport CONNECT peer FIN blocks fresh streams before Session event polling" {
    try blocksNewStreams(false);
}

test "WebTransport CONNECT peer RESET blocks fresh streams before Session event polling" {
    try blocksNewStreams(true);
}

test "WebTransport CONNECT peer FIN preserves buffered CLOSE across allocation failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]support.Role{ .client, .server }) |role| {
        var pair: support.Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        var bytes: [600]u8 = undefined;
        const reason = [_]u8{'r'} ** 512;
        const close = try control_mod.writeCloseInto(&bytes, 77, &reason);
        try pair.sendCapsules(role, close);
        try peerTerminatesConnect(&pair, role, false);
        const control = pair.control(role);
        const connection = pair.connection(role);
        try std.testing.expect(control.observeConnectReceive(connection));
        try std.testing.expectError(error.InvalidSessionState, control.ensureOpen());
        var no_alloc = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        control.allocator = no_alloc.allocator();
        defer control.allocator = std.testing.allocator;
        try std.testing.expectError(error.OutOfMemory, pair.receiveWithTimeout(role, .fromSeconds(1)));
        try std.testing.expect(no_alloc.has_induced_failure);
        try std.testing.expect(control.state.closed and !control.terminal_reported);
        control.allocator = std.testing.allocator;
        const event = try pair.receiveWithTimeout(role, .fromSeconds(1));
        try std.testing.expect(event == .closed);
        try std.testing.expectEqual(@as(u32, 77), event.closed.code);
        try std.testing.expectEqualSlices(u8, &reason, event.closed.reason);
        try std.testing.expect((try pair.poll(role)) == null);
        try std.testing.expect(!connection.closing());
    }
}

test "WebTransport CONNECT reordered peer FIN waits for missing control bytes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: support.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const sender = pair.connection(.server);
    const offset = sender.sendStreamStats(0).?.highest_sent_offset;
    try sender.send(&.{.{ .stream = .{ .stream_id = 0, .offset = offset + 2, .data = &.{}, .fin = true } }});
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    const connection = pair.connection(.client);
    while (connection.recvStreamStats(0).?.final_size == null) try pair.receiveProgress(.client, deadline);
    _ = try pair.client.openBidirectionalStream();
    try std.testing.expect(!pair.client.control.state.closed);
    // Two missing bytes complete an empty HTTP/3 DATA frame.
    try sender.send(&.{.{ .stream = .{ .stream_id = 0, .offset = offset, .data = &.{ 0, 0 } } }});
    while (connection.recvStreamStats(0).?.bytes_received != offset + 2) try pair.receiveProgress(.client, deadline);
    try std.testing.expectError(error.InvalidSessionState, pair.client.openBidirectionalStream());
    const event = try pair.client.receiveSessionEventWithTimeout(.fromSeconds(1));
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(@as(u32, 0), event.closed.code);
}

test "WebTransport CONNECT observed peer termination permits bounded close cleanup" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |reset| {
        for ([_]support.Role{ .client, .server }) |role| {
            var pair: support.Pair = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            const id = switch (role) {
                .client => try pair.client.openBidirectionalStream(),
                .server => try pair.server.openBidirectionalStream(),
            };
            try peerTerminatesConnect(&pair, role, reset);
            try std.testing.expect(pair.control(role).observeConnectReceive(pair.connection(role)));
            switch (role) {
                .client => try pair.client.closeWithTimeout(999, "cleanup", .fromSeconds(1)),
                .server => try pair.server.closeWithTimeout(999, "cleanup", .fromSeconds(1)),
            }
            const event = try pair.receiveWithTimeout(role, .fromSeconds(1));
            if (reset) {
                try std.testing.expect(event == .reset);
                try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), event.reset.http3_code);
            } else {
                try std.testing.expect(event == .closed);
                try std.testing.expectEqual(@as(u32, 0), event.closed.code);
            }
            const registry = if (role == .client) &pair.client.streams else &pair.server.streams;
            try std.testing.expect(registry.get(id).?.send_reset != null);
        }
    }
}
