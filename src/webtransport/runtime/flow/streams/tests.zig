const std = @import("std");
const webtransport = @import("../../../mod.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;

fn init(pair: *Pair, io: std.Io) !void {
    var settings = webtransport.defaultSettings(.{});
    settings.webtransport_initial_max_streams_bidi = 1;
    settings.webtransport_initial_max_streams_uni = 1;
    try pair.initWithSettings(io, settings, settings);
    for ([_]*webtransport.StreamRegistry{ &pair.client.streams, &pair.server.streams }) |registry| {
        registry.max_local_bidi = 1;
        registry.max_local_uni = 1;
        registry.max_peer_bidi = 1;
        registry.max_peer_uni = 1;
    }
}

fn runClient(pair: *Pair, direction: webtransport.StreamDirection, iterations: usize) !void {
    var out: [16]u8 = undefined;
    for (0..iterations) |index| {
        const id = switch (direction) {
            .bidirectional => try pair.client.openBidirectionalStreamWithTimeout(.fromSeconds(2)),
            .unidirectional => try pair.client.openUnidirectionalStreamWithTimeout(.fromSeconds(2)),
        };
        const payload = [_]u8{@intCast(index)};
        var committed: usize = 0;
        try pair.client.sendStreamWithTimeout(id, &payload, true, &committed, .fromSeconds(2));
        try std.testing.expectEqual(@as(usize, 1), committed);
        if (direction == .bidirectional) {
            const deadline = std.Io.Clock.Timestamp.fromNow(pair.connection(.client).endpoint.io, .{ .raw = .fromSeconds(2), .clock = .awake });
            while (true) {
                const event = try pair.client.readStreamIdWithDeadline(id, &out, deadline);
                try std.testing.expect(event == .data and event.data.bytes == 0);
                if (event.data.fin) break;
            }
        }
        try std.testing.expect(pair.client.streams.registered().len <= 1);
    }
}

fn exchange(pair: *Pair, direction: webtransport.StreamDirection, iterations: usize, whole: bool) !void {
    const Worker = struct {
        pair: *Pair,
        direction: webtransport.StreamDirection,
        iterations: usize,
        whole: bool,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var out: [16]u8 = undefined;
            for (0..self.iterations) |index| {
                var count: usize = 0;
                var stream_id: ?u62 = null;
                const deadline = std.Io.Clock.Timestamp.fromNow(self.pair.connection(.server).endpoint.io, .{ .raw = .fromSeconds(2), .clock = .awake });
                if (self.whole) {
                    var message = try self.pair.server.receiveStreamWithDeadline(deadline);
                    defer message.deinit();
                    stream_id = message.stream_id;
                    try std.testing.expectEqual(self.direction, message.direction);
                    try std.testing.expectEqual(@as(usize, 1), message.payload.len);
                    try std.testing.expectEqual(@as(u8, @intCast(index)), message.payload[0]);
                    count = message.payload.len;
                } else {
                    while (true) {
                        const event = try self.pair.server.readStreamWithDeadline(&out, deadline);
                        try std.testing.expect(event == .data and event.data.direction == self.direction);
                        if (stream_id) |id| try std.testing.expectEqual(id, event.data.stream_id);
                        stream_id = event.data.stream_id;
                        try std.testing.expect(count + event.data.bytes <= 1);
                        if (event.data.bytes != 0) try std.testing.expectEqual(@as(u8, @intCast(index)), out[0]);
                        count += event.data.bytes;
                        if (event.data.fin) break;
                    }
                }
                try std.testing.expectEqual(@as(usize, 1), count);
                if (self.direction == .bidirectional) try self.pair.server.finishStream(stream_id.?);
                try std.testing.expect(self.pair.server.streams.registered().len <= 1);
            }
        }
    };
    var worker = Worker{ .pair = pair, .direction = direction, .iterations = iterations, .whole = whole };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    var client_error: ?anyerror = null;
    runClient(pair, direction, iterations) catch |err| {
        client_error = err;
    };
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    if (client_error) |err| return err;
    const opened, const received, const retired = switch (direction) {
        .bidirectional => .{ pair.client.streams.opened_local_bidi, pair.server.streams.opened_peer_bidi, pair.server.streams.flow.?.retired_peer.bidi },
        .unidirectional => .{ pair.client.streams.opened_local_uni, pair.server.streams.opened_peer_uni, pair.server.streams.flow.?.retired_peer.uni },
    };
    try std.testing.expectEqual(@as(u64, iterations), opened);
    try std.testing.expectEqual(@as(u64, iterations), received);
    try std.testing.expect(retired >= iterations - 1);
    try std.testing.expectEqual(@as(u64, iterations), pair.client.streams.flow.?.sent.data);
    try std.testing.expectEqual(@as(u64, iterations), pair.server.streams.flow.?.received.data);
}

test "WebTransport flow stream grants sustain bidi and uni sessions with one retained slot" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
        var pair: Pair = undefined;
        try init(&pair, threaded.io());
        defer pair.deinit();
        try exchange(&pair, direction, 32, false);
    }
}

const DropGrant = struct {
    delegate: std.Io,
    flow: *webtransport.flow_control.State,
    dropped: bool = false,

    fn netSend(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        if (!self.dropped and self.flow.retired_peer.uni == 1 and self.flow.receive_limit.uni == 1) {
            self.dropped = true;
            return .{ null, messages.len };
        }
        return self.delegate.vtable.netSend(self.delegate.userdata, socket, messages, flags);
    }
};

test "WebTransport flow lost stream grant recovers while owning reader waits for next stream" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try init(&pair, threaded.io());
    defer pair.deinit();
    const conn = pair.connection(.server);
    const original_io = conn.endpoint.io;
    var drop = DropGrant{ .delegate = original_io, .flow = pair.server.streams.flow.? };
    var vtable = original_io.vtable.*;
    vtable.netSend = DropGrant.netSend;
    conn.endpoint.io = .{ .userdata = &drop, .vtable = &vtable };
    defer conn.endpoint.io = original_io;
    try exchange(&pair, .unidirectional, 8, false);
    try std.testing.expect(drop.dropped);
}

test "WebTransport flow pending reset survives transport reclaim and returns stream credit once" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try init(&pair, threaded.io());
    defer pair.deinit();
    const cancelled = try pair.client.openUnidirectionalStream();
    try pair.client.sendStream(cancelled, "reset", false);
    var out: [16]u8 = undefined;
    const initial = try pair.server.readStreamWithTimeout(&out, .fromSeconds(1));
    try std.testing.expect(initial == .data and !initial.data.fin);
    try pair.client.resetStream(cancelled, 42);
    const sibling = try pair.client.openBidirectionalStream();
    try pair.client.sendStream(sibling, "stay", false);
    const event = try pair.server.readStreamIdWithTimeout(sibling, &out, .fromSeconds(1));
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings("stay", out[0..event.data.bytes]);
    try std.testing.expect(pair.connection(.server).peerStreamClosed(cancelled));
    try std.testing.expect(pair.server.streams.get(cancelled) != null);
    try std.testing.expect(!pair.server.streams.get(cancelled).?.reset_reported);
    try std.testing.expectEqual(@as(u64, 0), pair.server.streams.flow.?.retired_peer.uni);
    const reset = try pair.server.readStreamIdWithTimeout(cancelled, &out, .fromSeconds(1));
    try std.testing.expect(reset == .reset);
    try std.testing.expectEqual(@as(?u32, 42), reset.reset.error_info.application_code);
    try std.testing.expect(pair.server.streams.get(cancelled) == null);
    try std.testing.expect(!try pair.server.releaseCompletedPeerStream(cancelled));
    try std.testing.expect(pair.server.streams.get(sibling) != null);
    try std.testing.expectEqual(@as(u64, 1), pair.server.streams.flow.?.retired_peer.uni);
    _ = try pair.server.pollSessionEvent();
    try std.testing.expectEqual(@as(u64, 1), pair.server.streams.flow.?.retired_peer.uni);
    try std.testing.expectEqual(@as(u64, 9), pair.server.streams.flow.?.received.data);
    _ = try pair.client.openUnidirectionalStreamWithTimeout(.fromSeconds(1));
}

test "WebTransport flow complete readers replenish stream grants while awaiting next message" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
        var pair: Pair = undefined;
        try init(&pair, threaded.io());
        defer pair.deinit();
        try exchange(&pair, direction, 16, true);
    }
}

test "WebTransport flow cached STOP remains observable after QUIC send table is reclaimed" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try init(&pair, threaded.io());
    defer pair.deinit();
    const id = try pair.server.openUnidirectionalStream();
    try pair.server.sendStream(id, "stop", false);
    var out: [16]u8 = undefined;
    const event = try pair.client.readStreamWithTimeout(&out, .fromSeconds(1));
    try std.testing.expect(event == .data);
    try pair.client.stopStream(id, 7);
    const conn = pair.connection(.server);
    const deadline = std.Io.Clock.Timestamp.fromNow(conn.endpoint.io, .{ .raw = .fromSeconds(1), .clock = .awake });
    while (conn.sendStreamStats(id).?.stopped == null) try pair.receiveProgress(.server, deadline);
    try std.testing.expect((try pair.server.pollSessionEvent()) == null);
    try std.testing.expect(pair.server.streams.get(id).?.stopped != null);
    _ = try conn.requestCompletedLocalStreamRelease(id);
    const sent = conn.next_packet_number;
    for (0..@as(usize, @intCast(sent))) |packet| _ = conn.markPacketAcknowledged(packet);
    try std.testing.expect(conn.localStreamClosed(id));
    try std.testing.expect(conn.sendStreamStats(id) == null);
    const stop = try pair.server.readStreamIdWithTimeout(id, &out, .fromSeconds(1));
    try std.testing.expect(stop == .stopped);
    try std.testing.expectEqual(@as(?u32, 7), stop.stopped.error_info.application_code);
    try std.testing.expect(pair.server.streams.get(id) == null);
    try std.testing.expectEqual(@as(u64, 4), pair.server.streams.flow.?.sent.data);
}

test "WebTransport flow maintenance reacquires sender after retired sibling swap removal" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const settings = webtransport.defaultSettings(.{});
    var limited = settings;
    limited.webtransport_initial_max_data = 0;
    var pair: Pair = undefined;
    try pair.initWithSettings(threaded.io(), settings, limited);
    defer pair.deinit();
    const old = try pair.client.openUnidirectionalStream();
    try pair.client.sendStream(old, "", true);
    var out: [16]u8 = undefined;
    const eof = try pair.server.readStreamWithTimeout(&out, .fromSeconds(1));
    try std.testing.expect(eof == .data and eof.data.fin);
    _ = try pair.server.flushPendingAck();
    const active = try pair.client.openBidirectionalStream();
    try std.testing.expectEqual(@as(usize, 2), pair.client.streams.registered().len);
    try pair.server.grantData(3);
    var committed: usize = 0;
    try pair.client.sendStreamWithTimeout(active, "new", true, &committed, .fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 3), committed);
    try std.testing.expect(pair.client.streams.get(old) == null);
    try std.testing.expectEqual(@as(usize, 1), pair.client.streams.registered().len);
    try std.testing.expectEqual(active, pair.client.streams.registered()[0].stream_id);
    try std.testing.expectEqual(@as(u64, 3), pair.client.streams.get(active).?.bytes_sent);
    try std.testing.expectEqual(@as(u64, 3), pair.client.streams.flow.?.sent.data);
}
