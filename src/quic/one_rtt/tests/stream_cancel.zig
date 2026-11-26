const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");
const ObservedBatchSend = @import("observed_batch_send.zig").ObservedBatchSend;
const NativeSendIo = @import("../../../internal/testing/deadline_send_io.zig").Native;

const Fixture = struct {
    endpoint: quic.runtime.Endpoint,
    peer_endpoint: quic.runtime.Endpoint,
    connection: one_rtt.Connection,
    peer: one_rtt.Connection,

    fn init(self: *Fixture, io: std.Io) !void {
        const allocator = std.testing.allocator;
        self.endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.endpoint.deinit();
        self.peer_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.peer_endpoint.deinit();
        const keys = quic.protection.deriveAes128Keys([_]u8{0x91} ** quic.protection.secret_len);
        self.connection = try one_rtt.Connection.init(&self.endpoint, .{
            .peer = self.peer_endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "cancel-client",
            .peer_connection_id = "cancel-server",
            .enable_pacing = false,
        });
        errdefer self.connection.deinit();
        self.peer = try one_rtt.Connection.init(&self.peer_endpoint, .{
            .peer = self.endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "cancel-server",
            .peer_connection_id = "cancel-client",
            .local_endpoint = .server,
            .enable_pacing = false,
        });
    }

    fn deinit(self: *Fixture) void {
        self.peer.deinit();
        self.connection.deinit();
        self.peer_endpoint.deinit();
        self.endpoint.deinit();
    }

    fn prepare(self: *Fixture) !void {
        try self.connection.send(&.{.{ .stream = .{ .stream_id = 0, .data = "outbound" } }});
        var request = try self.peer.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
        defer request.deinit(std.testing.allocator);
        try self.peer.send(&.{.{ .stream = .{ .stream_id = 0, .data = "inbound" } }});
        var response = try self.connection.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
        defer response.deinit(std.testing.allocator);
    }

    fn expectRetryable(self: *Fixture) !void {
        try std.testing.expect(self.connection.sendStreamStats(0).?.reset == null);
        try std.testing.expect(self.connection.recvStreamStats(0).?.stop_sending_sent == null);
        try std.testing.expectEqualStrings("inbound", self.connection.availableReceivedStream(0).?);
    }

    fn expectWire(self: *Fixture, expect_reset: bool) !void {
        var packet = try self.peer.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
        defer packet.deinit(std.testing.allocator);
        var saw_reset = false;
        var saw_stop = false;
        for (packet.frames) |frame| switch (frame) {
            .reset_stream => |reset| {
                try std.testing.expectEqual(@as(u62, 0), reset.stream_id);
                try std.testing.expectEqual(@as(u64, 71), reset.application_error_code);
                try std.testing.expectEqual(@as(u64, 8), reset.final_size);
                saw_reset = true;
            },
            .stop_sending => |stop| {
                try std.testing.expectEqual(@as(u62, 0), stop.stream_id);
                try std.testing.expectEqual(@as(u64, 71), stop.application_error_code);
                saw_stop = true;
            },
            else => {},
        };
        try std.testing.expectEqual(expect_reset, saw_reset);
        try std.testing.expect(saw_stop);
    }
};

test "QUIC stream cancel deadline rejects expired budgets before state allocation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    try std.testing.expectError(error.Timeout, fixture.connection.cancelStreamWithTimeout(0, 71, .zero));
    try std.testing.expectError(error.Timeout, fixture.connection.cancelStreamWithDeadline(0, 71, .{ .clock = .awake, .raw = .zero }));
    const realtime = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .real, .raw = .fromSeconds(1) });
    try std.testing.expectError(error.Timeout, fixture.connection.cancelStreamWithDeadline(0, 71, realtime));
    try std.testing.expect(fixture.connection.sendStreamStats(0) == null);
    try std.testing.expect(fixture.connection.recvStreamStats(0) == null);
    try std.testing.expectEqual(@as(u64, 0), fixture.connection.next_packet_number);
}

test "QUIC stream cancel deadline commits both halves in one packet" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    try fixture.prepare();
    try fixture.connection.cancelStreamWithTimeout(0, 71, .fromSeconds(1));
    try fixture.expectWire(true);
    try std.testing.expectEqual(@as(u64, 71), fixture.connection.sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expectEqual(@as(u64, 71), fixture.connection.recvStreamStats(0).?.stop_sending_sent.?.application_error_code);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.availableReceivedStream(0).?.len);
    const packet_number = fixture.connection.next_packet_number;
    try fixture.connection.cancelStreamWithTimeout(0, 71, .fromSeconds(1));
    try std.testing.expectEqual(packet_number, fixture.connection.next_packet_number);
}

test "QUIC stream cancel deadline preserves both halves across pacing timeout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    try fixture.prepare();
    fixture.connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    fixture.connection.pacer.budget = 0;
    fixture.connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.Timeout, fixture.connection.cancelStreamWithTimeout(0, 71, .fromMilliseconds(5)));
    try fixture.expectRetryable();
    fixture.connection.pacer.enabled = false;
    try fixture.connection.cancelStreamWithTimeout(0, 71, .fromSeconds(1));
    try fixture.expectWire(true);
}

test "QUIC stream cancel deadline preserves both halves across congestion timeout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    try fixture.prepare();
    const original_window = fixture.connection.congestion.congestion_window;
    fixture.connection.congestion.congestion_window = fixture.connection.bytesInFlight();
    try std.testing.expectError(error.Timeout, fixture.connection.cancelStreamWithTimeout(0, 71, .fromMilliseconds(5)));
    try fixture.expectRetryable();
    fixture.connection.congestion.congestion_window = original_window;
    try fixture.connection.cancelStreamWithTimeout(0, 71, .fromSeconds(1));
    try fixture.expectWire(true);
}

test "QUIC stream cancel deadline services queued ACK congestion progress" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    try fixture.prepare();
    fixture.connection.congestion.congestion_window = fixture.connection.bytesInFlight();
    try fixture.peer.sendAck(0);
    try fixture.connection.cancelStreamWithTimeout(0, 71, .fromSeconds(1));
    try fixture.expectWire(true);
}

test "QUIC stream cancel deadline retries atomic socket failure" {
    var send_io: NativeSendIo = .{ .backend = .init(std.testing.allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(send_io.backend.io());
    defer fixture.deinit();
    try fixture.prepare();
    const original_io = fixture.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    send_io.send_context = &observed;
    send_io.send_override = ObservedBatchSend.netSend;
    fixture.endpoint.io = send_io.io();
    defer fixture.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, fixture.connection.cancelStreamWithTimeout(0, 71, .fromSeconds(1)));
    try fixture.expectRetryable();
    observed.fail_on_call = null;
    try fixture.connection.cancelStreamWithTimeout(0, 71, .fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try fixture.expectWire(true);
}

test "QUIC stream cancel deadline preserves an already committed FIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    try fixture.prepare();
    try fixture.connection.send(&.{.{ .stream = .{ .stream_id = 0, .offset = 8, .data = &.{}, .fin = true } }});
    var fin = try fixture.peer.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
    defer fin.deinit(std.testing.allocator);
    try fixture.connection.cancelStreamWithTimeout(0, 71, .fromSeconds(1));
    try fixture.expectWire(false);
    try std.testing.expect(fixture.connection.sendStreamStats(0).?.reset == null);
    try std.testing.expectEqual(@as(?u64, 8), fixture.connection.sendStreamStats(0).?.final_size);
}

test "QUIC stream cancel preserves a committed reset while canceling the other half" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for (0..3) |mode| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        try fixture.prepare();
        try fixture.connection.resetStream(0, 19);
        var reset = try fixture.peer.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
        defer reset.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u64, 19), fixture.peer.recvStreamStats(0).?.reset.?.application_error_code);
        switch (mode) {
            0 => try fixture.connection.cancelStream(0, 71),
            1 => try fixture.connection.tryCancelStream(0, 71),
            2 => try fixture.connection.cancelStreamWithTimeout(0, 71, .fromSeconds(1)),
            else => unreachable,
        }
        try fixture.expectWire(false);
        try std.testing.expectEqual(@as(u64, 19), fixture.connection.sendStreamStats(0).?.reset.?.application_error_code);
        try std.testing.expectEqual(@as(u64, 8), fixture.connection.sendStreamStats(0).?.reset.?.final_size);
        try std.testing.expectEqual(@as(usize, 0), fixture.connection.availableReceivedStream(0).?.len);
        const packet_number = fixture.connection.next_packet_number;
        try fixture.connection.tryCancelStream(0, 71);
        try std.testing.expectEqual(packet_number, fixture.connection.next_packet_number);
    }
}

test "QUIC stream cancel reliable downgrade retains the committed reset error code" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    fixture.connection.config.reliable_reset.peer = true;
    fixture.peer.config.reliable_reset.local = true;
    try fixture.prepare();
    try fixture.connection.resetStreamReliably(0, 19, 8);
    var initial = try fixture.peer.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
    defer initial.deinit(std.testing.allocator);
    try fixture.connection.tryCancelStream(0, 71);
    var canceled = try fixture.peer.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
    defer canceled.deinit(std.testing.allocator);
    var reset = false;
    var stop = false;
    for (canceled.frames) |frame| switch (frame) {
        .reset_stream => |value| {
            try std.testing.expectEqual(@as(u64, 19), value.application_error_code);
            try std.testing.expectEqual(@as(u64, 8), value.final_size);
            reset = true;
        },
        .stop_sending => |value| {
            try std.testing.expectEqual(@as(u64, 71), value.application_error_code);
            stop = true;
        },
        else => {},
    };
    try std.testing.expect(reset and stop);
    try std.testing.expectEqual(@as(u64, 19), fixture.peer.recvStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expectEqual(@as(u64, 0), fixture.peer.recvStreamStats(0).?.reset.?.reliable_size);
    try std.testing.expect(!fixture.peer.closed());
}

test "QUIC stream cancel after a committed reset preserves receive ownership on backpressure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |paced| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        try fixture.prepare();
        try fixture.connection.resetStream(0, 19);
        var reset = try fixture.peer.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
        defer reset.deinit(std.testing.allocator);
        if (paced) {
            fixture.connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
            fixture.connection.pacer.budget = 0;
            fixture.connection.pacer.setLastSentTimeNs(@intCast(std.Io.Clock.awake.now(threaded.io()).nanoseconds));
        } else {
            one_rtt.testing.clampCongestionWindowToBytesInFlight(&fixture.connection);
        }
        const packet_number = fixture.connection.next_packet_number;
        if (paced) try std.testing.expectError(error.PacingLimited, fixture.connection.tryCancelStream(0, 71)) else try std.testing.expectError(error.CongestionLimited, fixture.connection.tryCancelStream(0, 71));
        try std.testing.expectEqual(@as(u64, 19), fixture.connection.sendStreamStats(0).?.reset.?.application_error_code);
        try std.testing.expect(fixture.connection.recvStreamStats(0).?.stop_sending_sent == null);
        try std.testing.expectEqualStrings("inbound", fixture.connection.availableReceivedStream(0).?);
        try std.testing.expectEqual(packet_number, fixture.connection.next_packet_number);
        fixture.connection.pacer.enabled = false;
        fixture.connection.congestion.congestion_window = 64 * 1024;
        try fixture.connection.tryCancelStream(0, 71);
        try fixture.expectWire(false);
    }
}
