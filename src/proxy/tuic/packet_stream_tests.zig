//! Real protected packets prove prefix, FIN, credit and reset ownership.
const std = @import("std");
const quic = @import("../netz.zig").quic;
const stream = @import("packet_stream.zig");
const native = @import("../../internal/testing/native_protocol_io.zig");
const Observed = @import("../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;
const allocator = std.testing.allocator;

const Fixture = struct {
    base: std.Io,
    sender_endpoint: quic.runtime.Endpoint,
    peer_endpoint: quic.runtime.Endpoint,
    sender: quic.one_rtt.Connection,
    peer: quic.one_rtt.Connection,
    state: stream.PacketStream = .{},

    fn init(self: *Fixture, base: std.Io, credit: u64) !void {
        self.* = .{ .base = base, .sender_endpoint = undefined, .peer_endpoint = undefined, .sender = undefined, .peer = undefined };
        self.sender_endpoint = try quic.runtime.Endpoint.bind(allocator, base, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096, .enable_gso_send = false });
        errdefer self.sender_endpoint.deinit();
        self.peer_endpoint = try quic.runtime.Endpoint.bind(allocator, base, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.peer_endpoint.deinit();
        const keys = quic.protection.deriveAes128Keys([_]u8{0x53} ** 32);
        self.sender = try quic.one_rtt.Connection.init(&self.sender_endpoint, .{
            .peer = self.peer_endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "sender",
            .peer_connection_id = "peer",
            .enable_pacing = false,
            .max_datagram_size = 1280,
            .initial_send_max_data = credit,
            .initial_send_max_stream_data = credit,
        });
        errdefer self.sender.deinit();
        self.peer = try quic.one_rtt.Connection.init(&self.peer_endpoint, .{
            .peer = self.sender_endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "peer",
            .peer_connection_id = "sender",
            .local_endpoint = .server,
            .enable_pacing = false,
        });
        self.sender.congestion.congestion_window = 1024 * 1024;
    }
    fn deinit(self: *Fixture) void {
        self.sender.deinit();
        self.peer.deinit();
        self.sender_endpoint.deinit();
        self.peer_endpoint.deinit();
    }
    fn receive(self: *Fixture) !quic.one_rtt.ReceivedPacket {
        return self.peer.receivePacketTimeout(.{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    }
};

fn largePacket(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 64 * 1024);
    defer fixture.deinit();
    fixture.sender.next_packet_number = 127;
    fixture.peer.expected_packet_number = 127;
    var bytes: [4096]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @intCast(i % 251);
    var seen: usize = 0;
    var first_id: ?u64 = null;
    for (0..16) |_| {
        var progress: stream.Progress = .{};
        try fixture.state.send(&fixture.sender, &bytes, &progress);
        try std.testing.expect(progress.committed_bytes != 0);
        var packet = try fixture.receive();
        defer packet.deinit(allocator);
        const frame = packet.frames[0].stream;
        if (first_id) |id| try std.testing.expectEqual(id, frame.stream_id) else first_id = frame.stream_id;
        try std.testing.expectEqual(@as(u64, @intCast(seen)), frame.offset);
        try std.testing.expectEqualSlices(u8, bytes[seen..][0..progress.committed_bytes], frame.data);
        seen += progress.committed_bytes;
        try std.testing.expectEqual(seen == bytes.len, frame.fin);
        try std.testing.expectEqual(frame.fin, progress.fin_committed);
        if (progress.fin_committed) break;
    }
    try std.testing.expectEqual(bytes.len, seen);
    try std.testing.expect(fixture.state.stream_id == null and fixture.state.cursor == 0 and fixture.state.payload.len == 0);
    try std.testing.expect(fixture.sender.next_packet_number > 128);
    var progress: stream.Progress = .{};
    try fixture.state.send(&fixture.sender, "next", &progress);
    var packet = try fixture.receive();
    defer packet.deinit(allocator);
    try std.testing.expect(packet.frames[0].stream.stream_id != first_id.?);
    try std.testing.expectEqual(@as(u64, 0), packet.frames[0].stream.offset);
    try std.testing.expectEqualStrings("next", packet.frames[0].stream.data);
    try std.testing.expect(packet.frames[0].stream.fin and progress.fin_committed);
}
test "TUIC PacketStream exact 4 KiB prefix uses one stream and final FIN" {
    try native.run(largePacket);
}

fn refusalAndRetirement(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 4);
    defer fixture.deinit();
    var progress: stream.Progress = .{};
    try fixture.state.send(&fixture.sender, "abcdefgh", &progress);
    const id = fixture.state.stream_id.?;
    try std.testing.expectEqual(@as(usize, 4), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    const number = fixture.sender.next_packet_number;
    try std.testing.expectError(error.FlowControlBlocked, fixture.state.send(&fixture.sender, "abcdefgh", &progress));
    try std.testing.expectEqual(@as(usize, 4), fixture.state.cursor);
    try std.testing.expectEqual(number, fixture.sender.next_packet_number);
    var packet = try fixture.receive();
    defer packet.deinit(allocator);
    try std.testing.expectEqualStrings("abcd", packet.frames[0].stream.data);
    try std.testing.expect(!packet.frames[0].stream.fin);
    var retirements: stream.Retirements = .{};
    try std.testing.expect(retirements.add(&fixture.state));
    try std.testing.expect(fixture.state.stream_id == null);
    try std.testing.expectEqual(@as(usize, 1), retirements.count);
    var observed = Observed{ .delegate = base, .fail_after_prefix = 0 };
    fixture.sender_endpoint.io = observed.io();
    try std.testing.expectError(error.NetworkDown, retirements.flush(&fixture.sender));
    try std.testing.expectEqual(@as(usize, 1), retirements.count);
    try std.testing.expectEqual(id, retirements.slots[0].?.stream_id.?);
    try std.testing.expectEqual(@as(usize, 0), retirements.slots[0].?.payload.len);
    fixture.sender_endpoint.io = base;
    try retirements.flush(&fixture.sender);
    try std.testing.expectEqual(@as(usize, 0), retirements.count);
    var reset = try fixture.receive();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(id, reset.frames[0].reset_stream.stream_id);
    try std.testing.expectEqual(@as(u64, 4), reset.frames[0].reset_stream.final_size);
}
test "TUIC PacketStream refusal retains prefix and retired reset until accepted" {
    try native.run(refusalAndRetirement);
}

fn positiveError(base: std.Io) !void {
    inline for (.{ false, true }) |large| {
        var fixture: Fixture = undefined;
        try fixture.init(base, 64 * 1024);
        defer fixture.deinit();
        var bytes: [4096]u8 = @splat('x');
        const payload = if (large) &bytes else bytes[0..8];
        var observed = Observed{ .delegate = base, .fail_after_prefix = 1 };
        fixture.sender_endpoint.io = observed.io();
        var progress: stream.Progress = .{};
        try std.testing.expectError(error.NetworkDown, fixture.state.send(&fixture.sender, payload, &progress));
        try std.testing.expect(progress.committed_bytes != 0);
        try std.testing.expectEqual(!large, progress.fin_committed);
        if (large) try std.testing.expectEqual(progress.committed_bytes, fixture.state.cursor) else try std.testing.expect(fixture.state.stream_id == null);
        fixture.sender_endpoint.io = base;
        var packet = try fixture.receive();
        defer packet.deinit(allocator);
        try std.testing.expectEqualSlices(u8, payload[0..progress.committed_bytes], packet.frames[0].stream.data);
        try std.testing.expectEqual(!large, packet.frames[0].stream.fin);
    }
}
test "TUIC PacketStream trailing error preserves committed prefix and FIN" {
    try native.run(positiveError);
}

fn timedPrefix(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 4);
    defer fixture.deinit();
    var progress: stream.Progress = .{};
    const next_id = fixture.sender.nextLocalUnidirectionalStreamId();
    try std.testing.expectError(error.Timeout, fixture.state.sendWithTimeout(&fixture.sender, "abcdefgh", .fromNanoseconds(0), &progress));
    try std.testing.expectEqual(next_id, fixture.sender.nextLocalUnidirectionalStreamId());
    try std.testing.expect(fixture.state.stream_id == null);
    try std.testing.expectError(error.Timeout, fixture.state.sendWithTimeout(&fixture.sender, "abcdefgh", .fromMilliseconds(25), &progress));
    try std.testing.expectEqual(@as(usize, 4), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    const id = fixture.state.stream_id.?;
    var packet = try fixture.receive();
    defer packet.deinit(allocator);
    try std.testing.expectEqualStrings("abcd", packet.frames[0].stream.data);
    try fixture.peer.send(&.{ .{ .max_data = .{ .maximum_data = 64 } }, .{ .max_stream_data = .{ .stream_id = id, .maximum_stream_data = 64 } } });
    var credit = try fixture.sender.receivePacketTimeout(.{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    defer credit.deinit(allocator);
    try fixture.state.sendWithTimeout(&fixture.sender, "abcdefgh", .fromSeconds(1), &progress);
    try std.testing.expectEqual(@as(usize, 4), progress.committed_bytes);
    try std.testing.expect(progress.fin_committed);
    const deadline = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (true) {
        var suffix = try fixture.peer.receivePacketTimeout(.{ .deadline = deadline });
        defer suffix.deinit(allocator);
        const final = for (suffix.frames) |frame| {
            if (frame == .stream) break frame.stream;
        } else continue;
        try std.testing.expectEqual(id, final.stream_id);
        try std.testing.expectEqual(@as(u64, 4), final.offset);
        try std.testing.expectEqualStrings("efgh", final.data);
        try std.testing.expect(final.fin);
        break;
    }
}
test "TUIC PacketStream timed send resumes exact suffix and excludes expired admission" {
    try native.run(timedPrefix);
}
