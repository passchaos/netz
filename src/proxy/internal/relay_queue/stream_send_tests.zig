const std = @import("std");
const quic = @import("../../netz.zig").quic;
const queues = @import("../relay_queue.zig");
const output = @import("stream_send.zig");
const ObservedSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;
const gpa = std.testing.allocator;

const Fixture = struct {
    threaded: std.Io.Threaded,
    sender_endpoint: quic.runtime.Endpoint,
    peer_endpoint: quic.runtime.Endpoint,
    sender: quic.one_rtt.Connection,
    peer: quic.one_rtt.Connection,
    relay: queues.Relay,

    fn init(self: *Fixture, credit: u64) !void {
        self.threaded = .init(gpa, .{});
        errdefer self.threaded.deinit();
        const io = self.threaded.io();
        self.sender_endpoint = try quic.runtime.Endpoint.bind(gpa, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096, .enable_gso_send = false });
        errdefer self.sender_endpoint.deinit();
        self.peer_endpoint = try quic.runtime.Endpoint.bind(gpa, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
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
        self.relay = .{
            .allocator = gpa,
            .io = io,
            .tcp = undefined,
            .stream_id = 0,
            .last_activity_ns = 0,
            .idle_timeout = .fromSeconds(1),
            .buffer_size = 4096,
        };
    }

    fn deinit(self: *Fixture) void {
        self.sender.deinit();
        self.peer.deinit();
        self.sender_endpoint.deinit();
        self.peer_endpoint.deinit();
        self.threaded.deinit();
    }
};

test "proxy relay STREAM prefix respects flow and congestion refusal" {
    var fixture: Fixture = undefined;
    try fixture.init(4);
    defer fixture.deinit();
    var bytes = "abcdefgh".*;
    var progress: output.Progress = .{};
    try output.send(quic, &fixture.sender, &fixture.relay, .{ .data = &bytes }, bytes.len, &progress);
    try std.testing.expectEqual(@as(usize, 4), progress.committed_bytes);
    try std.testing.expect(!progress.complete);
    const packet_number = fixture.sender.next_packet_number;
    try std.testing.expectError(error.FlowControlBlocked, output.send(quic, &fixture.sender, &fixture.relay, .{ .data = &bytes }, bytes.len, &progress));
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
    try std.testing.expectEqual(packet_number, fixture.sender.next_packet_number);
    var received = try fixture.peer.receivePacket();
    defer received.deinit(gpa);
    try fixture.peer.send(&.{
        .{ .max_data = .{ .maximum_data = 32 } },
        .{ .max_stream_data = .{ .stream_id = 0, .maximum_stream_data = 32 } },
    });
    var credit = try fixture.sender.receivePacket();
    defer credit.deinit(gpa);
    const in_flight = fixture.sender.congestion.bytes_in_flight;
    fixture.sender.congestion.bytes_in_flight = fixture.sender.congestion.congestion_window;
    try std.testing.expectError(error.CongestionLimited, output.send(quic, &fixture.sender, &fixture.relay, .{ .data = &bytes }, bytes.len, &progress));
    try std.testing.expectEqual(packet_number, fixture.sender.next_packet_number);
    fixture.sender.congestion.bytes_in_flight = in_flight;
    try output.send(quic, &fixture.sender, &fixture.relay, .{ .data = &bytes }, bytes.len, &progress);
    try std.testing.expect(progress.complete);
    try std.testing.expectEqual(@as(u64, 8), fixture.relay.send_offset);
}

test "proxy relay STREAM retry retires protected but unsent packet numbers" {
    var fixture: Fixture = undefined;
    try fixture.init(64 * 1024);
    defer fixture.deinit();
    var observed = ObservedSend{ .delegate = fixture.sender_endpoint.io, .fail_after_prefix = 0 };
    fixture.sender_endpoint.io = observed.io();
    defer fixture.sender_endpoint.io = observed.delegate;
    var bytes = "abcdefgh".*;
    var progress: output.Progress = .{};
    try std.testing.expectError(error.NetworkDown, output.send(quic, &fixture.sender, &fixture.relay, .{ .data = &bytes }, bytes.len, &progress));
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
    try std.testing.expectEqual(@as(usize, 0), fixture.relay.pending_data_start);
    try std.testing.expectEqual(@as(u64, 0), fixture.relay.send_offset);
    try std.testing.expectEqual(@as(u64, 1), fixture.sender.next_packet_number);
    try std.testing.expectEqual(@as(u64, 64 * 1024), fixture.sender.connectionSendAvailable());
    fixture.sender_endpoint.io = observed.delegate;
    try output.send(quic, &fixture.sender, &fixture.relay, .{ .data = &bytes }, bytes.len, &progress);
    try std.testing.expect(progress.complete);
    try std.testing.expectEqual(@as(u64, 2), fixture.sender.next_packet_number);
    var received = try fixture.peer.receivePacket();
    defer received.deinit(gpa);
    try std.testing.expectEqualStrings("abcdefgh", received.frames[0].stream.data);
}

test "proxy relay STREAM commits a socket-visible item even with a trailing error" {
    var fixture: Fixture = undefined;
    try fixture.init(64 * 1024);
    defer fixture.deinit();
    var observed = ObservedSend{ .delegate = fixture.sender_endpoint.io, .fail_after_prefix = 1 };
    fixture.sender_endpoint.io = observed.io();
    defer fixture.sender_endpoint.io = observed.delegate;
    var bytes = "abcdefgh".*;
    var progress: output.Progress = .{};
    try std.testing.expectError(error.NetworkDown, output.send(quic, &fixture.sender, &fixture.relay, .{ .data = &bytes }, bytes.len, &progress));
    try std.testing.expect(progress.complete);
    try std.testing.expectEqual(@as(usize, 8), progress.committed_bytes);
    try std.testing.expectEqual(@as(u64, 8), fixture.relay.send_offset);
    fixture.sender_endpoint.io = observed.delegate;
    var received = try fixture.peer.receivePacket();
    defer received.deinit(gpa);
    try std.testing.expectEqualStrings("abcdefgh", received.frames[0].stream.data);
}

test "proxy relay STREAM packet budget remains exact across packet-number widths" {
    var fixture: Fixture = undefined;
    try fixture.init(64 * 1024);
    defer fixture.deinit();
    fixture.sender.next_packet_number = 127;
    fixture.peer.expected_packet_number = 127;
    // This test isolates framing; integration tests exercise ordinary ACK-driven congestion.
    fixture.sender.congestion.congestion_window = 1024 * 1024;
    var bytes: [16 * 1024]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @intCast(index % 251);
    var seen: usize = 0;
    var progress: output.Progress = .{};
    for (0..128) |_| {
        try output.send(quic, &fixture.sender, &fixture.relay, .{ .data = &bytes }, bytes.len, &progress);
        try std.testing.expect(progress.committed_bytes != 0);
        var received = try fixture.peer.receivePacket();
        defer received.deinit(gpa);
        const stream = received.frames[0].stream;
        try std.testing.expectEqual(@as(u64, seen), stream.offset);
        try std.testing.expectEqualSlices(u8, bytes[seen..][0..progress.committed_bytes], stream.data);
        seen += progress.committed_bytes;
        if (progress.complete) break;
    }
    try std.testing.expectEqual(bytes.len, seen);
    try std.testing.expect(fixture.sender.next_packet_number > 128);
    try output.send(quic, &fixture.sender, &fixture.relay, .fin, 0, &progress);
    var received = try fixture.peer.receivePacket();
    defer received.deinit(gpa);
    try std.testing.expect(received.frames[0].stream.fin);
    try std.testing.expectEqual(@as(u64, bytes.len), received.frames[0].stream.offset);
}
