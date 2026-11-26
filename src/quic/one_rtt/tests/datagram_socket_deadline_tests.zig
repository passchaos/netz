//! Real UDP DATAGRAM prefixes, raced errors and nonce-safe suffix reuse.
const std = @import("std");
const quic = @import("../../mod.zig");
const runtime = @import("../../../runtime.zig");
const Probe = @import("../../../internal/testing/udp_deadline_probe.zig").Probe;
const allocator = std.testing.allocator;

fn prefix(once: bool, forced_error: ?std.Io.net.Socket.SendError) !void {
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .expected_messages = 2, .forced_error = forced_error };
    defer probe.backend.deinit();
    const io = probe.io();
    const base = probe.backend.io();
    var peer_backend = try runtime.Backend.initWithExecutors(allocator, 1);
    defer peer_backend.deinit();
    var receiver = try quic.runtime.Endpoint.bind(allocator, peer_backend.io(), .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 256 });
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 256, .enable_gso_send = false });
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0xc1} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .local_max_datagram_frame_size = 256,
        .peer_max_datagram_frame_size = 256,
        .max_frames_per_packet = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const Task = struct {
        connection: *quic.one_rtt.Connection,
        base: std.Io,
        once: bool,
        committed: usize = 99,
        result: ?anyerror!void = null,
        done: std.Io.Event = .unset,
        fn run(self: *@This()) void {
            const until: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1000000) };
            self.result = if (self.once)
                self.connection.trySendDatagramsWithDeadline(&.{ "one", "two" }, &self.committed, until)
            else
                self.connection.sendDatagramsWithDeadline(&.{ "one", "two" }, &self.committed, until);
            self.done.set(self.base);
        }
    };
    var task: Task = .{ .connection = &connection, .base = base, .once = once };
    var sending = try std.Io.concurrent(base, Task.run, .{&task});
    defer sending.cancel(base);
    try probe.emitted.waitTimeout(base, .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
    try task.done.waitTimeout(base, .{ .duration = .{ .raw = .fromMilliseconds(250), .clock = .awake } });
    sending.await(base);
    try std.testing.expectError(forced_error orelse error.Timeout, task.result.?);
    try std.testing.expect(probe.joined.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), task.committed);
    try std.testing.expectEqual(@as(u64, 2), connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 1), connection.datagrams_sent_count);
    try std.testing.expectEqual(@as(u64, 0), connection.send_flow.used);
    var first = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer first.deinit(allocator);
    try std.testing.expect(first.bytes.len != 0);
    try std.testing.expectError(error.Timeout, receiver.receiveBytesWithTimeout(.fromMilliseconds(5)));
    // Reuse the same connection with a fresh real-clock budget, after the
    // synthetic expired operation and all of its borrowed storage have joined.
    sender.io = base;
    var committed: usize = 99;
    try connection.trySendDatagramsWithDeadline(&.{"two"}, &committed, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(@as(usize, 1), committed);
    try std.testing.expectEqual(@as(u64, 3), connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 2), connection.datagrams_sent_count);
    var suffix = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer suffix.deinit(allocator);
    try std.testing.expect(suffix.bytes.len != 0);
    try std.testing.expect(!connection.closed());
}

test "QUIC datagram socket deadline retains actual payload prefix and fresh nonces" {
    try prefix(false, null);
    try prefix(true, null);
}

test "QUIC datagram socket deadline preserves network errors after actual prefix" {
    try prefix(false, error.NetworkDown);
    try prefix(true, error.NetworkDown);
}

test "QUIC datagram socket deadline rejects budgets and unavailable watcher before protection" {
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }) };
    defer probe.backend.deinit();
    const io = probe.io();
    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd1} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .local_max_datagram_frame_size = 256,
        .peer_max_datagram_frame_size = 256,
    });
    defer connection.deinit();
    var committed: usize = 99;
    try std.testing.expectError(error.Timeout, connection.trySendDatagramsWithTimeout(&.{"x"}, &committed, .zero));
    try std.testing.expectEqual(@as(usize, 0), committed);
    probe.table.groupConcurrent = std.Io.failingGroupConcurrent;
    committed = 99;
    try std.testing.expectError(error.ConcurrencyUnavailable, connection.trySendDatagramsWithTimeout(&.{"x"}, &committed, .fromSeconds(1)));
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(u64, 0), connection.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), probe.send_calls.load(.acquire));
}
