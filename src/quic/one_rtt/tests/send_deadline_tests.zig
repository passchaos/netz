//! Real UDP prefix, timed cancellation and nonce-safe suffix reuse.
const std = @import("std");
const quic = @import("../../mod.zig");
const allocator = std.testing.allocator;
const app_runtime = @import("../../../runtime.zig");

const Probe = @import("../../../internal/testing/udp_deadline_probe.zig").Probe;

fn partialPrefix(forced_error: ?std.Io.net.Socket.SendError, relative: bool) !void {
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .forced_error = forced_error };
    defer probe.backend.deinit();
    const io = probe.io();
    // Use the application backend for timed peer reads on every platform;
    // Threaded Windows does not provide the required polling capability.
    var peer_backend = try app_runtime.Backend.initWithExecutors(allocator, 1);
    defer peer_backend.deinit();
    var receiver = try quic.runtime.Endpoint.bind(allocator, peer_backend.io(), .{ .ip4 = .loopback(0) }, .{});
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .enable_gso_send = false });
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x61} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "deadline-local",
        .peer_connection_id = "deadline-peer",
        .initial_send_max_data = 100,
        .initial_send_max_stream_data = 100,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const id = try connection.openStream();
    const first = [_]quic.Frame{.{ .stream = .{ .stream_id = id, .data = "a" } }};
    const second = [_]quic.Frame{.{ .stream = .{ .stream_id = id, .offset = 1, .data = "b", .fin = true } }};
    const packets = [_][]const quic.Frame{ &first, &second };
    var progress: quic.one_rtt.ConnectionBatchSendResult = .{ .sent_count = 99, .protected_count = 99 };
    const until: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1000000) };
    const expected_error: anyerror = if (forced_error) |err| err else error.Timeout;
    const result = if (relative)
        connection.sendManyProgressWithTimeout(&packets, &progress, .fromMilliseconds(1))
    else
        connection.sendManyProgressWithDeadline(&packets, &progress, until);
    try std.testing.expectError(expected_error, result);
    try std.testing.expect(probe.joined.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), progress.sent_count);
    try std.testing.expectEqual(@as(usize, 2), progress.protected_count);
    try std.testing.expectEqual(@as(u64, 2), connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 1), connection.send_flow.used);
    try std.testing.expectEqual(@as(u64, 1), connection.sendStreamStats(id).?.bytes_sent);
    try std.testing.expectEqual(@as(usize, 1), connection.stats().sent_packet_stats.tracked_packets);
    var received = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer received.deinit(allocator);
    try std.testing.expect(received.bytes.len != 0);
    try std.testing.expectError(error.Timeout, receiver.receiveBytesWithTimeout(.fromMilliseconds(5)));
    // Only the uncommitted stream offset is retried, with a fresh packet number.
    try connection.trySend(&second);
    try std.testing.expectEqual(@as(u64, 3), connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 2), connection.send_flow.used);
    try std.testing.expectEqual(@as(u64, 2), connection.sendStreamStats(id).?.bytes_sent);
    var suffix = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer suffix.deinit(allocator);
    try std.testing.expect(suffix.bytes.len != 0);
    try std.testing.expect(!connection.closed());
}

test "QUIC send deadline actual UDP prefix retains recovery and consumes unsent packet numbers" {
    try partialPrefix(null, false);
    try partialPrefix(null, true);
}

test "QUIC send deadline actual UDP prefix preserves the network error after timer expiry" {
    try partialPrefix(error.NetworkDown, false);
    try partialPrefix(error.NetworkDown, true);
}

test "QUIC send deadline actual complete UDP packet succeeds after racing expiry" {
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .expected_messages = 1 };
    defer probe.backend.deinit();
    const io = probe.io();
    // Use the application backend for timed peer reads on every platform;
    // Threaded Windows does not provide the required polling capability.
    var peer_backend = try app_runtime.Backend.initWithExecutors(allocator, 1);
    defer peer_backend.deinit();
    var receiver = try quic.runtime.Endpoint.bind(allocator, peer_backend.io(), .{ .ip4 = .loopback(0) }, .{});
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x71} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "deadline-local",
        .peer_connection_id = "deadline-peer",
        .initial_send_max_data = 100,
        .initial_send_max_stream_data = 100,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const id = try connection.openStream();
    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = id, .data = "done", .fin = true } }};
    const until: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1000000) };
    try connection.trySendWithDeadline(&frames, until);
    try std.testing.expect(probe.joined.load(.acquire));
    try std.testing.expectEqual(@as(u64, 1), connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 4), connection.send_flow.used);
    var packet = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer packet.deinit(allocator);
    try std.testing.expect(packet.bytes.len != 0);
    try std.testing.expect(!connection.closed());
}

test "QUIC send deadline unavailable watcher leaves packet numbers and socket untouched" {
    var probe: Probe = .{ .backend = .init(allocator, .{}) };
    defer probe.backend.deinit();
    const io = probe.io();
    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x81} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "deadline-local",
        .peer_connection_id = "deadline-peer",
    });
    defer connection.deinit();
    probe.table.groupConcurrent = std.Io.failingGroupConcurrent;
    const id = try connection.openStream();
    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = id, .data = "no-send" } }};
    const until: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1000000) };
    try std.testing.expectError(error.ConcurrencyUnavailable, connection.trySendWithDeadline(&frames, until));
    try std.testing.expectEqual(@as(u64, 0), connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 0), connection.send_flow.used);
    try std.testing.expect(!probe.emitted.isSet());
}

test "QUIC send deadline cancels occupied socket lock and rolls back protected unsent state" {
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }) };
    defer probe.backend.deinit();
    const io = probe.io();
    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x91} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "deadline-local",
        .peer_connection_id = "deadline-peer",
        .initial_send_max_data = 100,
        .initial_send_max_stream_data = 100,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const id = try connection.openStream();
    const first = [_]quic.Frame{.{ .stream = .{ .stream_id = id, .data = "a" } }};
    const second = [_]quic.Frame{.{ .stream = .{ .stream_id = id, .offset = 1, .data = "b" } }};
    const packets = [_][]const quic.Frame{ &first, &second };
    var progress: quic.one_rtt.ConnectionBatchSendResult = .{ .sent_count = 0, .protected_count = 0 };
    probe.held_mutex = &endpoint.send_mutex;
    endpoint.send_mutex.lockUncancelable(io);
    defer if (!probe.forced_mutex_release.load(.acquire)) endpoint.send_mutex.unlock(io);
    const until: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1000000) };
    try std.testing.expectError(error.Timeout, connection.sendManyProgressWithDeadline(&packets, &progress, until));
    try std.testing.expect(!probe.forced_mutex_release.load(.acquire));
    try std.testing.expect(!probe.emitted.isSet());
    try std.testing.expectEqual(@as(usize, 0), progress.sent_count);
    try std.testing.expectEqual(@as(usize, 2), progress.protected_count);
    try std.testing.expectEqual(@as(u64, 2), connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 0), connection.send_flow.used);
    try std.testing.expectEqual(@as(usize, 0), connection.stats().sent_packet_stats.tracked_packets);
}

test "QUIC send deadline relative budgets reject before protection and clear batch progress" {
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }) };
    defer probe.backend.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(allocator, probe.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0xa1} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "relative-local",
        .peer_connection_id = "relative-peer",
    });
    defer connection.deinit();
    const frames = [_]quic.Frame{.{ .ping = {} }};
    const packets = [_][]const quic.Frame{&frames};
    for ([_]std.Io.Duration{ .zero, .fromNanoseconds(-1) }) |invalid| {
        var progress: quic.one_rtt.ConnectionBatchSendResult = .{ .sent_count = 99, .protected_count = 99 };
        try std.testing.expectError(error.Timeout, connection.sendManyProgressWithTimeout(&packets, &progress, invalid));
        try std.testing.expectEqual(@as(usize, 0), progress.sent_count);
        try std.testing.expectEqual(@as(usize, 0), progress.protected_count);
        try std.testing.expect(progress.send_error == null);
        try std.testing.expectError(error.Timeout, connection.trySendWithTimeout(&frames, invalid));
    }
    probe.table.groupConcurrent = std.Io.failingGroupConcurrent;
    try std.testing.expectError(error.ConcurrencyUnavailable, connection.trySendWithTimeout(&frames, .fromSeconds(1)));
    try std.testing.expectEqual(@as(u64, 0), connection.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), probe.send_calls.load(.acquire));
}
