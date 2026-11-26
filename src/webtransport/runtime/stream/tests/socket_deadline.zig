//! Real associated STREAM prefixes survive interrupted writes and suffix retry.
const std = @import("std");
const webtransport = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const runtime = @import("../../../../runtime.zig");
const stream = @import("../../stream.zig");
const Probe = @import("../../../../internal/testing/udp_deadline_probe.zig").Probe;
const allocator = std.testing.allocator;
const Mode = enum { contiguous, slices, fin };

fn interrupted(mode: Mode, forced_error: ?std.Io.net.Socket.SendError) !void {
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .armed = .init(false), .expected_messages = if (mode == .fin) 1 else 2, .forced_error = forced_error };
    defer probe.backend.deinit();
    const io = probe.io();
    const base = probe.backend.io();
    var peer_backend = try runtime.Backend.initWithExecutors(allocator, 1);
    defer peer_backend.deinit();
    var receiver = try quic.runtime.Endpoint.bind(allocator, peer_backend.io(), .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 256 });
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 256, .enable_gso_send = false });
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe1} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .initial_send_max_data = 4096,
        .initial_send_max_stream_data = 4096,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = try webtransport.StreamRegistry.init(allocator, .init(0), .client, .{});
    defer registry.deinit();
    const id = (try registry.openLocal(.bidirectional)).stream_id;
    try std.testing.expectEqual(@as(u64, 0), try connection.openStream());
    try std.testing.expectEqual(id, try connection.openStream());
    // Establish a real association prefix and application seed before arming
    // the interrupted write. The registry starts from valid wire state.
    try stream.send(&connection, &registry, .init(0), id, "seed", false);
    const initial_number = connection.next_packet_number;
    const initial_offset = registry.get(id).?.send_offset;
    const initial_flow = connection.send_flow.used;
    for (0..initial_number) |_| {
        var packet = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
        packet.deinit(allocator);
    }
    const data = [_]u8{'x'} ** 200;
    const Task = struct {
        connection: *quic.one_rtt.Connection,
        registry: *webtransport.StreamRegistry,
        base: std.Io,
        id: u62,
        data: []const u8,
        mode: Mode,
        committed: usize = 99,
        result: ?anyerror!void = null,
        done: std.Io.Event = .unset,
        fn run(self: *@This()) void {
            const until: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1000000) };
            const parts = [_][]const u8{ self.data[0..16], &.{}, self.data[16..] };
            self.result = switch (self.mode) {
                .contiguous => stream.sendWithDeadline(self.connection, self.registry, .init(0), self.id, self.data, true, &self.committed, until),
                .slices => stream.sendSlicesWithDeadline(self.connection, self.registry, .init(0), self.id, &parts, true, &self.committed, until),
                .fin => stream.finishWithDeadline(self.connection, self.registry, .init(0), self.id, until),
            };
            self.done.set(self.base);
        }
    };
    var task: Task = .{ .connection = &connection, .registry = &registry, .base = base, .id = id, .data = &data, .mode = mode };
    probe.armed.store(true, .release);
    var sending = try std.Io.concurrent(base, Task.run, .{&task});
    defer sending.cancel(base);
    try probe.emitted.waitTimeout(base, .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
    try task.done.waitTimeout(base, .{ .duration = .{ .raw = .fromMilliseconds(250), .clock = .awake } });
    sending.await(base);
    try std.testing.expect(probe.joined.load(.acquire));
    var first = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer first.deinit(allocator);
    try std.testing.expect(first.bytes.len != 0);
    if (mode == .fin) {
        try task.result.?;
        try std.testing.expect(registry.get(id).?.local_fin);
        try std.testing.expectEqual(@as(u64, 4), registry.get(id).?.bytes_sent);
        try std.testing.expectEqual(initial_offset, registry.get(id).?.send_offset);
        try std.testing.expectEqual(initial_number + 1, connection.next_packet_number);
        return;
    }
    try std.testing.expectError(forced_error orelse error.Timeout, task.result.?);
    try std.testing.expect(task.committed > 0 and task.committed < data.len);
    try std.testing.expectEqual(@as(u64, 4 + task.committed), registry.get(id).?.bytes_sent);
    try std.testing.expectEqual(initial_offset + task.committed, registry.get(id).?.send_offset);
    try std.testing.expectEqual(initial_flow + task.committed, connection.send_flow.used);
    try std.testing.expect(registry.get(id).?.prefix_sent and !registry.get(id).?.local_fin);
    try std.testing.expectEqual(initial_number + 2, connection.next_packet_number);
    try std.testing.expectError(error.Timeout, receiver.receiveBytesWithTimeout(.fromMilliseconds(5)));
    sender.io = base;
    var suffix: usize = 0;
    try stream.sendWithDeadline(&connection, &registry, .init(0), id, data[task.committed..], true, &suffix, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(data.len - task.committed, suffix);
    try std.testing.expectEqual(@as(u64, 4 + data.len), registry.get(id).?.bytes_sent);
    try std.testing.expect(registry.get(id).?.local_fin);
    try std.testing.expect(!connection.closed());
}

test "WebTransport STREAM socket deadline retains associated contiguous and slice prefixes" {
    try interrupted(.contiguous, null);
    try interrupted(.slices, null);
}

test "WebTransport STREAM socket deadline preserves network error after associated prefix" {
    try interrupted(.contiguous, error.NetworkDown);
    try interrupted(.slices, error.NetworkDown);
}

test "WebTransport STREAM socket deadline keeps completed FIN race successful" {
    try interrupted(.fin, null);
}
