//! Exercise actual UDP submission under a direct STREAM deadline.
const std = @import("std");
const quic = @import("../../mod.zig");
const runtime = @import("../../../runtime.zig");
const Probe = @import("../../../internal/testing/udp_deadline_probe.zig").Probe;
const allocator = std.testing.allocator;

test "QUIC stream socket deadline joins actual prefix and permits suffix reuse" {
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .expected_messages = 1 };
    defer probe.backend.deinit();
    const io = probe.io();
    const base = probe.backend.io();
    var peer_backend = try runtime.Backend.initWithExecutors(allocator, 1);
    defer peer_backend.deinit();
    var receiver = try quic.runtime.Endpoint.bind(allocator, peer_backend.io(), .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 256 });
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 256, .enable_gso_send = false });
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb1} ** quic.protection.secret_len);
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
    const id = try connection.openStream();
    const data = [_]u8{'x'} ** 512;
    const Task = struct {
        connection: *quic.one_rtt.Connection,
        base: std.Io,
        id: u64,
        data: []const u8,
        committed: usize = 99,
        result: ?anyerror!void = null,
        done: std.Io.Event = .unset,
        fn run(self: *@This()) void {
            self.result = self.connection.sendStreamWithDeadline(self.id, 0, self.data, true, &self.committed, .{ .clock = .awake, .raw = .fromNanoseconds(1000000) });
            self.done.set(self.base);
        }
    };
    var task: Task = .{ .connection = &connection, .base = base, .id = id, .data = &data };
    var sending = try std.Io.concurrent(base, Task.run, .{&task});
    defer sending.cancel(base);
    try probe.emitted.waitTimeout(base, .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
    // Bound the fixture's legacy escape using the real backend clock. The
    // send deadline itself advances only after the real UDP prefix is sent.
    task.done.waitTimeout(base, .{ .duration = .{ .raw = .fromMilliseconds(250), .clock = .awake } }) catch {
        sending.cancel(base);
        return error.SocketDeadlineDidNotInterrupt;
    };
    sending.await(base);
    try std.testing.expectError(error.Timeout, task.result.?);
    try std.testing.expect(probe.joined.load(.acquire));
    try std.testing.expect(task.committed > 0 and task.committed < data.len);
    try std.testing.expectEqual(@as(u64, task.committed), connection.send_flow.used);
    try std.testing.expectEqual(@as(u64, 1), connection.next_packet_number);
    var prefix = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer prefix.deinit(allocator);
    try std.testing.expect(prefix.bytes.len != 0);
    sender.io = base;
    var suffix: usize = 0;
    try connection.sendStreamWithDeadline(id, task.committed, data[task.committed..], true, &suffix, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(data.len - task.committed, suffix);
    try std.testing.expectEqual(@as(u64, data.len), connection.send_flow.used);
    try std.testing.expect(!connection.closed());
}
