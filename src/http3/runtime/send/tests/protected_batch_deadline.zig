const std = @import("std");
const quic = @import("../../../../quic/mod.zig");
const Probe = @import("../../../../internal/testing/udp_deadline_probe.zig").Probe;
const send = @import("../protected.zig");
const body = @import("../body.zig");
const outbound = @import("../../stream/outbound_body.zig");
const BodyChunk = @import("../../body_batch.zig").Chunk;
const allocator = std.testing.allocator;
const app_runtime = @import("../../../../runtime.zig");

fn partialBatch(failure: ?std.Io.net.Socket.SendError) !void {
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .forced_error = failure };
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0x27} ** quic.protection.secret_len);
    const config = .{ .send_keys = keys, .peer_connection_id = @as([]const u8, "protected-peer"), .max_stream_frame_data = @as(usize, 128), .max_frames_per_packet = @as(usize, 8) };
    var protected = send.State.init(allocator);
    defer protected.deinit();
    var bodies = outbound.Set.init(allocator, 2);
    defer bodies.deinit();
    inline for (.{ @as(u62, 0), @as(u62, 4) }) |id| {
        try bodies.reserveOpen(id);
        bodies.appendOpenAssumeCapacity(id, quic.stream_state.SendState.init(id), 1);
    }
    const Context = struct {
        ids: [2]u62 = undefined,
        count: usize = 0,
        fn receive(_: *@This(), _: std.Io.Clock.Timestamp) !void {
            return error.Unexpected;
        }
        fn finish(self: *@This(), id: u62) void {
            self.ids[self.count] = id;
            self.count += 1;
        }
    };
    var context: Context = .{};
    const chunks = [_]BodyChunk{ .{ .stream_id = 0, .data = "a", .fin = true }, .{ .stream_id = 4, .data = "b", .fin = true } };
    var packet_number: u64 = 0;
    var committed: usize = 99;
    const until: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1000000) };
    const expected: anyerror = if (failure) |err| err else error.Timeout;
    try std.testing.expectError(expected, body.sendProtectedBodyBatchPacedWithDeadline(&sender, receiver.address(), config, &packet_number, &protected, &bodies, &chunks, &context, Context.receive, Context.finish, &committed, until));
    try std.testing.expect(probe.joined.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), committed);
    try std.testing.expectEqual(@as(u64, 2), packet_number);
    try std.testing.expect(protected.isUsable());
    try std.testing.expect(bodies.find(0) == null);
    try std.testing.expectEqual(@as(usize, 0), bodies.find(4).?.written);
    try std.testing.expectEqual(@as(u64, 0), bodies.find(4).?.send.next_offset);
    try std.testing.expectEqual(@as(usize, 1), context.count);
    try std.testing.expectEqual(@as(u62, 0), context.ids[0]);
    var prefix = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer prefix.deinit(allocator);
    try std.testing.expect(prefix.bytes.len != 0);
    const completed = try body.sendProtectedBodyBatchProgress(&sender, receiver.address(), config, &packet_number, &protected, &bodies, chunks[committed..], &context, Context.finish);
    try std.testing.expectEqual(@as(usize, 1), completed);
    try std.testing.expectEqual(@as(u64, 3), packet_number);
    try std.testing.expectEqual(@as(usize, 2), context.count);
    try std.testing.expectEqual(@as(u62, 4), context.ids[1]);
    try std.testing.expect(bodies.find(4) == null);
    var suffix = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer suffix.deinit(allocator);
    try std.testing.expect(suffix.bytes.len != 0);
}

test "HTTP/3 protected batch deadline preserves actual DATA prefix and suffix reuse" {
    try partialBatch(null);
}

test "HTTP/3 protected batch deadline preserves network error with committed prefix" {
    try partialBatch(error.NetworkDown);
}
