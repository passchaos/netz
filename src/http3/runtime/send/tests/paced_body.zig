const std = @import("std");
const quic = @import("../../../../quic/mod.zig");
const paced = @import("../paced_body.zig");
const bodies_module = @import("../../stream/outbound_body.zig");
const NativeSendIo = @import("../../../../internal/testing/deadline_send_io.zig").Native;
const Error = @import("../../error.zig").ReceiveTimeoutError;

test "HTTP/3 paced DATA deadline keeps complete committed prefix and connection usable" {
    try checkPrefix(false);
    try checkPrefix(true);
}

fn checkPrefix(comptime sliced: bool) !void {
    const allocator = std.testing.allocator;
    var timed: NativeSendIo = .{ .backend = .init(allocator, .{}), .advance_after_send_ns = std.time.ns_per_s };
    defer timed.backend.deinit();
    const io = timed.backend.io();
    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer sender.deinit();
    sender.io = timed.io();
    defer sender.io = io;
    const keys = quic.protection.deriveAes128Keys([_]u8{0x87} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "paced-client",
        .peer_connection_id = "paced-server",
        .initial_send_max_data = 128,
        .initial_send_max_stream_data = 128,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const id: u62 = @intCast(try connection.openStream());
    var bodies = bodies_module.Set.init(allocator, 1);
    defer bodies.deinit();
    try bodies.reserveOpen(id);
    bodies.appendOpenAssumeCapacity(id, .init(id), 500);
    const Hooks = struct {
        fn before(_: void, _: u62, _: ?std.Io.Clock.Timestamp) Error!bool {
            return false;
        }
        fn receive(_: void, _: u62, _: ?std.Io.Clock.Timestamp) Error!void {
            return error.UnexpectedFrame;
        }
        fn finish(_: void, _: u62) Error!void {
            return error.UnexpectedFrame;
        }
    };
    var progress: struct { committed_bytes: usize = 0, fin_committed: bool = false } = .{};
    const options = .{
        .paced_body_chunk_bytes = @as(usize, 8000),
        .max_stream_frame_data = @as(usize, 1200),
        .max_frames_per_packet = @as(usize, 8),
        .enable_data_prefix_fast_path = true,
    };
    const content = [_]u8{'x'} ** 500;
    const until: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(std.time.ns_per_ms) };
    const hooks = .{ .before = Hooks.before, .receive = Hooks.receive, .finish = Hooks.finish };
    if (sliced) {
        try std.testing.expectError(error.Timeout, paced.writeParts(&connection, &bodies, options, {}, id, &.{ content[0..13], "", content[13..57], content[57..] }, true, until, &progress, hooks));
    } else {
        try std.testing.expectError(error.Timeout, paced.write(&connection, &bodies, options, {}, id, &content, true, until, &progress, hooks));
    }
    // 128 stream bytes hold a three-byte DATA prefix and 125 body bytes.
    try std.testing.expectEqual(@as(usize, 125), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectEqual(@as(usize, 125), bodies.find(id).?.written);
    try std.testing.expectEqual(@as(u64, 128), bodies.find(id).?.send.next_offset);
    try std.testing.expect(!connection.closed());
}
