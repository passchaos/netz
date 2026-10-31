const std = @import("std");
const quic = @import("../../../../quic/mod.zig");
const paced = @import("../paced_body.zig");
const bodies_module = @import("../../stream/outbound_body.zig");
const Error = @import("../../error.zig").ReceiveTimeoutError;

test "HTTP/3 paced DATA deadline keeps complete committed prefix and connection usable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer sender.deinit();
    const Timed = struct {
        delegate: std.Io,
        now_ns: i96 = 0,
        fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }
        fn send(context: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const result = self.delegate.vtable.netSend(self.delegate.userdata, socket, messages, flags);
            if (result[1] != 0) self.now_ns += std.time.ns_per_s;
            return result;
        }
    };
    var timed = Timed{ .delegate = io };
    var vtable = io.vtable.*;
    vtable.now = Timed.now;
    vtable.netSend = Timed.send;
    sender.io = .{ .userdata = &timed, .vtable = &vtable };
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
    try std.testing.expectError(error.Timeout, paced.write(&connection, &bodies, .{
        .paced_body_chunk_bytes = @as(usize, 8000),
        .max_stream_frame_data = @as(usize, 1200),
        .max_frames_per_packet = @as(usize, 8),
        .enable_data_prefix_fast_path = true,
    }, {}, id, &([_]u8{'x'} ** 500), true, .{ .clock = .awake, .raw = .fromNanoseconds(std.time.ns_per_ms) }, &progress, .{ .before = Hooks.before, .receive = Hooks.receive, .finish = Hooks.finish }));
    // 128 stream bytes hold a three-byte DATA prefix and 125 body bytes.
    try std.testing.expectEqual(@as(usize, 125), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectEqual(@as(usize, 125), bodies.find(id).?.written);
    try std.testing.expectEqual(@as(u64, 128), bodies.find(id).?.send.next_offset);
    try std.testing.expect(!connection.closed());
}
