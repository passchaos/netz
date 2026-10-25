//! Unsolicited Pong is legal input while a liveness probe awaits its own reply.
const std = @import("std");
const websocket = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const h3 = @import("../h3.zig");
const http2 = @import("../../../http2/mod.zig").runtime;
const quic = @import("../../../quic/mod.zig");
const ping_reader = @import("ping.zig");
const common = @import("../common.zig");
const allocator = std.testing.allocator;

fn append(connection: anytype, role: runtime.Role, opcode: websocket.Opcode, payload: []const u8) !void {
    try websocket.writeFrame(&connection.inbuf, allocator, opcode, payload, .{ .mask_key = if (role == .server) .{ 1, 2, 3, 4 } else null });
}

fn exercise(connection: anytype, io: std.Io, role: runtime.Role) !void {
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try append(connection, role, .pong, "unsolicited");
    try append(connection, role, .text, "during probe");
    try append(connection, role, .pong, "older probe");
    try append(connection, role, .pong, "probe");
    try append(connection, role, .binary, "after probe");
    var application = try connection.continuePingWithDeadline("probe", deadline);
    defer application.deinit(allocator);
    try std.testing.expect(application == .application);
    try std.testing.expectEqualStrings("during probe", application.application.payload);
    var pong = try connection.continuePingWithDeadline("probe", deadline);
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);
    var after = try connection.receiveMessageWithDeadline(deadline);
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("after probe", after.payload);
    // An unsolicited Pong must not hide the terminal peer diagnosis either.
    try append(connection, role, .pong, "another probe");
    try append(connection, role, .close, "\x03\xe9peer diagnosis");
    connection.close_sent.store(true, .release);
    var closed = try connection.continuePingWithDeadline("probe", deadline);
    defer closed.deinit(allocator);
    try std.testing.expect(closed == .closed);
    try std.testing.expectEqual(websocket.CloseCode.going_away, closed.closed.?.code);
    try std.testing.expectEqualStrings("peer diagnosis", closed.closed.?.reason);
}

test "WebSocket HTTP1 Ping wait accepts unsolicited Pong and preserves application order" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(runtime.Role)) |role| {
        var connection = runtime.Connection{ .allocator = allocator, .io = threaded.io(), .stream = undefined, .role = role };
        defer connection.inbuf.deinit(allocator);
        try exercise(&connection, threaded.io(), role);
    }
}

test "WebSocket HTTP2 Ping wait accepts unsolicited Pong and preserves application order" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var transport: http2.Connection = undefined;
    transport.io = threaded.io();
    for (std.enums.values(runtime.Role)) |role| {
        var connection = runtime.H2Connection{ .allocator = allocator, .tunnel = .{ .connection = &transport, .stream_id = 1 }, .role = role };
        defer connection.inbuf.deinit(allocator);
        try exercise(&connection, threaded.io(), role);
    }
}

test "WebSocket HTTP3 Ping wait accepts unsolicited Pong and preserves application order" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x43} ** quic.protection.secret_len);
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        var connection = h3.Connection(role){ .allocator = allocator, .stream_id = 0, .h3 = undefined };
        connection.h3.established.connection = try quic.one_rtt.Connection.init(&endpoint, .{ .peer = endpoint.address(), .receive_keys = keys, .send_keys = keys, .local_connection_id = "pong-wait", .peer_connection_id = "pong-peer", .local_endpoint = if (role == .client) .client else .server, .enable_pacing = false });
        defer connection.h3.established.connection.deinit();
        defer connection.inbuf.deinit(allocator);
        try exercise(&connection, threaded.io(), role);
    }
}

test "WebSocket real TCP unsolicited Pong cannot renew Ping timeout or retransmit probe" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const socket = try listener.socket.address.connect(io, .{ .mode = .stream });
    const accepted = try listener.accept(io);
    var client = runtime.testing.initDirectConnection(allocator, io, socket, .client, .{});
    defer client.close();
    var server = runtime.testing.initDirectConnection(allocator, io, accepted, .server, .{});
    defer server.close();
    const Peer = struct {
        connection: *runtime.Connection,
        allow_reply: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var probe = try self.connection.receiveFrameWithTimeout(.fromSeconds(1));
            defer probe.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, probe.header.opcode);
            try self.connection.sendPong("older probe");
            try self.allow_reply.wait(self.connection.io);
            try self.connection.sendPong(probe.payload);
            try self.connection.sendBinary("following");
            // continuePing must wait for the existing probe, without sending
            // a second Ping in response to unrelated Pong traffic or timeout.
            try std.testing.expectError(error.Timeout, self.connection.receiveFrameWithTimeout(.fromMilliseconds(30)));
        }
    };
    var peer = Peer{ .connection = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.allow_reply.set(io);
        thread.join();
    };
    try std.testing.expectError(error.Timeout, client.pingWithTimeout("probe", .fromMilliseconds(30)));
    try std.testing.expect(!client.receive_failed.load(.acquire));
    peer.allow_reply.set(io);
    var pong = try client.continuePingWithTimeout("probe", .fromSeconds(1));
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);
    var following = try client.receiveMessageWithTimeout(.fromSeconds(1));
    defer following.deinit(allocator);
    try std.testing.expectEqualStrings("following", following.payload);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "WebSocket buffered unsolicited Pong stops at the original absolute deadline" {
    const ReaderError = websocket.Error || error{Timeout};
    const Source = struct {
        allocator: std.mem.Allocator = allocator,
        clock: std.Io,
        received: usize = 0,
        now_ns: i96 = 0,
        var active: ?*@This() = null;

        fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            return .fromNanoseconds(active.?.now_ns);
        }

        fn io(self: *@This()) std.Io {
            return self.clock;
        }

        fn receive(self: *@This(), _: std.Io.Clock.Timestamp, delivery: common.PendingAutomaticControl.Delivery) ReaderError!websocket.Frame {
            if (delivery != .ping_wait) return error.InvalidFrame;
            self.received += 1;
            self.now_ns = 3;
            const payload = if (self.received == 1) "unsolicited" else "probe";
            return .{ .header = .{ .fin = true, .opcode = .pong, .masked = false, .payload_len = payload.len, .header_len = 2, .mask_key = null }, .payload = try self.allocator.dupe(u8, payload), .consumed = 2 + payload.len };
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var vtable = threaded.io().vtable.*;
    vtable.now = Source.now;
    var source = Source{ .clock = .{ .userdata = threaded.io().userdata, .vtable = &vtable } };
    Source.active = &source;
    defer Source.active = null;
    const Reader = ping_reader.Reader(.{ .Error = ReaderError, .io = Source.io, .receive = Source.receive });
    const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(2) };
    try std.testing.expectError(error.Timeout, Reader.read(&source, "probe", deadline));
    try std.testing.expectEqual(@as(usize, 1), source.received);
    // Retrying an expired budget cannot consume the later matching Pong.
    try std.testing.expectError(error.Timeout, Reader.read(&source, "probe", deadline));
    try std.testing.expectEqual(@as(usize, 1), source.received);
    var pong = try Reader.read(&source, "probe", .{ .clock = .awake, .raw = .fromNanoseconds(10) });
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);
}
