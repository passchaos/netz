const std = @import("std");
const websocket = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const h3 = @import("../../h3.zig");
const http2 = @import("../../../../http2/mod.zig").runtime;
const quic = @import("../../../../quic/mod.zig");
const allocator = std.testing.allocator;

const Entropy = struct {
    delegate: std.Io,
    failing: bool = true,
    write_failure: bool = false,
    calls: usize = 0,
    var active: ?*Entropy = null;

    fn randomSecure(userdata: ?*anyopaque, out: []u8) std.Io.RandomSecureError!void {
        const self = active.?;
        self.calls += 1;
        if (self.failing) return error.EntropyUnavailable;
        return self.delegate.vtable.randomSecure(userdata, out);
    }

    fn netWrite(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.?;
        if (self.write_failure) return error.NetworkDown;
        return self.delegate.vtable.netWrite(userdata, handle, header, data, splat);
    }
};

fn receive(connection: anytype) !websocket.Frame {
    if (comptime @hasDecl(@TypeOf(connection.*), "receiveFrameAutoWithTimeout")) {
        return connection.receiveFrameAutoWithTimeout(.fromSeconds(1));
    }
    return connection.receiveFrameWithTimeout(.fromSeconds(1));
}

fn exercise(connection: anytype, entropy: *Entropy) !void {
    for ([_]websocket.Opcode{ .ping, .close }) |opcode| {
        for ([_]bool{ false, true }) |empty| {
            connection.close_sent.store(false, .release);
            connection.close_received.store(false, .release);
            connection.inbuf_consumed = 0;
            connection.inbuf.clearRetainingCapacity();
            entropy.failing = true;
            const payload = if (empty) "" else if (opcode == .ping) "probe" else "\x03\xe9diagnosis";
            try websocket.writeFrame(&connection.inbuf, allocator, opcode, payload, .{});
            try std.testing.expectError(error.EntropyUnavailable, receive(connection));
            // A complete frame already left input. A local mask failure must
            // retain ownership and delivery mode rather than drop the diagnosis.
            const pending = connection.pending_auto_control orelse return error.TestUnexpectedResult;
            try std.testing.expect(pending.frame != null);
            try std.testing.expectEqualSlices(u8, payload, pending.frame.?.payload);
            try std.testing.expect(connection.automatic_write_pending.load(.acquire));
            try std.testing.expect(!connection.receive_failed.load(.acquire));
            try std.testing.expectError(error.EntropyUnavailable, receive(connection));
            try std.testing.expectError(error.WriteInProgress, connection.receiveMessageWithTimeout(.fromSeconds(1)));
            // A concurrent local Close suppresses this unsent reply but must still
            // deliver the retained peer frame once, without consulting entropy.
            const before = entropy.calls;
            connection.close_sent.store(true, .release);
            var frame = try receive(connection);
            defer frame.deinit(allocator);
            try std.testing.expectEqual(before, entropy.calls);
            try std.testing.expectEqual(opcode, frame.header.opcode);
            try std.testing.expectEqualSlices(u8, payload, frame.payload);
            try std.testing.expect(connection.pending_auto_control == null);
            try std.testing.expect(!connection.automatic_write_pending.load(.acquire));
        }
    }
}

test "WebSocket HTTP1 automatic reply mask failure retains the received control frame" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var entropy = Entropy{ .delegate = threaded.io() };
    Entropy.active = &entropy;
    defer Entropy.active = null;
    var vtable = threaded.io().vtable.*;
    vtable.randomSecure = Entropy.randomSecure;
    const io = std.Io{ .userdata = threaded.io().userdata, .vtable = &vtable };
    var connection = runtime.Connection{ .allocator = allocator, .io = io, .stream = undefined, .role = .client };
    defer {
        if (connection.pending_auto_control) |*pending| pending.deinit(allocator);
        connection.inbuf.deinit(allocator);
    }
    try exercise(&connection, &entropy);
}

test "WebSocket HTTP2 automatic reply mask failure retains the received control frame" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var entropy = Entropy{ .delegate = threaded.io() };
    Entropy.active = &entropy;
    defer Entropy.active = null;
    var vtable = threaded.io().vtable.*;
    vtable.randomSecure = Entropy.randomSecure;
    var transport: http2.Connection = undefined;
    transport.io = .{ .userdata = threaded.io().userdata, .vtable = &vtable };
    var connection = runtime.H2Connection{ .allocator = allocator, .tunnel = .{ .connection = &transport, .stream_id = 1 }, .role = .client };
    defer {
        if (connection.pending_auto_control) |*pending| pending.deinit(allocator);
        connection.inbuf.deinit(allocator);
    }
    try exercise(&connection, &entropy);
}

test "WebSocket HTTP3 automatic reply mask failure retains the received control frame" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var entropy = Entropy{ .delegate = threaded.io() };
    Entropy.active = &entropy;
    defer Entropy.active = null;
    var vtable = threaded.io().vtable.*;
    vtable.randomSecure = Entropy.randomSecure;
    var endpoint = try quic.runtime.Endpoint.bind(allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    endpoint.io = .{ .userdata = threaded.io().userdata, .vtable = &vtable };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x38} ** quic.protection.secret_len);
    var connection = h3.Connection(.client){ .allocator = allocator, .stream_id = 0, .h3 = undefined };
    connection.h3.established.connection = try quic.one_rtt.Connection.init(&endpoint, .{ .peer = endpoint.address(), .receive_keys = keys, .send_keys = keys, .local_connection_id = "auto-mask", .peer_connection_id = "auto-peer", .enable_pacing = false });
    defer connection.h3.established.connection.deinit();
    defer {
        if (connection.pending_auto_control) |*pending| pending.deinit(allocator);
        connection.inbuf.deinit(allocator);
    }
    try exercise(&connection, &entropy);
}

test "WebSocket real TCP automatic reply resumes entropy and write failures with one mask" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]websocket.Opcode{ .ping, .close }) |opcode| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
        const receiver = try listener.accept(io);
        var peer = runtime.testing.initDirectConnection(allocator, io, sender, .server, .{});
        defer peer.close();
        var entropy = Entropy{ .delegate = io };
        Entropy.active = &entropy;
        defer Entropy.active = null;
        var vtable = io.vtable.*;
        vtable.randomSecure = Entropy.randomSecure;
        vtable.netWrite = Entropy.netWrite;
        const observed = std.Io{ .userdata = io.userdata, .vtable = &vtable };
        var connection = runtime.testing.initDirectConnection(allocator, observed, receiver, .client, .{});
        defer connection.close();
        const payload = if (opcode == .ping) "probe" else "\x03\xe9diagnosis";
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try websocket.writeFrame(&encoded, allocator, opcode, payload, .{});
        if (opcode == .ping) try websocket.writeFrame(&encoded, allocator, .binary, "following", .{});
        var writer = sender.writer(io, &.{});
        try writer.interface.writeAll(encoded.items);
        try std.testing.expectError(error.EntropyUnavailable, connection.receiveFrameAutoWithTimeout(.fromSeconds(1)));
        const original = connection.pending_auto_control.?.frame.?.payload;
        entropy.failing = false;
        entropy.write_failure = true;
        try std.testing.expectError(error.NetworkDown, connection.receiveFrameAutoWithTimeout(.fromSeconds(1)));
        try std.testing.expectEqual(@as(usize, 2), entropy.calls);
        const pending = connection.pending_auto_control.?;
        const mask = (try websocket.FrameHeader.parse(pending.bytes[0..pending.len])).mask_key;
        try std.testing.expect(mask != null);
        entropy.write_failure = false;
        var frame = try connection.receiveFrameAutoWithTimeout(.fromSeconds(1));
        defer frame.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 2), entropy.calls);
        try std.testing.expectEqual(original.ptr, frame.payload.ptr);
        try std.testing.expectEqualSlices(u8, payload, frame.payload);
        try std.testing.expect(connection.pending_auto_control == null);
        var reply = try peer.receiveFrameWithTimeout(.fromSeconds(1));
        defer reply.deinit(allocator);
        try std.testing.expectEqual(if (opcode == .ping) websocket.Opcode.pong else .close, reply.header.opcode);
        try std.testing.expectEqualSlices(u8, payload, reply.payload);
        try std.testing.expectEqualDeep(mask, reply.header.mask_key);
        if (opcode == .ping) {
            var following = try connection.receiveFrameAutoWithTimeout(.fromSeconds(1));
            defer following.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, following.header.opcode);
            try std.testing.expectEqualStrings("following", following.payload);
        } else try std.testing.expectError(error.ConnectionClosed, connection.receiveFrameAutoWithTimeout(.fromSeconds(1)));
    }
}

test "WebSocket borrowed message control keeps input through automatic mask failure" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]websocket.Opcode{ .ping, .close }) |opcode| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
        const receiver = try listener.accept(io);
        var peer = runtime.testing.initDirectConnection(allocator, io, sender, .server, .{});
        defer peer.close();
        var entropy = Entropy{ .delegate = io };
        Entropy.active = &entropy;
        defer Entropy.active = null;
        var vtable = io.vtable.*;
        vtable.randomSecure = Entropy.randomSecure;
        const observed = std.Io{ .userdata = io.userdata, .vtable = &vtable };
        var connection = runtime.testing.initDirectConnection(allocator, observed, receiver, .client, .{});
        defer connection.close();
        const payload = if (opcode == .ping) "probe" else "\x03\xe9diagnosis";
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try websocket.writeFrame(&encoded, allocator, opcode, payload, .{});
        if (opcode == .ping) try websocket.writeFrame(&encoded, allocator, .binary, "following", .{});
        try connection.inbuf.appendSlice(allocator, encoded.items);
        try std.testing.expectError(error.EntropyUnavailable, connection.receiveMessageWithTimeout(.fromSeconds(1)));
        try std.testing.expect(connection.pending_auto_control == null);
        try std.testing.expectEqual(@as(usize, 0), connection.inbuf_consumed);
        try std.testing.expectEqualSlices(u8, encoded.items, connection.inbuf.items);
        try std.testing.expect(!connection.receive_failed.load(.acquire));
        entropy.failing = false;
        if (opcode == .ping) {
            var message = try connection.receiveMessageWithTimeout(.fromSeconds(1));
            defer message.deinit(allocator);
            try std.testing.expectEqualStrings("following", message.payload);
        } else try std.testing.expectError(error.ConnectionClosed, connection.receiveMessageWithTimeout(.fromSeconds(1)));
        var reply = try peer.receiveFrameWithTimeout(.fromSeconds(1));
        defer reply.deinit(allocator);
        try std.testing.expectEqual(if (opcode == .ping) websocket.Opcode.pong else .close, reply.header.opcode);
        try std.testing.expectEqualSlices(u8, payload, reply.payload);
        try std.testing.expectEqual(@as(usize, 2), entropy.calls);
    }
}
