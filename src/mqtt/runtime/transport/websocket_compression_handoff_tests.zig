//! A retained message never replays a committed WebSocket compression context.
const std = @import("std");
const mqtt = @import("../../mod.zig");
const Transport = @import("../packet_transport.zig").Transport;
const websocket = @import("../../../websocket/runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");
const allocator = std.testing.allocator;

const Listener = union(enum) {
    plain: websocket.Server,
    secure: websocket.TlsServer,

    fn address(self: *Listener) std.Io.net.IpAddress {
        return switch (self.*) {
            inline else => |*server| server.address(),
        };
    }

    fn accept(self: *Listener) !websocket.Connection {
        return switch (self.*) {
            inline else => |*server| server.accept(.{ .enable_permessage_deflate = true, .allow_context_takeover = true, .compression_threshold = 1 }),
        };
    }

    fn deinit(self: *Listener) void {
        switch (self.*) {
            inline else => |*server| server.deinit(),
        }
    }
};

test "MQTT WS and WSS retain compressed handoff across repeated OOM and close" {
    for ([_]bool{ false, true }) |secure| {
        for ([_]bool{ false, true }) |resume_message| try exercise(secure, resume_message);
    }
}

fn exercise(secure: bool, resume_message: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    var listener: Listener = if (secure)
        .{ .secure = try websocket.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } } }) }
    else
        .{ .plain = try websocket.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}) };
    defer listener.deinit();
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    const body = "takeover payload/" ** 64;
    try mqtt.writePublish(&first, allocator, .v5, "handoff/first", body, .{});
    try mqtt.writePublish(&second, allocator, .v5, "handoff/second", body, .{});
    const Peer = struct {
        listener: *Listener,
        io: std.Io,
        first: []const u8,
        second: []const u8,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var connection = try self.listener.accept();
            defer connection.close();
            try std.testing.expect(connection.compression_send_context_takeover);
            try connection.sendBinary(self.first);
            try connection.sendBinary(self.second);
            try self.release.waitTimeout(self.io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
        }
    };
    var peer = Peer{ .listener = &listener, .io = io, .first = first.items, .second = second.items };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.release.set(io);
        thread.join();
    };
    const options: websocket.ConnectOptions = .{
        .host = "localhost",
        .enable_permessage_deflate = true,
        .allow_context_takeover = true,
        .compression_threshold = 1,
        .vail_tls = if (secure) .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() } } else null,
    };
    const connection = if (secure)
        try websocket.Client.connectTlsHost(allocator, io, "localhost", listener.address().ip4.port, options, .{ .verify_host = false })
    else
        try websocket.Client.connect(allocator, io, listener.address(), options);
    var transport = try Transport.initWebSocket(allocator, connection);
    defer transport.close(allocator);
    try std.testing.expect(transport.websocket.connection.compression_receive_context_takeover);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0, .resize_fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, transport.readPacketWithDeadline(failing.allocator(), 4096, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) })));
    const pending = transport.websocket.pending_payload.?;
    try std.testing.expectEqualStrings(first.items, pending);
    if (resume_message) {
        var repeated = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0, .resize_fail_index = 0 });
        try std.testing.expectError(error.OutOfMemory, transport.readPacketWithDeadline(repeated.allocator(), 4096, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) })));
        try std.testing.expectEqual(@intFromPtr(pending.ptr), @intFromPtr(transport.websocket.pending_payload.?.ptr));
        var packet = try transport.readPacketWithDeadline(allocator, 4096, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
        defer packet.deinit(allocator);
        try std.testing.expectEqualStrings(first.items, packet.bytes);
        var next = try transport.readPacketWithDeadline(allocator, 4096, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
        defer next.deinit(allocator);
        try std.testing.expectEqualStrings(second.items, next.bytes);
        try std.testing.expect(transport.websocket.pending_payload == null);
        try std.testing.expectError(error.Timeout, transport.readPacketWithDeadline(allocator, 4096, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(5) })));
    }
    peer.release.set(io);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
