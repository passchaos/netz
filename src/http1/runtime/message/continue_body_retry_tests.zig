//! Continue is committed before body storage, and is never replayed on retry.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const tls = @import("../../../tls/mod.zig").stream;
const tls_testing = @import("../../../tls/testing.zig");
const stream_io = @import("../../../internal/stream_io.zig");
const allocator = std.testing.allocator;
const Backend = enum { tcp, tls12, tls13 };
const head = "POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n";
const interim = "HTTP/1.1 100 Continue\r\n\r\n";
const final = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone";

test "HTTP1 TCP and TLS Continue survives body allocation retries without replay" {
    inline for (std.enums.values(Backend)) |backend| try exercise(backend);
}

fn exercise(comptime backend: Backend) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    var server = if (backend == .tcp)
        try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{})
    else
        try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
            .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
            .protocol_policy = if (backend == .tls12) .tls12_only else .tls13_only,
        });
    defer server.deinit();
    const Peer = struct {
        io: std.Io,
        address: std.Io.net.IpAddress,
        key: @TypeOf(key),
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.exchange() catch |err| {
                self.err = err;
            };
        }

        fn exchange(self: *@This()) !void {
            const socket = try self.address.connect(self.io, .{ .mode = .stream });
            var owned = true;
            defer if (owned) socket.close(self.io);
            const connection: ?*tls.ClientConnection = if (backend == .tcp) null else try tls.ClientConnection.init(allocator, self.io, socket, .{
                .server_name = "localhost",
                .server_verifier = .{ .pinned_ecdsa_p256_public_key = self.key.public_key.toUncompressedSec1() },
                .protocol_policy = if (backend == .tls12) .tls12_only else .tls13_only,
            });
            if (connection) |_| owned = false;
            defer if (connection) |value| value.deinit();
            try send(self.io, socket, connection, head);
            var response: [interim.len]u8 = undefined;
            try read(self.io, socket, connection, &response);
            try std.testing.expectEqualStrings(interim, &response);
            try self.release.waitTimeout(self.io, .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } });
            try send(self.io, socket, connection, "body" ++ head);
            try read(self.io, socket, connection, &response);
            try std.testing.expectEqualStrings(interim, &response);
            try send(self.io, socket, connection, "body");
            var finished: [final.len]u8 = undefined;
            try read(self.io, socket, connection, &finished);
            // Any replayed Continue would appear ahead of this final response.
            try std.testing.expectEqualStrings(final, &finished);
        }
    };
    var peer = Peer{ .io = io, .address = server.address(), .key = key };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.release.set(io);
        thread.join();
    };
    var connection = try server.accept();
    defer connection.close();
    var received_head: [head.len]u8 = undefined;
    try read(io, connection.stream, connection.tls_server_conn, &received_head);
    try std.testing.expectEqualStrings(head, &received_head);
    connection.inbuf = .fromOwnedSlice(try allocator.dupe(u8, &received_head));
    for (0..2) |_| {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0, .resize_fail_index = 0 });
        connection.allocator = failing.allocator();
        defer connection.allocator = allocator;
        try std.testing.expectError(error.OutOfMemory, connection.readRequestWithTimeout(.{}, .fromSeconds(1)));
        try std.testing.expect(connection.request_continue.sent);
        try std.testing.expectEqualStrings(head, connection.inbuf.items);
        try std.testing.expect(connection.writer_state.phase == .idle);
    }
    peer.release.set(io);
    for (0..2) |_| {
        var request = try connection.readRequestWithTimeout(.{}, .fromSeconds(2));
        defer request.deinit(allocator);
        try std.testing.expectEqualStrings("body", request.request.body);
        try std.testing.expect(!connection.request_continue.sent);
    }
    try send(io, connection.stream, connection.tls_server_conn, final);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn send(io: std.Io, socket: std.Io.net.Stream, connection: anytype, bytes: []const u8) !void {
    if (connection) |value| return value.writeAll(bytes);
    var writer = socket.writer(io, &.{});
    try writer.interface.writeAll(bytes);
}

fn read(io: std.Io, socket: std.Io.net.Stream, connection: anytype, output: []u8) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    var offset: usize = 0;
    while (offset < output.len) {
        const count = if (connection) |value| try value.readWithDeadline(output[offset..], deadline) else try stream_io.readSomeWithDeadline(io, socket, output[offset..], deadline);
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
}
