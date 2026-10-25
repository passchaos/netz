//! Encrypted HTTP input survives allocation failures in head/body decoding.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const tls = @import("../../../tls/mod.zig").stream;
const tls_testing = @import("../../../tls/testing.zig");
const allocator = std.testing.allocator;
const body = [_]u8{'b'} ** (16 * 1024);

test "HTTP1 TLS12 and TLS13 request retries retain body bytes and later requests" {
    for ([_]bool{ false, true }) |old| {
        var succeeded = false;
        for (0..16) |fail_index| {
            if (try exercise(old, fail_index)) {
                succeeded = true;
                break;
            }
        }
        try std.testing.expect(succeeded);
    }
}

fn exercise(old: bool, fail_index: usize) !bool {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = if (old) .tls12_only else .tls13_only,
    });
    defer server.deinit();
    const Peer = struct {
        io: std.Io,
        address: std.Io.net.IpAddress,
        old: bool,
        key: @TypeOf(key),
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.send() catch |err| {
                self.err = err;
            };
        }
        fn send(self: *@This()) !void {
            const socket = try self.address.connect(self.io, .{ .mode = .stream });
            var owned = true;
            errdefer if (owned) socket.close(self.io);
            const connection = try tls.ClientConnection.init(allocator, self.io, socket, .{
                .server_name = "localhost",
                .server_verifier = .{ .pinned_ecdsa_p256_public_key = self.key.public_key.toUncompressedSec1() },
                .protocol_policy = if (self.old) .tls12_only else .tls13_only,
            });
            owned = false;
            defer connection.deinit();
            try connection.writeAll("POST /large HTTP/1.1\r\nHost: localhost\r\nContent-Length: 16384\r\n\r\n");
            try connection.writeAll(&body);
            try connection.writeAll("GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n");
            try self.done.waitTimeout(self.io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
        }
    };
    var peer = Peer{ .io = io, .address = server.address(), .old = old, .key = key };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.done.set(io);
        thread.join();
    };
    var connection = try server.accept();
    defer connection.close();
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index, .resize_fail_index = 0 });
    const result = blk: {
        connection.allocator = failing.allocator();
        defer connection.allocator = allocator;
        break :blk connection.readRequestWithTimeout(.{}, .fromSeconds(2));
    };
    if (failing.has_induced_failure) {
        try std.testing.expectError(error.OutOfMemory, result);
        var request = try connection.readRequestWithTimeout(.{}, .fromSeconds(2));
        defer request.deinit(allocator);
        try std.testing.expectEqualStrings("/large", request.request.target);
        try std.testing.expectEqualStrings(&body, request.request.body);
    } else {
        var request = try result;
        request.deinit(allocator);
    }
    var next = try connection.readRequestWithTimeout(.{}, .fromSeconds(2));
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("/next", next.request.target);
    peer.done.set(io);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
    return !failing.has_induced_failure;
}
