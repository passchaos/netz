//! TLS batch output cannot treat an uncommitted record as zero wire progress.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const tls = @import("../../../tls/mod.zig");
const allocator = std.testing.allocator;

test "HTTP/2 batch output deadlines bound real TLS12 and TLS13 records" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    if (comptime builtin.os.tag != .linux) return;
    for ([_]bool{ false, true }) |tls12| {
        try exercise(tls12, false);
        try exercise(tls12, true);
    }
}

fn exercise(tls12: bool, body: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.testing.certificate_base64);
    const key = try tls.testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = if (tls12) .tls12_only else .tls13_only,
        .limits = .{ .max_header_list_size = 1024 * 1024 },
        .tls_handshake_timeout = .fromSeconds(2),
    });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            const buffer_size: c_int = 4096;
            try std.posix.setsockopt(connection.stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&buffer_size));
            try std.Io.sleep(connection.io, .fromMilliseconds(500), .awake);
        }
    };
    var peer: Peer = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connectTlsAddress(allocator, io, server.address(), "localhost", "localhost", .{}, .{
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .protocol_policy = if (tls12) .tls12_only else .tls13_only,
    });
    defer client.close();
    const buffer_size: c_int = 4096;
    try std.posix.setsockopt(client.stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&buffer_size));
    const large = "x" ** (256 * 1024);
    const requests = [_]runtime.RequestOptions{
        .{ .method = "POST", .path = "/one", .authority = "localhost", .headers = if (body) &.{} else &.{.{ .name = "x-large", .value = large }}, .body = if (body) large else &.{} },
        .{ .method = "POST", .path = "/two", .authority = "localhost" },
    };
    var responses: [2]runtime.OwnedResponse = undefined;
    const started = std.Io.Clock.awake.now(io);
    const result = if (body) client.requestBodyBatchIntoWithTimeout(&requests, 16_384, &responses, .fromMilliseconds(30)) else client.requestBatchIntoWithTimeout(&requests, &responses, .fromMilliseconds(30));
    try std.testing.expectError(error.Timeout, result);
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(client.aggregate_timeout_unusable);
    try std.testing.expect(client.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());
    try std.testing.expectEqual(@as(usize, 0), client.send_stream_windows.items.len);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
