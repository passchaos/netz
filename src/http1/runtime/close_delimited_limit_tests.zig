const std = @import("std");
const runtime = @import("../runtime.zig");
const pool_mod = @import("../client_pool.zig");
const tls_testing = @import("../../tls/testing.zig");

const Transport = enum { tcp, standard_tls, native_tls };

test "HTTP/1 EOF-delimited overflow retires TCP and TLS clients" {
    inline for (std.enums.values(Transport)) |transport| try clientOverflow(transport);
}

test "HTTP/1 EOF-delimited overflow on a pooled connection is not retried" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var first = try self.server.acceptWithTimeout(.fromSeconds(2));
            var first_owned = true;
            defer if (first_owned) first.close();
            try checkRequest(&first, "/warm");
            self.requests += 1;
            try write(&first, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
            try checkRequest(&first, "/large");
            self.requests += 1;
            try write(&first, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello");
            first.close();
            first_owned = false;
            var second = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer second.close();
            try checkRequest(&second, "/safe");
            self.requests += 1;
            try write(&second, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{ .max_connections = 1, .limits = .{ .max_body_bytes = 4 } });
    defer pool.deinit();
    const origin = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{server.address().getPort()});
    defer allocator.free(origin);
    const warm_uri = try std.fmt.allocPrint(allocator, "{s}/warm", .{origin});
    defer allocator.free(warm_uri);
    const large_uri = try std.fmt.allocPrint(allocator, "{s}/large", .{origin});
    defer allocator.free(large_uri);
    const safe_uri = try std.fmt.allocPrint(allocator, "{s}/safe", .{origin});
    defer allocator.free(safe_uri);
    var warm = try pool.requestUriWithTimeout(warm_uri, .{}, .fromSeconds(2));
    defer warm.deinit(allocator);
    try std.testing.expectEqualStrings("hi", warm.response.body);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    if (pool.requestUriWithTimeout(large_uri, .{}, .fromSeconds(2))) |value| {
        var unexpected = value;
        unexpected.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.BodyTooLarge, err);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    var safe = try pool.requestUriWithTimeout(safe_uri, .{}, .fromSeconds(2));
    defer safe.deinit(allocator);
    try std.testing.expectEqualStrings("ok", safe.response.body);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 3), peer.requests);
}

fn checkRequest(connection: *runtime.Connection, target: []const u8) !void {
    var request = try connection.readRequestWithTimeout(.{}, .fromSeconds(2));
    defer request.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(target, request.request.target);
}

fn write(connection: *runtime.Connection, bytes: []const u8) !void {
    if (connection.tls_server_conn) |tls| {
        try tls.writeAll(bytes);
    } else {
        var writer = connection.stream.writer(connection.io, &.{});
        try writer.interface.writeAll(bytes);
    }
}

fn clientOverflow(comptime transport: Transport) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const secure = transport != .tcp;
    var server = if (secure) try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .cipher_suites = &.{.aes_128_gcm_sha256},
    }) else try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *@TypeOf(server),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            try checkRequest(&connection, "/large");
            try write(&connection, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello");
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
    const limits = runtime.Limits{ .max_body_bytes = 4 };
    var client = switch (transport) {
        .tcp => try runtime.Client.connectWithDeadline(allocator, io, server.address(), limits, deadline),
        .standard_tls => try runtime.Client.connectTlsAddressWithDeadline(allocator, io, server.address(), "localhost", "localhost", limits, .{ .verify_host = false }, deadline),
        .native_tls => try runtime.Client.connectVailTlsAddressWithDeadline(allocator, io, server.address(), "localhost", limits, .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() } }, deadline),
    };
    defer client.close();
    if (client.requestWithDeadline(.{ .host = "localhost", .target = "/large" }, deadline)) |value| {
        var unexpected = value;
        unexpected.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.BodyTooLarge, err);
    try std.testing.expectError(error.ConnectionUnusable, client.request(.{ .host = "localhost" }));
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "HTTP/1 coalesced EOF-delimited body cannot bypass its limit" {
    try bufferedLimit(false, false, 4, "hello");
}

test "HTTP/1 coalesced EOF-delimited body fails before more I/O or allocation" {
    try bufferedLimit(true, true, 4, "hello");
}

test "HTTP/1 EOF-delimited exact and zero body limits remain valid" {
    try bufferedLimit(false, false, 5, "hello");
    try bufferedLimit(false, false, 0, "");
}

fn bufferedLimit(silent: bool, refuse_allocation: bool, maximum: usize, payload: []const u8) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const heads = [_][]const u8{
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 1\r\n\r\n",
    };
    for (heads) |head| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const client = try listener.socket.address.connect(io, .{ .mode = .stream });
        defer client.close(io);
        const peer = try listener.accept(io);
        var peer_owned = true;
        defer if (peer_owned) peer.close(io);
        if (!silent) {
            peer.close(io);
            peer_owned = false;
        }
        var inbuf: std.ArrayList(u8) = .empty;
        defer inbuf.deinit(allocator);
        try inbuf.appendSlice(allocator, head);
        try inbuf.appendSlice(allocator, payload);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        const result = runtime.readResponseFromStreamBufferedForRequestWithDeadline(
            if (refuse_allocation) failing.allocator() else allocator,
            io,
            client,
            .{ .max_head_bytes = 1024, .max_body_bytes = maximum },
            .{},
            &inbuf,
            .GET,
            .fromNow(io, .{ .raw = .fromMilliseconds(100), .clock = .awake }),
        );
        if (result) |value| {
            var response = value;
            defer response.deinit(allocator);
            if (payload.len > maximum) return error.TestUnexpectedResult;
            try std.testing.expectEqualStrings(payload, response.response.body);
            try std.testing.expect(response.response.body_framing == .close_delimited);
            try std.testing.expectEqual(@as(usize, 0), inbuf.items.len);
        } else |err| {
            if (payload.len <= maximum) return err;
            try std.testing.expectEqual(error.BodyTooLarge, err);
            try std.testing.expectEqual(head.len + payload.len, inbuf.items.len);
        }
        try std.testing.expect(!failing.has_induced_failure);
    }
}
