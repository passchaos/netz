const std = @import("std");
const runtime = @import("../runtime.zig");
const stream_io = @import("../../internal/stream_io.zig");
const net = std.Io.net;
const allocator = std.testing.allocator;

const Pair = struct {
    listener: net.Server,
    client: runtime.Client,
    peer: net.Stream,

    fn init(io: std.Io) !Pair {
        var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{});
        errdefer client.close();
        return .{ .listener = listener, .client = client, .peer = try listener.accept(io) };
    }

    fn deinit(self: *Pair) void {
        self.peer.close(self.client.io);
        self.listener.deinit(self.client.io);
        self.client.close();
    }

    fn respond(self: *Pair, bytes: []const u8) !void {
        try stream_io.writeAllSlices(self.client.io, self.peer, &.{bytes});
    }

    fn expectUnavailable(self: *Pair) !void {
        try std.testing.expect(!self.client.isReusable());
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        self.client.allocator = failing.allocator();
        defer self.client.allocator = allocator;
        try std.testing.expectError(error.ConnectionUnusable, self.client.request(.{ .method = .GET, .target = "/late", .host = "localhost" }));
        try std.testing.expect(!failing.has_induced_failure);
    }

    fn expectAborted(self: *Pair) !void {
        const deadline = std.Io.Clock.Timestamp.fromNow(self.client.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        var request: [4096]u8 = undefined;
        var used: usize = 0;
        while (std.mem.indexOf(u8, request[0..used], "\r\n\r\n") == null) {
            const count = try stream_io.readSomeWithDeadline(self.client.io, self.peer, request[used..], deadline);
            if (count == 0) return error.TestUnexpectedResult;
            used += count;
        }
        try std.testing.expectEqual(used, std.mem.indexOf(u8, request[0..used], "\r\n\r\n").? + 4);
        var byte: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 0), try stream_io.readSomeWithDeadline(self.client.io, self.peer, &byte, deadline));
    }
};

test "HTTP/1 handoff invalid 101 retires HTTP and aborts the upgraded peer" {
    const responses = [_][]const u8{
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: other\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: netz-test\r\n\r\n",
        "HTTP/1.0 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: netz-test\r\n\r\n",
        "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: other\r\n\r\n\x81\x00",
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (responses) |response| {
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        try pair.respond(response);
        try std.testing.expectError(error.InvalidResponse, pair.client.openUpgradeWithTimeout("/upgrade", "localhost", "netz-test", &.{}, .fromSeconds(1)));
        try pair.expectUnavailable();
        try pair.expectAborted();
    }
}

test "HTTP/1 handoff successful CONNECT retires aggregate clients across 2xx" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_][]const u8{ "HTTP/1.1 200 Connection Established\r\n\r\n", "HTTP/1.1 299 Connected\r\n\r\n" }) |reply| {
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        try pair.respond(reply);
        var response = try pair.client.requestWithTimeout(.{ .method = .CONNECT, .target = "example.com:443", .host = "example.com:443" }, .fromSeconds(1));
        defer response.deinit(allocator);
        try std.testing.expect(response.response.status >= 200 and response.response.status < 300);
        try pair.expectUnavailable();
    }
}

test "HTTP/1 handoff rejection respects response connection and EOF boundaries" {
    const cases = [_]struct { response: []const u8, eof: bool = false }{
        .{ .response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope" },
        .{ .response = "HTTP/1.0 403 Forbidden\r\nContent-Length: 4\r\n\r\nnope" },
        .{ .response = "HTTP/1.1 403 Forbidden\r\nConnection: keep-alive\r\n\r\nnope", .eof = true },
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |upgrade| {
        for (cases) |case| {
            var pair = try Pair.init(threaded.io());
            defer pair.deinit();
            try pair.respond(case.response);
            if (case.eof) try pair.peer.shutdown(threaded.io(), .send);
            if (upgrade) {
                try std.testing.expectError(error.InvalidResponse, pair.client.openUpgradeWithTimeout("/upgrade", "localhost", "netz-test", &.{}, .fromSeconds(1)));
            } else {
                try std.testing.expectError(error.InvalidResponse, pair.client.openConnectTunnelWithTimeout("example.com:443", &.{}, .fromSeconds(1)));
            }
            try pair.expectUnavailable();
        }
    }
}

test "HTTP/1 handoff ordinary framed rejection preserves the next HTTP exchange" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |upgrade| {
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        try pair.respond("HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\nTrailer: X-Rejected\r\n\r\n4\r\nnope\r\n0\r\nX-Rejected: yes\r\n\r\n");
        if (upgrade) {
            try std.testing.expectError(error.InvalidResponse, pair.client.openUpgradeWithTimeout("/upgrade", "localhost", "netz-test", &.{}, .fromSeconds(1)));
        } else {
            try std.testing.expectError(error.InvalidResponse, pair.client.openConnectTunnelWithTimeout("example.com:443", &.{}, .fromSeconds(1)));
        }
        try std.testing.expect(pair.client.isReusable());
        try pair.respond("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext");
        var response = try pair.client.requestWithTimeout(.{ .method = .GET, .target = "/next", .host = "localhost" }, .fromSeconds(1));
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("next", response.response.body);
        try std.testing.expect(pair.client.isReusable());
    }
}

test "HTTP/1 handoff CONNECT rejection respects a caller's Connection close" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io());
    defer pair.deinit();
    try pair.respond("HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\nnope");
    try std.testing.expectError(error.InvalidResponse, pair.client.openConnectTunnelWithTimeout("example.com:443", &.{.{ .name = "Connection", .value = "close" }}, .fromSeconds(1)));
    try pair.expectUnavailable();
}

test "HTTP/1 handoff pool discards switched clients instead of caching them" {
    const Pool = @import("../client_pool.zig").Pool;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]bool{ false, true }) |upgrade| {
        var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        var pool = try Pool.init(allocator, io, .{});
        defer pool.deinit();
        const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/", .{listener.socket.address.ip4.port});
        defer allocator.free(uri);
        var lease = try pool.acquireUri(uri);
        defer lease.release();
        const peer = try listener.accept(io);
        defer peer.close(io);
        if (upgrade) {
            try stream_io.writeAllSlices(io, peer, &.{"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: other\r\n\r\n"});
            try std.testing.expectError(error.InvalidResponse, lease.client().openUpgradeWithTimeout("/upgrade", "localhost", "netz-test", &.{}, .fromSeconds(1)));
        } else {
            try stream_io.writeAllSlices(io, peer, &.{"HTTP/1.1 200 Connection Established\r\n\r\n"});
            var response = try lease.client().requestWithTimeout(.{ .method = .CONNECT, .target = "example.com:443", .host = "example.com:443" }, .fromSeconds(1));
            defer response.deinit(allocator);
        }
        lease.release();
        try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
        try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    }
}

test "HTTP/1 handoff TLS invalid 101 aborts both client backends without releasing their owners" {
    const tls_testing = @import("../../tls/testing.zig");
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    for ([_]bool{ false, true }) |native_tls| {
        var server = try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .identity = .{
            .certificate_chain = &.{&certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } });
        defer server.deinit();
        const Worker = struct {
            fn run(target: *runtime.TlsServer) !void {
                var connection = try target.acceptWithTimeout(.fromSeconds(2));
                defer connection.close();
                var request = try connection.readRequestWithTimeout(.{}, .fromSeconds(2));
                defer request.deinit(allocator);
                try connection.tls_server_conn.?.writeAllSlices(&.{"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: other\r\n\r\n\x81\x00"});
                var byte: [1]u8 = undefined;
                const deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
                try std.testing.expectEqual(@as(usize, 0), try stream_io.readSomeWithDeadline(connection.io, connection.stream, &byte, deadline));
            }
        };
        var future = std.Io.async(io, Worker.run, .{&server});
        defer future.cancel(io) catch {};
        var client = if (native_tls)
            try runtime.Client.connectVailTlsAddress(allocator, io, server.address(), "localhost", .{}, .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1() } })
        else
            try runtime.Client.connectTlsAddress(allocator, io, server.address(), "localhost", "localhost", .{}, .{ .verify_host = false });
        defer client.close();
        try std.testing.expectError(error.InvalidResponse, client.openUpgradeWithTimeout("/upgrade", "localhost", "netz-test", &.{}, .fromSeconds(2)));
        try std.testing.expect(!client.isReusable());
        try std.testing.expectError(error.ConnectionUnusable, client.request(.{ .method = .GET, .target = "/late" }));
        try std.testing.expect(if (native_tls) client.tls_vail_conn != null else client.tls_conn != null);
        try future.await(io);
    }
}
