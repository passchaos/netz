const std = @import("std");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");
const net = std.Io.net;

test "HTTP1 named endpoint retains IPv6 network interface and local address constraints" {
    const checks = @import("../../../internal/network_interface_test_support.zig");
    if (!checks.supportedTcp()) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var backend = try @import("zio").Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip6 = .loopback(0) }, .{});
    defer server.deinit();
    var client = try runtime.Client.connectHostWithTimeout(allocator, io, "[::1]", server.address().getPort(), .{
        .local_address = .{ .ip6 = .loopback(0) },
        .network_interface = checks.loopback(),
    }, .fromSeconds(2));
    defer client.close();
    var peer = try server.acceptWithTimeout(.fromSeconds(2));
    defer peer.close();
    try checks.expectBound(io, client.stream.socket);
    try std.testing.expectEqual(client.stream.socket.address.getPort(), peer.stream.socket.address.getPort());
}

test "HTTP1 named endpoint validates identity budgets and OOM before network admission" {
    inline for (.{ 0, 1, 2 }) |backend| {
        const Connect = struct {
            fn run(allocator: std.mem.Allocator, host: []const u8, limits: runtime.Limits, deadline: ?std.Io.Clock.Timestamp) runtime.Error!runtime.Client {
                if (backend == 0) return if (deadline) |absolute| runtime.Client.connectHostWithDeadline(allocator, undefined, host, 443, limits, absolute) else runtime.Client.connectHost(allocator, undefined, host, 443, limits);
                if (backend == 1) return if (deadline) |absolute| runtime.Client.connectTlsHostWithDeadline(allocator, undefined, host, 443, limits, .{}, absolute) else runtime.Client.connectTlsHost(allocator, undefined, host, 443, limits, .{});
                return if (deadline) |absolute| runtime.Client.connectVailTlsHostWithDeadline(allocator, undefined, host, 443, limits, .{}, absolute) else runtime.Client.connectVailTlsHost(allocator, undefined, host, 443, limits, .{});
            }
        };
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        const allocator = failing.allocator();
        try std.testing.expectError(error.InvalidHostName, Connect.run(allocator, "[::1]:443", .{}, null));
        try std.testing.expectError(error.Timeout, Connect.run(allocator, "[::1]", .{ .connect_timeout = .zero }, null));
        try std.testing.expectError(error.Timeout, Connect.run(allocator, "::1", .{}, .{ .clock = .real, .raw = .zero }));
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectError(error.OutOfMemory, Connect.run(allocator, "::1", .{}, null));
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

const ClearPeer = struct {
    server: *runtime.Server,
    expected: []const u8,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
        defer connection.close();
        var request = try connection.readRequestWithTimeout(.{}, .fromSeconds(2));
        defer request.deinit(self.server.allocator);
        try std.testing.expectEqualStrings(self.expected, request.request.header("host").?);
        try connection.writeResponse(.{ .body = "endpoint-ok" });
    }
};

test "HTTP1 named endpoint accepts IPv6 and formats default authority" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip6 = .loopback(0) }, .{});
    defer server.deinit();
    var authority_buffer: [80]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buffer, "[::1]:{d}", .{server.address().getPort()});
    const cases = [_]struct { host: []const u8, bounded: bool, override: ?[]const u8 = null }{
        .{ .host = "::1", .bounded = false },
        .{ .host = "[::1]", .bounded = true },
        .{ .host = "0:0:0:0:0:0:0:1", .bounded = true },
        .{ .host = "[::1]", .bounded = false, .override = "virtual.example:8080" },
    };
    for (cases) |case| {
        var client = if (case.bounded)
            try runtime.Client.connectHostWithTimeout(allocator, io, case.host, server.address().getPort(), .{}, .fromSeconds(2))
        else
            try runtime.Client.connectHost(allocator, io, case.host, server.address().getPort(), .{});
        defer client.close();
        try std.testing.expectEqualStrings(authority, client.default_host.?);
        var peer = ClearPeer{ .server = &server, .expected = case.override orelse authority };
        const thread = try std.Thread.spawn(.{}, ClearPeer.run, .{&peer});
        var joined = false;
        defer if (!joined) thread.join();
        var response = try client.requestWithTimeout(.{ .host = case.override }, .fromSeconds(2));
        defer response.deinit(allocator);
        thread.join();
        joined = true;
        if (peer.err) |err| return err;
        try std.testing.expectEqualStrings("endpoint-ok", response.response.body);
    }
}

const TlsPeer = struct {
    server: *runtime.TlsServer,
    expected: []const u8,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
        defer connection.close();
        var request = try connection.readRequestWithTimeout(.{}, .fromSeconds(2));
        defer request.deinit(self.server.allocator);
        try std.testing.expectEqualStrings(self.expected, request.request.header("host").?);
        try connection.writeResponse(.{ .body = "tls-endpoint-ok" });
    }
};

fn exerciseTls(comptime named: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate_der, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(allocator, io, .{ .ip6 = .loopback(0) }, .{
        .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        },
    });
    defer server.deinit();
    var authority_buffer: [80]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buffer, "[::1]:{d}", .{server.address().getPort()});
    const cases = [_]struct { host: []const u8, bounded: bool, override: ?[]const u8 = null }{
        .{ .host = "::1", .bounded = false },
        .{ .host = "[::1]", .bounded = true },
        .{ .host = "0:0:0:0:0:0:0:1", .bounded = true },
        .{ .host = "[::1]", .bounded = false, .override = "virtual.example:8443" },
    };
    inline for (.{ false, true }) |vail_tls| {
        for (cases) |case| {
            var peer = TlsPeer{ .server = &server, .expected = case.override orelse authority };
            const thread = try std.Thread.spawn(.{}, TlsPeer.run, .{&peer});
            var joined = false;
            defer if (!joined) thread.join();
            const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
            var client = if (vail_tls) blk: {
                const tls: runtime.VailTlsClientOptions = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1() }, .verify_host = false };
                break :blk if (named)
                    if (case.bounded) try runtime.Client.connectVailTlsHostWithDeadline(allocator, io, case.host, server.address().getPort(), .{}, tls, deadline) else try runtime.Client.connectVailTlsHost(allocator, io, case.host, server.address().getPort(), .{}, tls)
                else if (case.bounded) try runtime.Client.connectVailTlsAddressWithDeadline(allocator, io, server.address(), case.host, .{}, tls, deadline) else try runtime.Client.connectVailTlsAddress(allocator, io, server.address(), case.host, .{}, tls);
            } else blk: {
                const tls: runtime.TlsClientOptions = .{ .verify_host = false };
                break :blk if (named)
                    if (case.bounded) try runtime.Client.connectTlsHostWithDeadline(allocator, io, case.host, server.address().getPort(), .{}, tls, deadline) else try runtime.Client.connectTlsHost(allocator, io, case.host, server.address().getPort(), .{}, tls)
                else if (case.bounded) try runtime.Client.connectTlsAddressWithDeadline(allocator, io, server.address(), case.host, authority, .{}, tls, deadline) else try runtime.Client.connectTlsAddress(allocator, io, server.address(), case.host, authority, .{}, tls);
            };
            defer client.close();
            try std.testing.expectEqualStrings(authority, client.default_host.?);
            var response = try client.requestWithTimeout(.{ .host = case.override }, .fromSeconds(2));
            defer response.deinit(allocator);
            thread.join();
            joined = true;
            if (peer.err) |err| return err;
            try std.testing.expectEqualStrings("tls-endpoint-ok", response.response.body);
        }
    }
}

test "HTTP1 named endpoint TLS accepts IPv6 identities and request authority overrides" {
    try exerciseTls(true);
}

test "HTTP1 TLS address endpoint formats IPv6 identities and request authority overrides" {
    try exerciseTls(false);
}
