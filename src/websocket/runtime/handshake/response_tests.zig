const std = @import("std");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");

const ObservedWrite = struct {
    delegate: std.Io,
    armed: bool = false,
    delay_body: bool = false,
    fail_prefix: bool = false,
    calls: usize = 0,

    // Keep Threaded's userdata for receive, cancellation, and clock callbacks.
    var active: ?*ObservedWrite = null;

    fn netWrite(
        userdata: ?*anyopaque,
        handle: std.Io.net.Socket.Handle,
        header: []const u8,
        data: []const []const u8,
        splat: usize,
    ) std.Io.net.Stream.Writer.Error!usize {
        const self = active.?;
        if (!self.armed) return self.delegate.vtable.netWrite(userdata, handle, header, data, splat);
        const ordinal = self.calls;
        self.calls += 1;
        if (ordinal == 0 and (self.delay_body or self.fail_prefix)) {
            const prefix = if (self.fail_prefix) header[0..@min(header.len, 7)] else header;
            return self.delegate.vtable.netWrite(userdata, handle, prefix, &.{""}, 0);
        }
        if (self.fail_prefix and ordinal == 1) return error.NetworkDown;
        if ((!self.delay_body and ordinal == 0) or (self.delay_body and ordinal == 1)) {
            try std.Io.sleep(self.delegate, .fromMilliseconds(150), .awake);
        }
        return self.delegate.vtable.netWrite(userdata, handle, header, data, splat);
    }
};

test "WebSocket pending Upgrade deadline bounds 101 response writing" {
    inline for (.{ false, true }) |secure| try responseFailure(false, false, secure);
}

test "WebSocket pending Upgrade rejection keeps one deadline through body" {
    inline for (.{ false, true }) |secure| try responseFailure(true, false, secure);
}

test "WebSocket pending Upgrade partial write failure blocks another response" {
    inline for (.{ false, true }) |secure| try responseFailure(false, true, secure);
}

test "WebSocket unsupported version response retains opening deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = ObservedWrite{ .delegate = io, .armed = true };
    ObservedWrite.active = &observer;
    defer ObservedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = ObservedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var server = try runtime.Server.listen(allocator, observed_io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Client = struct {
        io: std.Io,
        address: std.Io.net.IpAddress,

        fn run(self: *@This()) void {
            const stream = self.address.connect(self.io, .{ .mode = .stream }) catch return;
            defer stream.close(self.io);
            var writer = stream.writer(self.io, &.{});
            writer.interface.writeAll(
                "GET /version HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 12\r\n\r\n",
            ) catch return;
            var buffer: [512]u8 = undefined;
            var buffers = [_][]u8{&buffer};
            _ = self.io.vtable.netRead(self.io.userdata, stream.socket.handle, &buffers) catch return;
        }
    };
    var client = Client{ .io = io, .address = server.address() };
    const thread = try std.Thread.spawn(.{}, Client.run, .{&client});
    defer thread.join();
    if (server.receiveUpgradeRequestWithTimeout(.{}, .fromMilliseconds(75))) |value| {
        var unexpected = value;
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.Timeout, err);
    try std.testing.expect(observer.calls != 0);
}

fn responseFailure(reject: bool, fail_prefix: bool, comptime secure: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = ObservedWrite{ .delegate = io, .delay_body = reject, .fail_prefix = fail_prefix };
    ObservedWrite.active = &observer;
    defer ObservedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = ObservedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    var server = if (secure) try runtime.TlsServer.listen(allocator, observed_io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .cipher_suites = &.{.aes_128_gcm_sha256},
    }) else try runtime.Server.listen(allocator, observed_io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Client = struct {
        io: std.Io,
        address: std.Io.net.IpAddress,
        accepted: bool = false,
        public_key: [65]u8,

        fn run(self: *@This()) void {
            const result = if (secure) runtime.Client.connectTlsAddressAttemptWithTimeout(std.testing.allocator, self.io, self.address, "localhost", .{
                .host = "localhost",
                .target = "/response-budget",
                .tls_identity = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = self.public_key } },
            }, .{}, .fromSeconds(3)) else runtime.Client.connectAttemptWithTimeout(std.testing.allocator, self.io, self.address, .{
                .host = "localhost",
                .target = "/response-budget",
            }, .fromSeconds(3));
            var attempt = result catch return;
            defer attempt.deinit();
            self.accepted = attempt.accepted();
        }
    };
    var client = Client{ .io = io, .address = server.address(), .public_key = key.public_key.toUncompressedSec1() };
    const thread = try std.Thread.spawn(.{}, Client.run, .{&client});
    var joined = false;
    defer if (!joined) thread.join();
    var pending = try server.receiveUpgradeRequestWithTimeout(.{}, .fromSeconds(3));
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    pending.deadline = if (fail_prefix) null else .fromNow(io, .{ .raw = .fromMilliseconds(50), .clock = .awake });
    observer.armed = true;
    if (reject) {
        pending.reject(403, "Forbidden", &.{}, "denied") catch |err| {
            try std.testing.expectEqual(error.Timeout, err);
            try std.testing.expectEqualStrings("/response-budget", pending.target());
            if (secure) try std.testing.expect(pending.negotiatedCipherSuite() != null);
            try expectNoResponseRetry(&pending, &pending_owned);
            thread.join();
            joined = true;
            return;
        };
        pending_owned = false;
        return error.TestUnexpectedResult;
    }
    if (pending.accept()) |value| {
        var connection = value;
        pending_owned = false;
        connection.close();
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(if (fail_prefix) error.NetworkDown else error.Timeout, err);
    }
    try std.testing.expectEqualStrings("/response-budget", pending.target());
    if (secure) try std.testing.expect(pending.negotiatedCipherSuite() != null);
    try expectNoResponseRetry(&pending, &pending_owned);
    thread.join();
    joined = true;
    try std.testing.expect(!client.accepted);
}

fn expectNoResponseRetry(pending: *runtime.PendingUpgrade, owned: *bool) !void {
    if (pending.accept()) |value| {
        var connection = value;
        owned.* = false;
        connection.close();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.ConnectionClosed, err);
    pending.forbidden() catch |err| {
        try std.testing.expectEqual(error.ConnectionClosed, err);
        return;
    };
    owned.* = false;
    return error.TestUnexpectedResult;
}
