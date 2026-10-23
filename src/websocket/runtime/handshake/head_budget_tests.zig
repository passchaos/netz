const std = @import("std");
const http1 = @import("../../../http1/mod.zig");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");

test "WebSocket pending 101 head limit precedes descriptor and byte allocation" {
    inline for (.{ false, true }) |secure| try oversizedResponse(secure, false);
}

test "WebSocket pending rejection head limit precedes descriptor and byte allocation" {
    inline for (.{ false, true }) |secure| try oversizedResponse(secure, true);
}

fn oversizedResponse(comptime secure: bool, reject: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    var server = if (secure) try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .cipher_suites = &.{.aes_128_gcm_sha256},
    }) else try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        io: std.Io,
        address: std.Io.net.IpAddress,
        public_key: [65]u8,
        reject: bool,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.connect() catch |err| {
                self.err = err;
            };
        }

        fn connect(self: *@This()) !void {
            const options = runtime.ConnectOptions{
                .host = "localhost",
                .target = "/head-budget",
                .protocols = &.{"echo.v1"},
                .enable_permessage_deflate = true,
                .tls_identity = if (secure) .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = self.public_key }, .protocol_policy = .tls13_only } else null,
            };
            var attempt = if (secure) try runtime.Client.connectTlsAddressAttemptWithTimeout(allocator, self.io, self.address, "localhost", options, .{}, .fromSeconds(3)) else try runtime.Client.connectAttemptWithTimeout(allocator, self.io, self.address, options, .fromSeconds(3));
            var attempt_owned = true;
            defer if (attempt_owned) attempt.deinit();
            try std.testing.expectEqual(!self.reject, attempt.accepted());
            var fields: usize = 0;
            for (attempt.headers()) |header| fields += @intFromBool(header.eqlName("x-budget"));
            try std.testing.expectEqual(@as(usize, 20), fields);
            if (self.reject) {
                try std.testing.expectEqual(@as(u16, 401), attempt.status());
                try std.testing.expectEqualStrings("denied", attempt.body());
            } else {
                var connection = try attempt.requireAccepted();
                attempt_owned = false;
                connection.close();
            }
        }
    };
    var peer = Peer{ .io = io, .address = server.address(), .public_key = key.public_key.toUncompressedSec1(), .reject = reject };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    const fields: [20]http1.Header = @splat(.{ .name = "X-Budget", .value = "ok" });
    var pending = try server.receiveUpgradeRequestWithTimeout(.{
        .protocols = &.{"echo.v1"},
        .enable_permessage_deflate = true,
        .extra_headers = if (reject) &.{} else fields[0..10],
    }, .fromSeconds(3));
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    pending.limits.max_head_bytes = 1;
    {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        pending.allocator = failing.allocator();
        defer pending.allocator = allocator;
        if (reject) {
            try std.testing.expectError(error.HeadersTooLarge, pending.reject(401, "Unauthorized", &fields, "denied"));
        } else {
            try std.testing.expectError(error.HeadersTooLarge, pending.acceptWithHeaders(fields[10..]));
        }
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expect(!pending.response_write_failed);
        try std.testing.expectEqualStrings("/head-budget", pending.target());
    }
    // A valid response on this same transport proves the failed attempt left
    // neither a wire prefix nor terminal state behind, including WSS framing.
    pending.limits.max_head_bytes = 4096;
    if (reject) {
        try pending.reject(401, "Unauthorized", &fields, "denied");
        pending_owned = false;
    } else {
        var connection = try pending.acceptWithHeaders(fields[10..]);
        pending_owned = false;
        connection.close();
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
