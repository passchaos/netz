const std = @import("std");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");

const Fault = enum { delayed, partial_timeout, partial_failure };
const Entry = enum { address, caller_stream };

const ObservedWrite = struct {
    delegate: std.Io,
    fault: Fault,
    armed: std.atomic.Value(bool) = .init(false),
    cancelled: std.atomic.Value(bool) = .init(false),
    calls: usize = 0,
    var active: ?*ObservedWrite = null;

    fn randomSecure(userdata: ?*anyopaque, bytes: []u8) std.Io.RandomSecureError!void {
        const self = active.?;
        try self.delegate.vtable.randomSecure(userdata, bytes);
        // The HTTP client draws its 16-byte WebSocket nonce after TLS/proxy
        // setup. Arm at that boundary so only Upgrade output is delayed.
        if (bytes.len == 16) self.armed.store(true, .release);
    }

    fn netWrite(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.?;
        if (!self.armed.load(.acquire)) return self.delegate.vtable.netWrite(userdata, handle, header, data, splat);
        const ordinal = self.calls;
        self.calls += 1;
        if (self.fault != .delayed and ordinal == 0) {
            return self.delegate.vtable.netWrite(userdata, handle, header[0..@min(header.len, 7)], &.{""}, 0);
        }
        if (self.fault == .partial_failure and ordinal == 1) return error.NetworkDown;
        if ((self.fault == .delayed and ordinal == 0) or (self.fault == .partial_timeout and ordinal == 1)) {
            std.Io.sleep(self.delegate, .fromMilliseconds(150), .awake) catch |err| {
                self.cancelled.store(true, .release);
                return err;
            };
        }
        return self.delegate.vtable.netWrite(userdata, handle, header, data, splat);
    }
};

test "WebSocket client HTTP phase timeout includes Upgrade request writing" {
    inline for (.{ false, true }) |secure| try requestFailure(secure, .address, .delayed, false);
}

test "WebSocket client caller deadline cancels partial Upgrade request writing" {
    try requestFailure(false, .address, .partial_timeout, true);
}

test "WebSocket caller stream Upgrade failure closes transferred transport" {
    inline for (.{ false, true }) |secure| try requestFailure(secure, .caller_stream, .partial_failure, true);
}

test "WebSocket caller stream HTTP phase budget stays shorter than outer deadline" {
    inline for (.{ false, true }) |secure| try requestFailure(secure, .caller_stream, .partial_timeout, false);
}

fn requestFailure(comptime secure: bool, entry: Entry, fault: Fault, outer_budget: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = ObservedWrite{ .delegate = io, .fault = fault };
    ObservedWrite.active = &observer;
    defer ObservedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = ObservedWrite.netWrite;
    vtable.randomSecure = ObservedWrite.randomSecure;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    var server = if (secure) try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .cipher_suites = &.{.aes_128_gcm_sha256},
    }) else try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *@TypeOf(server),
        upgraded: bool = false,
        failed: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.acceptWithTimeout(.{}, .fromSeconds(3)) catch |err| {
                self.failed = true;
                self.err = err;
                return;
            };
            self.upgraded = true;
            connection.close();
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    const options = runtime.ConnectOptions{
        .host = "localhost",
        .target = "/request-budget",
        .connect_timeout = .fromSeconds(1),
        .limits = .{ .http1_handshake_timeout = if (outer_budget) .fromSeconds(1) else .fromMilliseconds(50) },
        .tls_identity = if (secure) .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() }, .protocol_policy = .tls13_only } else null,
    };
    const timeout = if (fault == .partial_failure) std.Io.Duration.fromSeconds(3) else if (entry == .caller_stream and !outer_budget) std.Io.Duration.fromMilliseconds(500) else std.Io.Duration.fromMilliseconds(50);
    const result = if (entry == .caller_stream) blk: {
        const stream = try server.address().connect(io, .{ .mode = .stream });
        // Ownership transfers to these helpers even when the Upgrade fails.
        break :blk if (secure) runtime.Client.connectAcceptedTlsStreamAttemptWithTimeout(allocator, observed_io, stream, "localhost", options, .{}, timeout) else runtime.Client.connectAcceptedStreamAttemptWithTimeout(allocator, observed_io, stream, options, timeout);
    } else if (secure and outer_budget) runtime.Client.connectTlsAddressAttemptWithTimeout(allocator, observed_io, server.address(), "localhost", options, .{}, timeout) else if (secure) runtime.Client.connectTlsAddressAttempt(allocator, observed_io, server.address(), "localhost", options, .{}) else if (outer_budget) runtime.Client.connectAttemptWithTimeout(allocator, observed_io, server.address(), options, timeout) else runtime.Client.connectAttempt(allocator, observed_io, server.address(), options);
    if (result) |value| {
        var unexpected = value;
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(if (fault == .partial_failure) error.NetworkDown else error.Timeout, err);
    if (fault != .partial_failure) try std.testing.expect(observer.cancelled.load(.acquire));
    thread.join();
    joined = true;
    try std.testing.expect(peer.failed);
    try std.testing.expect(!peer.upgraded);
    try std.testing.expect(peer.err.? != error.Timeout);
}
