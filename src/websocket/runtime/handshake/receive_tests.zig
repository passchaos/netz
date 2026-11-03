const std = @import("std");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");
const stream_io = @import("../../../internal/stream_io.zig");

const Framing = enum { fixed, chunked, close_delimited };
const Budget = enum { phase, phase_with_outer, outer };
const Delivery = enum { stalled, trickled, complete };
const Transport = enum { tcp, native_tls, standard_tls };

test "WebSocket rejected HTTP1 body uses HTTP phase deadline" {
    inline for (std.enums.values(Transport)) |transport| {
        for (std.enums.values(Framing)) |framing| try rejection(transport, framing, .phase, .stalled);
    }
}

test "WebSocket rejected HTTP1 body preserves earlier phase or caller deadline" {
    inline for (std.enums.values(Transport)) |transport| {
        for (std.enums.values(Framing)) |framing| {
            try rejection(transport, framing, .phase_with_outer, .stalled);
            try rejection(transport, framing, .outer, .stalled);
        }
    }
}

test "WebSocket rejected HTTP1 trickled body does not renew opening deadline" {
    inline for (std.enums.values(Transport)) |transport| {
        for (std.enums.values(Framing)) |framing| try rejection(transport, framing, .phase_with_outer, .trickled);
    }
}

test "WebSocket rejected HTTP1 complete body and trailers survive bounded receive" {
    inline for (std.enums.values(Transport)) |transport| {
        for (std.enums.values(Framing)) |framing| try rejection(transport, framing, .phase_with_outer, .complete);
    }
}

fn write(pending: *runtime.PendingUpgrade, bytes: []const u8) !void {
    switch (pending.transport) {
        .tcp => |tcp| try stream_io.writeAllParts(tcp.io, tcp.stream, bytes, &.{}),
        .tls_server => |connection| try connection.writeAll(bytes),
        else => unreachable,
    }
}

fn waitForClose(pending: *runtime.PendingUpgrade) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(pending.io, .{ .raw = .fromSeconds(2), .clock = .awake });
    var byte: [1]u8 = undefined;
    const count = switch (pending.transport) {
        .tcp => |tcp| stream_io.readSomeWithDeadline(tcp.io, tcp.stream, &byte, deadline),
        .tls_server => |connection| connection.readWithDeadline(&byte, deadline),
        else => unreachable,
    };
    if (count) |n| {
        if (n != 0) return error.TestUnexpectedResult;
    } else |err| switch (err) {
        // Standard and native TLS clients may send close_notify or close the
        // socket directly when an unfinished HTTP attempt loses ownership.
        error.ConnectionClosed, error.TruncatedRecord, error.ConnectionResetByPeer => {},
        else => return err,
    }
}

fn rejection(comptime transport: Transport, framing: Framing, budget: Budget, delivery: Delivery) !void {
    const secure = transport != .tcp;
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
        server: *@TypeOf(server),
        framing: Framing,
        delivery: Delivery,
        head_sent: bool = false,
        body_parts_sent: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequestWithTimeout(.{}, .fromSeconds(3));
            defer pending.deinit();
            const head = switch (self.framing) {
                .fixed => "HTTP/1.1 401 Unauthorized\r\nContent-Length: 4\r\nX-Auth: expired\r\nConnection: close\r\n\r\n",
                .chunked => "HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\nTrailer: X-Detail\r\nX-Auth: expired\r\nConnection: close\r\n\r\n",
                .close_delimited => "HTTP/1.1 401 Unauthorized\r\nX-Auth: expired\r\nConnection: close\r\n\r\n",
            };
            try write(&pending, head);
            self.head_sent = true;
            if (self.delivery == .stalled) return waitForClose(&pending);
            if (self.delivery == .trickled) {
                for ("nope") |byte| {
                    // Each piece arrives before a renewed 150-ms timeout, but
                    // the complete body outlives the original HTTP deadline.
                    try std.Io.sleep(pending.io, .fromMilliseconds(60), .awake);
                    const part: [6]u8 = .{ '1', '\r', '\n', byte, '\r', '\n' };
                    write(&pending, if (self.framing == .chunked) &part else part[3..4]) catch break;
                    self.body_parts_sent += 1;
                }
                if (self.body_parts_sent == 4) {
                    if (self.framing == .chunked) write(&pending, "0\r\nX-Detail: denied\r\n\r\n") catch {};
                    // Complete all three framing forms, including TLS EOF.
                    // A reader that renews its budget would now succeed.
                    return;
                }
                return waitForClose(&pending);
            }
            try write(&pending, if (self.framing == .chunked) "4\r\nnope\r\n0\r\nX-Detail: denied\r\n\r\n" else "nope");
        }
    };
    var peer = Peer{ .server = &server, .framing = framing, .delivery = delivery };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();

    const options = runtime.ConnectOptions{
        .host = "localhost",
        .limits = .{ .http1_handshake_timeout = if (delivery == .complete or budget == .outer) .fromSeconds(3) else if (delivery == .stalled) .fromSeconds(1) else .fromMilliseconds(150) },
        .tls_identity = if (transport == .native_tls) .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() }, .protocol_policy = .tls13_only } else null,
    };
    // The native TLS arm pins the test identity; the standard TLS arm exercises
    // its separate record reader without loading the machine's root store.
    const tls_options = @import("../../../http1/runtime.zig").TlsClientOptions{ .verify_host = transport != .standard_tls };
    const outer_timeout = if (budget == .outer) std.Io.Duration.fromMilliseconds(150) else std.Io.Duration.fromSeconds(3);
    const result = if (secure) (if (budget == .phase) runtime.Client.connectTlsAddressAttempt(allocator, io, server.address(), "localhost", options, tls_options) else runtime.Client.connectTlsAddressAttemptWithTimeout(allocator, io, server.address(), "localhost", options, tls_options, outer_timeout)) else (if (budget == .phase) runtime.Client.connectAttempt(allocator, io, server.address(), options) else runtime.Client.connectAttemptWithTimeout(allocator, io, server.address(), options, outer_timeout));
    if (delivery == .complete) {
        var attempt = try result;
        defer attempt.deinit();
        try std.testing.expect(!attempt.accepted());
        try std.testing.expect(attempt.transport == null);
        try std.testing.expectEqual(@as(u16, 401), attempt.status());
        try std.testing.expectEqualStrings("expired", attempt.responseHeader("x-auth").?);
        try std.testing.expectEqualStrings("nope", attempt.body());
        if (framing == .chunked) {
            try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
            try std.testing.expectEqualStrings("X-Detail", attempt.trailers()[0].name);
            try std.testing.expectEqualStrings("denied", attempt.trailers()[0].value);
        }
        try std.testing.expectError(error.InvalidResponse, attempt.requireAccepted());
    } else if (result) |value| {
        var unexpected = value;
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.Timeout, err);

    thread.join();
    joined = true;
    if (peer.err) |err| return err;
    try std.testing.expect(peer.head_sent);
    if (delivery == .trickled) try std.testing.expect(peer.body_parts_sent >= 1);
}
