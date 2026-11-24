const std = @import("std");
const runtime = @import("../runtime.zig");
const zio = @import("zio");
const tls_testing = @import("../../tls/testing.zig");
const net = std.Io.net;

test "WebSocket named endpoint formats IPv6 Upgrade authority" {
    const allocator = std.testing.allocator;
    var backend = try zio.Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip6 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequestWithTimeout(.{}, .fromSeconds(2));
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(self.expected, pending.header("host").?);
            var connection = try pending.accept();
            pending_owned = false;
            defer connection.close();
        }
    };
    var authority_buffer: [80]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buffer, "[::1]:{d}", .{server.address().getPort()});
    const cases = [_]struct { host: []const u8, bounded: bool, override: []const u8 = "" }{
        .{ .host = "::1", .bounded = false },
        .{ .host = "[::1]", .bounded = true },
        .{ .host = "0:0:0:0:0:0:0:1", .bounded = true },
        .{ .host = "[::1]", .bounded = false, .override = "virtual.example:8080" },
    };
    for (cases) |case| {
        var peer = Peer{ .server = &server, .expected = if (case.override.len > 0) case.override else authority };
        var accepting = try io.concurrent(Peer.run, .{&peer});
        defer accepting.cancel(io);
        const options: runtime.ConnectOptions = .{ .host = case.override };
        const result = if (case.bounded)
            runtime.Client.connectHostWithTimeout(allocator, io, case.host, server.address().getPort(), options, .fromSeconds(2))
        else
            runtime.Client.connectHost(allocator, io, case.host, server.address().getPort(), options);
        var client = result catch |err| {
            accepting.await(io);
            return peer.err orelse err;
        };
        defer client.close();
        accepting.await(io);
        if (peer.err) |err| return err;
    }
}

const Route = enum { host, address, uri, adopted };

test "WSS common handshake budget is inherited by named address URI and adopted connects" {
    const allocator = std.testing.allocator;
    var backend = try zio.Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const SilentPeer = struct {
        io: std.Io,
        listener: *net.Server,
        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(self.io, .fromMilliseconds(120), .awake) catch {};
        }
    };
    inline for (.{ false, true }) |vail_tls| {
        inline for (.{ Route.host, Route.address, Route.uri, Route.adopted }) |route| {
            var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
            defer listener.deinit(io);
            var peer = SilentPeer{ .io = io, .listener = &listener };
            var accepting = try io.concurrent(SilentPeer.run, .{&peer});
            defer accepting.cancel(io);
            const options: runtime.ConnectOptions = .{
                .host = "localhost",
                .tls_handshake_timeout = .fromMilliseconds(10),
                .vail_tls = if (vail_tls) .{} else null,
            };
            const tls: runtime.http1_runtime.TlsClientOptions = .{ .verify_host = false };
            const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
            var uri_buffer: [80]u8 = undefined;
            const uri = try std.fmt.bufPrint(&uri_buffer, "wss://127.0.0.1:{d}/", .{listener.socket.address.getPort()});
            const result = switch (route) {
                .host => runtime.Client.connectTlsHostWithDeadline(allocator, io, "127.0.0.1", listener.socket.address.getPort(), options, tls, deadline),
                .address => runtime.Client.connectTlsAddressWithDeadline(allocator, io, listener.socket.address, "localhost", options, tls, deadline),
                .uri => runtime.Client.connectUriTlsWithDeadline(allocator, io, uri, options, tls, deadline),
                .adopted => runtime.Client.connectAcceptedTlsStreamWithDeadline(allocator, io, try listener.socket.address.connect(io, .{ .mode = .stream }), "localhost", options, tls, deadline),
            };
            if (result) |value| {
                var client = value;
                client.close();
                return error.TestExpectedError;
            } else |err| try std.testing.expectEqual(@as(anyerror, error.Timeout), err);
            accepting.await(io);
        }
    }
}

test "WSS named endpoint preserves IPv6 authority and explicit handshake budgets" {
    const allocator = std.testing.allocator;
    var backend = try zio.Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate_der, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(allocator, io, .{ .ip6 = .loopback(0) }, .{
        .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        },
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.TlsServer,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            // A positive TLS budget must permit a delayed, successful peer.
            try std.Io.sleep(self.server.io, .fromMilliseconds(30), .awake);
            var pending = try self.server.receiveUpgradeRequestWithTimeout(.{}, .fromSeconds(2));
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(self.expected, pending.header("host").?);
            var connection = try pending.accept();
            pending_owned = false;
            defer connection.close();
        }
    };
    var authority_buffer: [80]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buffer, "[::1]:{d}", .{server.address().getPort()});
    const cases = [_]struct { route: Route, host: []const u8, bounded: bool, override: []const u8 = "" }{
        .{ .route = .host, .host = "::1", .bounded = false },
        .{ .route = .host, .host = "[::1]", .bounded = true },
        .{ .route = .host, .host = "0:0:0:0:0:0:0:1", .bounded = true, .override = "virtual.example:8443" },
        .{ .route = .address, .host = "::1", .bounded = false },
        .{ .route = .address, .host = "[::1]", .bounded = true },
        .{ .route = .adopted, .host = "localhost", .bounded = true, .override = "virtual.example:8443" },
        .{ .route = .uri, .host = "", .bounded = true, .override = "virtual.example:8443" },
    };
    const Policy = enum { standard, vail_explicit, vail_nested };
    const verifier: runtime.tls_client_identity.CertificateVerifier = .{
        .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1(),
    };
    for ([_]Policy{ .standard, .vail_explicit, .vail_nested }) |policy| {
        for (cases) |case| {
            var peer = Peer{ .server = &server, .expected = if (case.override.len > 0) case.override else authority };
            var accepting = try io.concurrent(Peer.run, .{&peer});
            defer accepting.cancel(io);
            const options: runtime.ConnectOptions = .{
                .host = case.override,
                .tls_handshake_timeout = .fromNanoseconds(0),
                .vail_tls = switch (policy) {
                    .standard => null,
                    .vail_explicit => .{ .server_verifier = verifier },
                    .vail_nested => .{ .server_verifier = verifier, .handshake_timeout = .fromSeconds(2) },
                },
            };
            const tls: runtime.http1_runtime.TlsClientOptions = .{
                .verify_host = false,
                .handshake_timeout = if (policy == .vail_nested) .fromNanoseconds(0) else .fromSeconds(2),
            };
            const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .raw = .fromSeconds(3), .clock = .awake });
            const port = server.address().getPort();
            var uri_buffer: [80]u8 = undefined;
            const uri = try std.fmt.bufPrint(&uri_buffer, "wss://[::1]:{d}/", .{port});
            const result = switch (case.route) {
                .host => if (case.bounded)
                    runtime.Client.connectTlsHostWithDeadline(allocator, io, case.host, port, options, tls, deadline)
                else
                    runtime.Client.connectTlsHost(allocator, io, case.host, port, options, tls),
                .address => if (case.bounded)
                    runtime.Client.connectTlsAddressWithDeadline(allocator, io, server.address(), case.host, options, tls, deadline)
                else
                    runtime.Client.connectTlsAddress(allocator, io, server.address(), case.host, options, tls),
                .uri => runtime.Client.connectUriTlsWithDeadline(allocator, io, uri, options, tls, deadline),
                .adopted => runtime.Client.connectAcceptedTlsStreamWithDeadline(allocator, io, try server.address().connect(io, .{ .mode = .stream }), case.host, options, tls, deadline),
            };
            var client = result catch |err| {
                accepting.await(io);
                std.debug.print("WSS IPv6 policy={s} route={s} host={s} bounded={} client={s} peer={any}\n", .{ @tagName(policy), @tagName(case.route), case.host, case.bounded, @errorName(err), peer.err });
                return peer.err orelse err;
            };
            defer client.close();
            accepting.await(io);
            if (peer.err) |err| return err;
        }
    }
}
