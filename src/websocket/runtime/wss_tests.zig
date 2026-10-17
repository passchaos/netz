const std = @import("std");
const websocket = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const tls_testing = @import("../../tls/testing.zig");

test "WSS server completes verified WebSocket echo" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var pending = shared.server.receiveUpgradeRequest(.{
                .protocols = &.{"echo.v1"},
                .require_subprotocol = true,
            }) catch |err| {
                shared.err = err;
                return;
            };
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            if (!std.mem.eql(u8, pending.target(), "/echo") or
                !std.mem.eql(
                    u8,
                    pending.header("authorization") orelse "",
                    "Bearer wss-admission",
                ))
            {
                shared.err = error.InvalidHandshake;
                return;
            }
            if (pending.peerCertificates() != null or
                pending.negotiatedCipherSuite() !=
                    .aes_128_gcm_sha256 or
                pending.negotiatedTranscriptHash() != .sha256)
            {
                shared.err = error.InvalidCipherSuite;
                return;
            }
            var connection = pending.accept() catch |err| {
                shared.err = err;
                return;
            };
            pending_owned = false;
            defer connection.close();
            if (connection.peerCertificates() != null) {
                shared.err = error.UnexpectedPeerCertificate;
                return;
            }
            if (connection.negotiatedCipherSuite() !=
                .aes_128_gcm_sha256 or
                connection.negotiatedTranscriptHash() != .sha256)
            {
                shared.err = error.InvalidCipherSuite;
                return;
            }
            var message = connection.receiveMessage() catch |err| {
                shared.err = err;
                return;
            };
            defer message.deinit(shared.server.allocator);
            connection.sendBinary(message.payload) catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const Resolver = struct {
        address: std.Io.net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "localhost") or
                port != self.address.getPort() or deadline == null)
            {
                return error.UnknownHostName;
            }
            const addresses = try resolve_allocator.alloc(
                std.Io.net.IpAddress,
                1,
            );
            addresses[0] = self.address;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return addresses;
        }
    };
    var resolver = Resolver{ .address = server.address() };
    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/echo",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try runtime.Client.connectUriTls(
        allocator,
        io,
        uri,
        .{
            .protocols = &.{"echo.v1"},
            .extra_headers = &.{.{
                .name = "Authorization",
                .value = "Bearer wss-admission",
            }},
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
            .connect_timeout = .fromSeconds(3),
            .address_resolver = .{
                .context = &resolver,
                .resolve = Resolver.resolve,
            },
        },
        .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    );
    defer client.close();
    // The standard-library client path cannot expose its authenticated chain;
    // vail-backed client-identity and ALPN paths do so below.
    try std.testing.expect(client.peerCertificates() == null);
    try std.testing.expect(client.negotiatedCipherSuite() == null);
    try std.testing.expect(client.negotiatedTranscriptHash() == null);
    try std.testing.expectError(
        error.TlsKeyUpdateUnavailable,
        client.updateTrafficKeys(false),
    );
    try client.sendBinary("encrypted websocket");
    var echoed = try client.receiveMessage();
    defer echoed.deinit(allocator);
    try std.testing.expectEqualStrings(
        "encrypted websocket",
        echoed.payload,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u8, 1), resolver.calls.load(.acquire));
}

test "WSS negotiates TLS 1.2 and completes an echo" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .tls12_cipher_suites = &.{
                .ecdhe_ecdsa_aes_128_gcm_sha256,
            },
            .protocol_policy = .tls12_only,
            .alpn_protocols = &.{"http/1.1"},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var pending = shared.server.receiveUpgradeRequest(.{}) catch |err| {
                shared.err = err;
                return;
            };
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            var connection = pending.accept() catch |err| {
                shared.err = err;
                return;
            };
            pending_owned = false;
            defer connection.close();
            if (connection.negotiatedTlsProtocol() != .tls12) {
                shared.err = error.InvalidProtocolVersion;
                return;
            }
            var message = connection.receiveMessage() catch |err| {
                shared.err = err;
                return;
            };
            defer message.deinit(std.testing.allocator);
            connection.sendBinary(message.payload) catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/tls12",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try runtime.Client.connectUriTls(
        allocator,
        io,
        uri,
        .{ .vail_tls = .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"http/1.1"},
            .tls12_cipher_suites = &.{
                .ecdhe_ecdsa_aes_128_gcm_sha256,
            },
            .protocol_policy = .tls12_only,
        } },
        .{},
    );
    defer client.close();
    try std.testing.expectEqual(
        tls_stream.Protocol.tls12,
        client.negotiatedTlsProtocol().?,
    );
    try client.sendBinary("tls12-wss");
    var echoed = try client.receiveMessage();
    defer echoed.deinit(allocator);
    try std.testing.expectEqualStrings("tls12-wss", echoed.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WSS client connects to resolved address with separate TLS host" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var message = connection.receiveMessage() catch |err| {
                self.err = err;
                return;
            };
            defer message.deinit(self.server.allocator);
            connection.sendBinary(message.payload) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var client = try runtime.Client.connectTlsAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{ .target = "/resolved" },
        .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    );
    defer client.close();
    try client.sendBinary("resolved wss");
    var echoed = try client.receiveMessage();
    defer echoed.deinit(allocator);
    try std.testing.expectEqualStrings("resolved wss", echoed.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WSS client attempt preserves rejected response metadata" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var pending = self.server.receiveUpgradeRequestWithTimeout(
                .{},
                .fromSeconds(3),
            ) catch |err| {
                self.err = err;
                return;
            };
            pending.reject(
                401,
                "Unauthorized",
                &.{.{ .name = "WWW-Authenticate", .value = "Bearer" }},
                "login required",
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/private",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var attempt = try runtime.Client.connectUriTlsAttemptWithTimeout(
        allocator,
        io,
        uri,
        .{},
        .{ .ca_bundle = .{ .bundle = &ca_bundle, .lock = &ca_lock } },
        .fromSeconds(3),
    );
    defer attempt.deinit();
    try std.testing.expectEqual(@as(u16, 401), attempt.status());
    try std.testing.expectEqualStrings(
        "Bearer",
        attempt.responseHeader("www-authenticate").?,
    );
    try std.testing.expectEqualStrings("login required", attempt.body());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "ordinary vail WSS client exposes TLS state and KeyUpdate" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
            .cipher_suites = &.{.aes_256_gcm_sha384},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        exporter: [32]u8 = undefined,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept(.{});
            defer connection.close();
            try connection.exportKeyingMaterial(
                "EXPORTER-netz-wss",
                "anonymous-client",
                &shared.exporter,
            );
            try connection.updateTrafficKeys(true);
            var message = try connection.receiveMessage();
            defer message.deinit(allocator);
            try std.testing.expectEqualStrings("vail wss", message.payload);
            try connection.sendBinary(message.payload);
            var second = try connection.receiveMessage();
            defer second.deinit(allocator);
            try std.testing.expectEqualStrings(
                "vail wss after update",
                second.payload,
            );
            try connection.sendBinary(second.payload);
            const updates = connection.keyUpdateCounts().?;
            try std.testing.expectEqual(@as(u64, 1), updates.sent);
            try std.testing.expectEqual(@as(u64, 1), updates.received);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
            .vail_tls = .{
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .cipher_suites = &.{.aes_256_gcm_sha384},
            },
        },
        .{},
    );
    defer client.close();
    const chain = client.peerCertificates() orelse
        return error.MissingPeerCertificate;
    try std.testing.expectEqualSlices(u8, &certificate_der, chain[0]);
    try std.testing.expectEqual(
        tls_stream.NegotiatedCipherSuite.aes_256_gcm_sha384,
        client.negotiatedCipherSuite().?,
    );
    var exporter: [32]u8 = undefined;
    try client.exportKeyingMaterial(
        "EXPORTER-netz-wss",
        "anonymous-client",
        &exporter,
    );
    try client.sendBinary("vail wss");
    var echoed = try client.receiveMessage();
    defer echoed.deinit(allocator);
    try std.testing.expectEqualStrings("vail wss", echoed.payload);
    try client.sendBinary("vail wss after update");
    var second_echo = try client.receiveMessage();
    defer second_echo.deinit(allocator);
    try std.testing.expectEqualStrings(
        "vail wss after update",
        second_echo.payload,
    );
    try std.testing.expectEqualSlices(u8, &shared.exporter, &exporter);
    const updates = client.keyUpdateCounts().?;
    try std.testing.expectEqual(@as(u64, 1), updates.sent);
    try std.testing.expectEqual(@as(u64, 1), updates.received);
    client.receive_failed.store(true, .release);
    const before_terminal = client.keyUpdateCounts().?;
    try std.testing.expectError(
        error.ConnectionClosed,
        client.updateTrafficKeys(false),
    );
    try std.testing.expectEqual(
        before_terminal,
        client.keyUpdateCounts().?,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WSS compression threshold and context takeover propagate through TLS endpoints" {
    const allocator = std.testing.allocator;
    const below = "wss-below-threshold";
    const at_threshold = "wss-threshold-compressible-" ** 10;
    const threshold = at_threshold.len;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .compression_threshold = threshold,
            });
            defer connection.close();
            try std.testing.expect(
                connection.compression_send_context_takeover,
            );
            try std.testing.expect(
                connection.compression_receive_context_takeover,
            );

            var first = try connection.receiveFrame();
            defer first.deinit(self.server.allocator);
            try std.testing.expect(!first.header.rsv1);
            try std.testing.expectEqualStrings(below, first.payload);

            var second = try connection.receiveFrame();
            defer second.deinit(self.server.allocator);
            try std.testing.expect(second.header.rsv1);
            const decoded = try websocket.decompressMessage(
                self.server.allocator,
                second.payload,
                at_threshold.len,
            );
            defer self.server.allocator.free(decoded);
            try std.testing.expectEqualStrings(at_threshold, decoded);

            var repeated = try connection.receiveMessage();
            defer repeated.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(at_threshold, repeated.payload);
            try std.testing.expect(repeated.was_compressed);

            try connection.sendText(at_threshold);
            try connection.sendText(at_threshold);
            try std.testing.expect(connection.compression_send.context != null);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/compression-threshold",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try runtime.Client.connectUriTls(
        allocator,
        io,
        uri,
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .compression_threshold = threshold,
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
        },
        .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    );
    defer client.close();
    try std.testing.expect(client.compression_send_context_takeover);
    try std.testing.expect(client.compression_receive_context_takeover);

    try client.sendText(below);
    try std.testing.expect(client.compression_send.encoder == null);
    try client.sendText(at_threshold);
    try client.sendText(at_threshold);
    try std.testing.expect(client.compression_send.context != null);
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expect(response.was_compressed);
    try std.testing.expectEqualStrings(at_threshold, response.payload);
    var output: [4096]u8 = undefined;
    const repeated = try client.receiveMessageInto(&output);
    try std.testing.expect(repeated.was_compressed);
    try std.testing.expectEqualStrings(at_threshold, repeated.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WSS public client identity completes mTLS echo" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .client_auth = .{ .verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        expected_certificate: *const [tls_testing.certificate_der_len]u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept(.{
                .protocols = &.{"mtls.v1"},
                .require_subprotocol = true,
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            const chain = connection.peerCertificates() orelse {
                shared.err = error.MissingPeerCertificate;
                return;
            };
            if (chain.len != 1 or !std.mem.eql(
                u8,
                chain[0],
                shared.expected_certificate,
            )) {
                shared.err = error.InvalidPeerCertificate;
                return;
            }
            if (connection.negotiatedCipherSuite() !=
                .aes_128_gcm_sha256 or
                connection.negotiatedTranscriptHash() != .sha256)
            {
                shared.err = error.InvalidCipherSuite;
                return;
            }
            connection.updateTrafficKeys(true) catch |err| {
                shared.err = err;
                return;
            };
            var message = connection.receiveMessage() catch |err| {
                shared.err = err;
                return;
            };
            defer message.deinit(shared.server.allocator);
            connection.sendBinary(message.payload) catch |err| {
                shared.err = err;
                return;
            };
            var after_update = connection.receiveMessage() catch |err| {
                shared.err = err;
                return;
            };
            defer after_update.deinit(shared.server.allocator);
            if (!std.mem.eql(u8, after_update.payload, "rotated websocket")) {
                shared.err = error.InvalidPayload;
                return;
            }
            connection.sendBinary(after_update.payload) catch |err| {
                shared.err = err;
                return;
            };
            const updates = connection.keyUpdateCounts().?;
            if (updates.sent != 1 or updates.received != 1 or
                updates.awaiting_peer_response)
            {
                shared.err = error.InvalidKeyUpdateCount;
            }
        }
    };
    var shared = Shared{
        .server = &server,
        .expected_certificate = &certificate_der,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/mtls",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try runtime.Client.connectUriTls(
        allocator,
        io,
        uri,
        .{
            .protocols = &.{"mtls.v1"},
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
            .tls_identity = .{
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .cipher_suites = &.{.aes_128_gcm_sha256},
            },
        },
        .{},
    );
    defer client.close();
    const server_chain = client.peerCertificates() orelse {
        return error.MissingPeerCertificate;
    };
    try std.testing.expectEqual(@as(usize, 1), server_chain.len);
    try std.testing.expectEqualSlices(
        u8,
        &certificate_der,
        server_chain[0],
    );
    try std.testing.expectEqual(
        tls_stream.NegotiatedCipherSuite.aes_128_gcm_sha256,
        client.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        tls_stream.TranscriptHash.sha256,
        client.negotiatedTranscriptHash().?,
    );
    try client.sendBinary("authenticated websocket");
    var echoed = try client.receiveMessage();
    defer echoed.deinit(allocator);
    try std.testing.expectEqualStrings(
        "authenticated websocket",
        echoed.payload,
    );
    try client.sendBinary("rotated websocket");
    var rotated_echo = try client.receiveMessage();
    defer rotated_echo.deinit(allocator);
    try std.testing.expectEqualStrings(
        "rotated websocket",
        rotated_echo.payload,
    );
    const updates = client.keyUpdateCounts().?;
    try std.testing.expectEqual(@as(u64, 1), updates.sent);
    try std.testing.expectEqual(@as(u64, 1), updates.received);
    try std.testing.expect(!updates.awaiting_peer_response);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket client identity is rejected for cleartext URI" {
    const key_pair = try tls_testing.serverKeyPair();
    var certificate_der: [tls_testing.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    try std.testing.expectError(
        error.UnsupportedScheme,
        runtime.Client.connectUri(
            std.testing.allocator,
            std.testing.io,
            "ws://127.0.0.1:1/",
            .{ .tls_identity = .{ .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            } } },
        ),
    );
}

fn localCaBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { std.crypto.Certificate.Bundle, std.Io.RwLock } {
    var certificate_der: [tls_testing.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    var pem_storage: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&pem_storage);
    try writer.writeAll("-----BEGIN CERTIFICATE-----\n");
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    const encoded = try writer.writableSliceGreedy(encoded_len);
    _ = std.base64.standard.Encoder.encode(
        encoded[0..encoded_len],
        &certificate_der,
    );
    writer.advance(encoded_len);
    try writer.writeAll("\n-----END CERTIFICATE-----\n");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "ca.pem",
        .data = writer.buffered(),
    });
    var bundle: std.crypto.Certificate.Bundle = .empty;
    errdefer bundle.deinit(allocator);
    try bundle.addCertsFromFilePath(
        allocator,
        io,
        std.Io.Timestamp.now(io, .real),
        tmp.dir,
        "ca.pem",
    );
    return .{ bundle, .init };
}
