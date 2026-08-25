const std = @import("std");
const runtime = @import("../runtime.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/2 TLS runtime negotiates h2 and exchanges a request" {
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
    const limits: runtime.Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    };
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
            .limits = limits,
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
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
            var request = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(shared.server.allocator);
            if (!std.mem.eql(u8, request.path, "/secure") or
                !std.mem.eql(u8, request.scheme, "https"))
            {
                shared.err = error.InvalidRequest;
                return;
            }
            connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = "secure h2",
            }) catch |err| {
                shared.err = err;
                return;
            };
            var after_update = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer after_update.deinit(shared.server.allocator);
            if (!std.mem.eql(u8, after_update.path, "/after-update")) {
                shared.err = error.InvalidRequest;
                return;
            }
            connection.writeResponse(after_update.stream_id, .{
                .body = "rotated h2",
            }) catch |err| {
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

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        limits,
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer client.close();
    try std.testing.expectEqual(
        tls_stream.CipherSuite.aes_128_gcm_sha256,
        client.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        tls_stream.TranscriptHash.sha256,
        client.negotiatedTranscriptHash().?,
    );
    var response = try client.request(.{ .path = "/secure" });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("secure h2", response.body);
    var after_update = try client.request(.{ .path = "/after-update" });
    defer after_update.deinit(allocator);
    try std.testing.expectEqualStrings("rotated h2", after_update.body);
    const updates = client.keyUpdateCounts().?;
    try std.testing.expectEqual(@as(u64, 1), updates.sent);
    try std.testing.expectEqual(@as(u64, 1), updates.received);
    try std.testing.expect(!updates.awaiting_peer_response);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 TLS listener rejects a client without h2 ALPN" {
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
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,
        rejected: bool = false,

        fn run(shared: *@This()) void {
            const stream = shared.server.listener.accept(
                shared.server.io,
            ) catch |err| {
                shared.err = err;
                return;
            };
            var stream_owned = true;
            defer if (stream_owned) stream.close(shared.server.io);
            const connection = tls_stream.ServerConnection.init(
                std.testing.allocator,
                shared.server.io,
                stream,
                shared.server.tls,
            ) catch |err| {
                if (err == error.InvalidAlpn) {
                    shared.rejected = true;
                } else {
                    shared.err = err;
                }
                return;
            };
            stream_owned = false;
            connection.deinit();
            shared.err = error.UnexpectedAlpn;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    const client_result = tls_stream.ClientConnection.init(
        allocator,
        io,
        stream,
        .{
            .server_name = "localhost",
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"http/1.1"},
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    if (client_result) |connection| {
        connection.deinit();
        return error.UnexpectedAlpn;
    } else |err| switch (err) {
        error.ConnectionClosed => stream.close(io),
        else => return err,
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.rejected);
}

test "HTTP/2 TLS runtime exposes a required authenticated client chain" {
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
    const limits: runtime.Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    };
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
            .limits = limits,
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        certificate: *const [tls_testing.certificate_der_len]u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            const chain = connection.peerCertificates() orelse {
                shared.err = error.MissingPeerCertificate;
                return;
            };
            if (chain.len != 1 or
                !std.mem.eql(u8, chain[0], shared.certificate))
            {
                shared.err = error.InvalidPeerCertificate;
                return;
            }
            var request = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(shared.server.allocator);
            connection.writeResponse(request.stream_id, .{
                .body = "authenticated h2",
            }) catch |err| {
                shared.err = err;
            };
        }
    };

    var shared = Shared{
        .server = &server,
        .certificate = &certificate_der,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        limits,
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .client_identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer client.close();
    const server_chain = client.peerCertificates() orelse
        return error.MissingPeerCertificate;
    try std.testing.expectEqual(@as(usize, 1), server_chain.len);
    try std.testing.expectEqualSlices(
        u8,
        &certificate_der,
        server_chain[0],
    );
    var response = try client.request(.{ .path = "/mtls" });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("authenticated h2", response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 TLS listener bounds an idle transport handshake" {
    const allocator = std.testing.allocator;
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
            .tls_handshake_timeout = .fromMilliseconds(75),
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "HTTP/2 TLS client bounds an idle server handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *std.Io.net.Server,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(
                self.io,
                .fromMilliseconds(250),
                .awake,
            ) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectTlsHost(
            allocator,
            io,
            "127.0.0.1",
            listener.socket.address.ip4.port,
            .{},
            .{
                .server_verifier = .{},
                .tls_handshake_timeout = .fromMilliseconds(75),
            },
        ),
    );
    thread.join();
    joined = true;
}
