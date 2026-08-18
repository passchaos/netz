const std = @import("std");
const runtime = @import("../runtime.zig");
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
            var connection = shared.server.accept(.{
                .protocols = &.{"echo.v1"},
                .require_subprotocol = true,
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            if (connection.peerCertificates() != null) {
                shared.err = error.UnexpectedPeerCertificate;
                return;
            }
            var message = connection.receiveMessage() catch |err| {
                shared.err = err;
                return;
            };
            defer message.deinit(shared.server.allocator);
            connection.sendBinary(message.payload) catch |err| {
                shared.err = err;
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
            var message = connection.receiveMessage() catch |err| {
                shared.err = err;
                return;
            };
            defer message.deinit(shared.server.allocator);
            connection.sendBinary(message.payload) catch |err| {
                shared.err = err;
            };
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
    try client.sendBinary("authenticated websocket");
    var echoed = try client.receiveMessage();
    defer echoed.deinit(allocator);
    try std.testing.expectEqualStrings(
        "authenticated websocket",
        echoed.payload,
    );

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
