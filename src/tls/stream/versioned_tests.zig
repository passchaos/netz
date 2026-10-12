const std = @import("std");
const client = @import("versioned_client_connection.zig");
const server = @import("versioned_server_connection.zig");
const version = @import("version.zig");
const tls_testing = @import("../testing.zig");

test "versioned TLS established connections discard handshake state" {
    try std.testing.expect(@sizeOf(client.Connection) <= 36 * 1024);
    try std.testing.expect(@sizeOf(server.Connection) <= 36 * 1024);
}

test "versioned TLS stream negotiates TLS 1.2 only" {
    try exerciseVersion(.tls12_only);
}

test "versioned TLS stream negotiates highest version" {
    try exerciseVersion(.tls12_and_tls13);
}

test "versioned TLS stream negotiates TLS 1.3 only" {
    try exerciseVersion(.tls13_only);
}

test "versioned TLS stream refuses a disjoint version policy" {
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
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        listener: *std.Io.net.Server,
        io: std.Io,
        certificate: *const [tls_testing.certificate_der_len]u8,
        key_pair: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            const stream = shared.listener.accept(shared.io) catch |err| {
                shared.err = err;
                return;
            };
            var stream_owned = true;
            defer if (stream_owned) stream.close(shared.io);
            const result = server.Connection.initWithDeadline(
                std.testing.allocator,
                shared.io,
                stream,
                .{
                    .identity = .{
                        .certificate_chain = &.{shared.certificate},
                        .signer = .{ .ecdsa_p256_sha256 = .{
                            .key_pair = shared.key_pair,
                        } },
                    },
                    .protocol_policy = .tls13_only,
                },
                .fromNow(shared.io, .{
                    .raw = .fromSeconds(1),
                    .clock = .awake,
                }),
            );
            if (result) |connection| {
                stream_owned = false;
                connection.deinit();
                shared.err = error.ExpectedVersionRejection;
            } else |err| {
                shared.err = err;
            }
        }
    };
    var shared = Shared{
        .listener = &listener,
        .io = io,
        .certificate = &certificate_der,
        .key_pair = key_pair,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const result = client.Connection.initWithDeadline(
        allocator,
        io,
        stream,
        .{
            .server_name = "localhost",
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .protocol_policy = .tls12_only,
        },
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    if (result) |connection| {
        stream_owned = false;
        connection.deinit();
        return error.ExpectedVersionRejection;
    } else |_| {}

    thread.join();
    joined = true;
    try std.testing.expectEqual(
        error.NoSupportedProtocolVersion,
        shared.err orelse return error.ExpectedVersionRejection,
    );
}

fn exerciseVersion(policy: version.Policy) !void {
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
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        listener: *std.Io.net.Server,
        io: std.Io,
        certificate: *const [tls_testing.certificate_der_len]u8,
        key_pair: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
        policy: version.Policy,
        protocol: ?version.Protocol = null,
        exporter: [32]u8 = undefined,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            const stream = shared.listener.accept(shared.io) catch |err| {
                shared.err = err;
                return;
            };
            var stream_owned = true;
            defer if (stream_owned) stream.close(shared.io);
            const connection = server.Connection.init(
                std.testing.allocator,
                shared.io,
                stream,
                .{
                    .identity = .{
                        .certificate_chain = &.{shared.certificate},
                        .signer = .{ .ecdsa_p256_sha256 = .{
                            .key_pair = shared.key_pair,
                        } },
                    },
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .tls12_cipher_suites = &.{
                        .ecdhe_ecdsa_aes_128_gcm_sha256,
                    },
                    .protocol_policy = shared.policy,
                    .alpn_protocols = &.{"mqtt"},
                },
            ) catch |err| {
                shared.err = err;
                return;
            };
            stream_owned = false;
            defer connection.deinit();
            shared.protocol = connection.negotiatedProtocol();
            if (!std.mem.eql(
                u8,
                connection.negotiatedAlpn() orelse "",
                "mqtt",
            )) {
                shared.err = error.InvalidAlpn;
                return;
            }
            connection.exportKeyingMaterial(
                "EXPORTER-netz-versioned-test",
                "context",
                &shared.exporter,
            ) catch |err| {
                shared.err = err;
                return;
            };
            var request: [4]u8 = undefined;
            var offset: usize = 0;
            while (offset < request.len) {
                const count = connection.read(request[offset..]) catch |err| {
                    shared.err = err;
                    return;
                };
                if (count == 0) {
                    shared.err = error.ConnectionClosed;
                    return;
                }
                offset += count;
            }
            if (!std.mem.eql(u8, &request, "ping")) {
                shared.err = error.InvalidPayload;
                return;
            }
            connection.writeAllParts("po", "ng") catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{
        .listener = &listener,
        .io = io,
        .certificate = &certificate_der,
        .key_pair = key_pair,
        .policy = policy,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const connection = try client.Connection.init(allocator, io, stream, .{
        .server_name = "localhost",
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
        .alpn_protocols = &.{"mqtt"},
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .tls12_cipher_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256},
        .protocol_policy = policy,
    });
    stream_owned = false;
    defer connection.deinit();
    const expected: version.Protocol = if (policy == .tls12_only)
        .tls12
    else
        .tls13;
    try std.testing.expectEqual(expected, connection.negotiatedProtocol());
    try std.testing.expectEqualStrings("mqtt", connection.negotiatedAlpn().?);
    try std.testing.expectEqual(
        if (expected == .tls12)
            version.NegotiatedCipherSuite.ecdhe_ecdsa_aes_128_gcm_sha256
        else
            version.NegotiatedCipherSuite.aes_128_gcm_sha256,
        connection.negotiatedCipherSuite(),
    );
    var client_exporter: [32]u8 = undefined;
    try connection.exportKeyingMaterial(
        "EXPORTER-netz-versioned-test",
        "context",
        &client_exporter,
    );
    if (expected == .tls12) {
        try std.testing.expectError(
            error.TlsKeyUpdateUnavailable,
            connection.updateTrafficKeys(false),
        );
    }
    try connection.writeAllSlices(&.{ "pi", "ng" });
    var response: [4]u8 = undefined;
    var offset: usize = 0;
    while (offset < response.len) {
        const count = try connection.read(response[offset..]);
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
    try std.testing.expectEqualStrings("pong", &response);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(expected, shared.protocol.?);
    try std.testing.expectEqualSlices(u8, &shared.exporter, &client_exporter);
}
