const std = @import("std");
const client = @import("client_connection.zig");
const server = @import("server_connection.zig");
const tls_testing = @import("../testing.zig");

test "TLS stream negotiates ALPN and exchanges application data" {
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
                    .alpn_protocols = &.{ "h2", "http/1.1" },
                },
            ) catch |err| {
                shared.err = err;
                return;
            };
            stream_owned = false;
            defer connection.deinit();
            if (!std.mem.eql(u8, connection.selected_alpn.?, "h2")) {
                shared.err = error.InvalidAlpn;
                return;
            }
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
            connection.writeAll("pong") catch |err| {
                shared.err = err;
            };
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
    const connection = try client.Connection.init(allocator, io, stream, .{
        .server_name = "localhost",
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
        .alpn_protocols = &.{ "h2", "http/1.1" },
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    stream_owned = false;
    defer connection.deinit();
    try std.testing.expectEqualStrings("h2", connection.selected_alpn.?);
    try connection.writeAllSlices(&.{ "pi", "", "ng" });
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
}

test "TLS stream rejects ALPN without a shared protocol" {
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
            defer stream.close(shared.io);
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
                    .alpn_protocols = &.{"h2"},
                },
            ) catch |err| {
                if (err != error.InvalidAlpn) shared.err = err;
                return;
            };
            connection.deinit();
            shared.err = error.UnexpectedAlpn;
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
    const client_result = client.Connection.init(allocator, io, stream, .{
        .server_name = "localhost",
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
        .alpn_protocols = &.{"http/1.1"},
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    if (client_result) |connection| {
        connection.deinit();
        return error.UnexpectedAlpn;
    } else |err| switch (err) {
        // The server detects the missing overlap before emitting its encrypted
        // flight, so the client observes the peer close rather than a selected
        // protocol it could validate locally.
        error.ConnectionClosed => stream.close(io),
        else => return err,
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
