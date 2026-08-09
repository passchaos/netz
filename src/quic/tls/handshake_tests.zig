const std = @import("std");
const quic = @import("../mod.zig");

const Ed25519 = std.crypto.sign.Ed25519;

test "QUIC integrated mutual TLS proves both Ed25519 identities" {
    const result = try runMutualTls(
        false,
        .aes_128_gcm_sha256,
    );
    if (result.client_err) |err| return err;
    if (result.server_err) |err| return err;
}

test "QUIC AES-256 SHA-384 mutual TLS proves both Ed25519 identities" {
    const result = try runMutualTls(
        false,
        .aes_256_gcm_sha384,
    );
    if (result.client_err) |err| return err;
    if (result.server_err) |err| return err;
}

test "QUIC integrated mutual TLS requires a client certificate" {
    const result = try runMutualTls(
        true,
        .aes_128_gcm_sha256,
    );
    try std.testing.expectEqualStrings(
        "ClientCertificateRequired",
        @errorName(result.client_err orelse return error.TestUnexpectedResult),
    );
    try std.testing.expect(result.server_err != null);
}

const Result = struct {
    client_err: ?anyerror,
    server_err: ?anyerror,
};

fn runMutualTls(
    omit_client_identity: bool,
    cipher_suite: quic.tls_client_hello.CipherSuite,
) !Result {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const server_key = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x21} ** Ed25519.KeyPair.seed_length,
    );
    const client_key = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x22} ** Ed25519.KeyPair.seed_length,
    );
    const server_public = server_key.public_key.toBytes();
    const client_public = client_key.public_key.toBytes();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        server_key: Ed25519.KeyPair,
        server_public: *const [32]u8,
        client_public: [32]u8,
        cipher_suite: quic.tls_client_hello.CipherSuite,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = quic.handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0x23} ** 32,
                .x25519_secret_key = [_]u8{0x24} ** 32,
                .cipher_suites = &.{shared.cipher_suite},
                .identity = .{
                    .certificate_chain = &.{shared.server_public},
                    .signer = .{
                        .ed25519 = .{ .key_pair = shared.server_key },
                    },
                },
                .client_auth = .{
                    .verifier = .{
                        .pinned_ed25519_public_key = shared.client_public,
                    },
                },
            }) catch |err| {
                shared.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .server_key = server_key,
        .server_public = &server_public,
        .client_public = client_public,
        .cipher_suite = cipher_suite,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client_err: ?anyerror = null;
    var options = quic.handshake.ClientOptions{
        .original_destination_connection_id = "mtls0001",
        .local_connection_id = "client",
        .random = [_]u8{0x25} ** 32,
        .x25519_secret_key = [_]u8{0x26} ** 32,
        .cipher_suites = &.{cipher_suite},
        .server_auth = .{
            .pinned_ed25519_public_key = server_public,
        },
    };
    if (!omit_client_identity) {
        options.client_identity = .{
            .certificate_chain = &.{&client_public},
            .signer = .{
                .ed25519 = .{ .key_pair = client_key },
            },
        };
    }
    var established = quic.handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        options,
    ) catch |err| blk: {
        client_err = err;
        try client_endpoint.sendBytes(server_endpoint.address(), "invalid");
        break :blk null;
    };
    if (established) |*connection| connection.deinit();
    thread.join();
    return .{
        .client_err = client_err,
        .server_err = shared.err,
    };
}
