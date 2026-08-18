//! One-connection MQTT mTLS server used by the OpenSSL interop gate.

const std = @import("std");
const netz = @import("netz");

const tls_test = netz.tls.testing;

const Mode = enum {
    required,
    required_rsa,
    required_reject,
    required_untrusted,
    optional_anonymous,
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or args.len > 4) return error.InvalidArguments;
    const mode = std.meta.stringToEnum(Mode, args[1]) orelse
        return error.InvalidArguments;
    if ((mode == .required_rsa) != (args.len == 4)) {
        return error.InvalidArguments;
    }
    const port = try std.fmt.parseInt(u16, args[2], 10);

    const allocator = init.gpa;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const rsa_public_key = if (mode == .required_rsa)
        try std.Io.Dir.cwd().readFileAlloc(
            io,
            args[3],
            allocator,
            .limited(16 * 1024),
        )
    else
        null;
    defer if (rsa_public_key) |bytes| allocator.free(bytes);
    const requirement: netz.mqtt.tls_runtime.ClientAuthRequirement =
        switch (mode) {
            .required,
            .required_rsa,
            .required_reject,
            .required_untrusted,
            => .required,
            .optional_anonymous => .optional,
        };
    const verifier: netz.mqtt.tls_runtime.ClientCertificateVerifier =
        if (rsa_public_key) |key|
            .{ .pinned_rsa_public_key = key }
        else
            .{ .pinned_ecdsa_p256_public_key = public_key };
    var server = try netz.mqtt.tls_runtime.Server.listen(
        allocator,
        io,
        try std.Io.net.IpAddress.parse("127.0.0.1", port),
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .client_auth = .{
                .verifier = verifier,
                .requirement = requirement,
            },
            .limits = .{ .max_packet_size = 4096 },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();
    std.debug.print("MQTT mTLS server listening\n", .{});

    if (mode == .required_reject or mode == .required_untrusted) {
        _ = server.accept(.{ .protocol = .v5 }) catch |err| {
            const expected = switch (mode) {
                .required_reject => error.ClientCertificateRequired,
                .required_untrusted => error.CertificateUntrusted,
                else => unreachable,
            };
            if (err != expected) return err;
            std.debug.print(
                "required mTLS rejected {s} client\n",
                .{switch (mode) {
                    .required_reject => "anonymous",
                    .required_untrusted => "untrusted",
                    else => unreachable,
                }},
            );
            return;
        };
        return error.ExpectedClientCertificateRejection;
    }

    var accepted = try server.accept(.{ .protocol = .v5 });
    defer accepted.deinit(allocator);
    try std.testing.expectEqualStrings(
        "openssl-mtls",
        accepted.connect.connect.client_id,
    );
    const peer_certificates = accepted.connection.peerCertificates();
    switch (mode) {
        .required, .required_rsa => {
            const chain = peer_certificates orelse
                return error.MissingPeerCertificate;
            try std.testing.expectEqual(@as(usize, 1), chain.len);
            if (mode == .required) {
                try std.testing.expectEqualSlices(
                    u8,
                    &certificate_der,
                    chain[0],
                );
            }
            std.debug.print(
                "required mTLS authenticated {s} peer certificate\n",
                .{if (mode == .required_rsa) "RSA" else "ECDSA"},
            );
        },
        .optional_anonymous => {
            if (peer_certificates != null) {
                return error.UnexpectedPeerCertificate;
            }
            std.debug.print(
                "optional mTLS accepted anonymous client\n",
                .{},
            );
        },
        .required_reject, .required_untrusted => unreachable,
    }
}
