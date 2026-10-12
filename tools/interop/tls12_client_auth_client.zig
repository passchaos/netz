//! TLS 1.2 client used to verify CertificateRequest identity selection against
//! an independent OpenSSL server.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }
    const expect_certificate = if (std.mem.eql(u8, args[3], "present"))
        true
    else if (std.mem.eql(u8, args[3], "absent"))
        false
    else
        return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        std.Io.Clock.real.now(io),
        args[2],
    );
    var ca_lock: std.Io.RwLock = .init;

    var client_certificate: [netz.tls.testing.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &client_certificate,
        netz.tls.testing.certificate_base64,
    );
    const client_key = try netz.tls.testing.serverKeyPair();
    var connection = netz.http1.runtime.Client.connectVailTlsAddress(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        "localhost",
        .{ .response_head_timeout = .fromSeconds(5) },
        .{
            .ca_bundle = .{ .bundle = &ca_bundle, .lock = &ca_lock },
            .client_identity = .{
                .certificate_chain = &.{&client_certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = client_key,
                } },
            },
            .alpn_protocols = &.{"http/1.1"},
            .tls12_cipher_suites = &.{
                .ecdhe_ecdsa_aes_128_gcm_sha256,
            },
            .protocol_policy = .tls12_only,
            .request_tls12_session_ticket = false,
        },
    ) catch |err| {
        std.debug.print(
            "netz TLS 1.2 optional-mTLS connection failed: {s}\n",
            .{@errorName(err)},
        );
        return err;
    };
    defer connection.close();
    if (connection.negotiatedTlsProtocol() != .tls12) {
        return error.InvalidProtocolVersion;
    }
    var response = try connection.request(.{
        .method = .GET,
        .target = "/",
        .host = "localhost",
    });
    defer response.deinit(allocator);
    if (response.response.status != 200) return error.InvalidResponse;
    const certificate_was_absent = std.mem.indexOf(
        u8,
        response.response.body,
        "no client certificate available",
    ) != null;
    if (certificate_was_absent == expect_certificate) {
        return error.UnexpectedClientCertificate;
    }
    std.debug.print(
        "netz TLS 1.2 client certificate selection={s} " ++
            "server=openssl client_io=zio-std-io status=200\n",
        .{if (expect_certificate) "present" else "absent"},
    );
}
