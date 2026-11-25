//! TLS 1.2/1.3 client used to verify CertificateRequest identity selection
//! against an independent OpenSSL server.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 5) return error.InvalidArgument;
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
    const protocol_policy: netz.tls.stream.VersionPolicy =
        if (std.mem.eql(u8, args[4], "tls12"))
            .tls12_only
        else if (std.mem.eql(u8, args[4], "tls13"))
            .tls13_only
        else
            return error.InvalidArgument;
    const expected_protocol: netz.tls.stream.Protocol =
        if (protocol_policy == .tls12_only) .tls12 else .tls13;

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
            .protocol_policy = protocol_policy,
            .request_tls12_session_ticket = false,
            .request_tls13_session_ticket = false,
        },
    ) catch |err| {
        std.debug.print(
            "netz TLS {s} optional-mTLS connection failed: {s}\n",
            .{ if (expected_protocol == .tls12) "1.2" else "1.3", @errorName(err) },
        );
        return err;
    };
    defer connection.close();
    if (connection.negotiatedTlsProtocol() != expected_protocol) {
        return error.InvalidProtocolVersion;
    }
    var response = try connection.request(.{
        .method = .GET,
        .target = "/interop-response.http",
        .host = "localhost",
    });
    defer response.deinit(allocator);
    if (response.response.status != 200) return error.InvalidResponse;
    std.debug.print(
        "netz TLS {s} client certificate expected={s} " ++
            "server=openssl client_io=zio-std-io status=200\n",
        .{
            if (expected_protocol == .tls12) "1.2" else "1.3",
            if (expect_certificate) "present" else "absent",
        },
    );
}
