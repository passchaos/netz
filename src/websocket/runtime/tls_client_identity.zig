//! Vail-backed TLS policy shared by WSS callers.
//!
//! Zig 0.16's standard TLS client remains the default for anonymous WSS.
//! Configuring this module's `Options` selects the vail-backed TLS 1.2/1.3 client
//! for ALPN, peer-chain, exporter and KeyUpdate access. A client identity is
//! optional and answers CertificateRequest when supplied.

const std = @import("std");
const http1_runtime = @import("../../http1/mod.zig").runtime;
const tls_stream = @import("../../tls/mod.zig").stream;
const vail = @import("vail");

const net = std.Io.net;

pub const ClientIdentity = vail.tls.client_auth.ClientIdentity;
pub const CertificateVerifier = vail.tls.auth.ClientVerifier;
pub const StapledOcspPolicy = tls_stream.StapledOcspPolicy;

pub const Options = struct {
    /// Client certificate chain and signer used to answer TLS
    /// CertificateRequest. Storage only needs to outlive the synchronous
    /// WebSocket connect call.
    identity: ?ClientIdentity = null,
    /// Custom server trust policy. When omitted, `tls.ca_bundle` or operating
    /// system roots plus hostname verification are used.
    server_verifier: ?CertificateVerifier = null,
    /// Built-in verifier policy for RFC 6066 stapled OCSP responses.
    stapled_ocsp: StapledOcspPolicy = .ignore,
    /// Emit status_request. Must remain enabled for `.require` and defaults on
    /// so RFC 7633 Must-Staple certificates work without another option.
    request_ocsp: bool = true,
    /// Optional ALPN offer list for protocols layered over WebSocket.
    alpn_protocols: []const []const u8 = &.{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const vail.tls.tls12.Suite =
        tls_stream.default_tls12_cipher_suites,
    protocol_policy: tls_stream.VersionPolicy = .tls12_and_tls13,
    max_server_handshake_size: usize = 256 * 1024,
    /// Absolute receive budget spanning all server handshake flights.
    handshake_timeout: ?std.Io.Duration = null,
};

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    server_name: []const u8,
    tls_options: http1_runtime.TlsClientOptions,
    identity_options: Options,
) tls_stream.Error!*tls_stream.ClientConnection {
    return initBefore(
        allocator,
        io,
        stream,
        server_name,
        tls_options,
        identity_options,
        null,
    );
}

pub fn initWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    server_name: []const u8,
    tls_options: http1_runtime.TlsClientOptions,
    identity_options: Options,
    deadline: std.Io.Clock.Timestamp,
) tls_stream.Error!*tls_stream.ClientConnection {
    return initBefore(
        allocator,
        io,
        stream,
        server_name,
        tls_options,
        identity_options,
        deadline,
    );
}

fn initBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    server_name: []const u8,
    tls_options: http1_runtime.TlsClientOptions,
    identity_options: Options,
    deadline: ?std.Io.Clock.Timestamp,
) tls_stream.Error!*tls_stream.ClientConnection {
    const options = verifiedOptions(
        server_name,
        tls_options,
        identity_options,
    );
    return if (deadline) |absolute|
        tls_stream.ClientConnection.initVerifiedWithDeadline(
            allocator,
            io,
            stream,
            options,
            absolute,
        )
    else
        tls_stream.ClientConnection.initVerified(
            allocator,
            io,
            stream,
            options,
        );
}

fn verifiedOptions(
    server_name: []const u8,
    tls_options: http1_runtime.TlsClientOptions,
    identity_options: Options,
) tls_stream.ClientVerifiedOptions {
    return .{
        .server_name = server_name,
        .verify_host = tls_options.verify_host,
        .ca_bundle = if (tls_options.ca_bundle) |bundle|
            .{ .bundle = bundle.bundle, .lock = bundle.lock }
        else
            null,
        .server_verifier = identity_options.server_verifier,
        .stapled_ocsp = identity_options.stapled_ocsp,
        .request_ocsp = identity_options.request_ocsp,
        .client_identity = identity_options.identity,
        .alpn_protocols = identity_options.alpn_protocols,
        .cipher_suites = identity_options.cipher_suites,
        .tls12_cipher_suites = identity_options.tls12_cipher_suites,
        .protocol_policy = identity_options.protocol_policy,
        .max_server_handshake_size = identity_options.max_server_handshake_size,
        .handshake_timeout = identity_options.handshake_timeout orelse tls_options.handshake_timeout,
    };
}

test "WSS vail TLS options preserve stapled OCSP policy" {
    const mapped = verifiedOptions("example.com", .{}, .{
        .stapled_ocsp = .require,
        .request_ocsp = true,
    });
    try std.testing.expectEqual(StapledOcspPolicy.require, mapped.stapled_ocsp);
    try std.testing.expect(mapped.request_ocsp);
}
