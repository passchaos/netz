//! Vail-backed TLS policy shared by WSS callers.
//!
//! Zig 0.16's standard TLS client remains the default for anonymous WSS.
//! Configuring this module's `Options` selects the vail-backed TLS 1.3 client
//! for ALPN, peer-chain, exporter and KeyUpdate access. A client identity is
//! optional and answers CertificateRequest when supplied.

const std = @import("std");
const http1_runtime = @import("../../http1/mod.zig").runtime;
const tls_stream = @import("../../tls/mod.zig").stream;
const vail = @import("vail");

const net = std.Io.net;

pub const ClientIdentity = vail.tls.client_auth.ClientIdentity;
pub const CertificateVerifier = vail.tls.auth.ClientVerifier;

pub const Options = struct {
    /// Client certificate chain and signer used to answer TLS 1.3
    /// CertificateRequest. Storage only needs to outlive the synchronous
    /// WebSocket connect call.
    identity: ?ClientIdentity = null,
    /// Custom server trust policy. When omitted, `tls.ca_bundle` or operating
    /// system roots plus hostname verification are used.
    server_verifier: ?CertificateVerifier = null,
    /// Optional ALPN offer list for protocols layered over WebSocket.
    alpn_protocols: []const []const u8 = &.{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
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
    return tls_stream.ClientConnection.initVerified(
        allocator,
        io,
        stream,
        .{
            .server_name = server_name,
            .verify_host = tls_options.verify_host,
            .ca_bundle = if (tls_options.ca_bundle) |bundle|
                .{ .bundle = bundle.bundle, .lock = bundle.lock }
            else
                null,
            .server_verifier = identity_options.server_verifier,
            .client_identity = identity_options.identity,
            .alpn_protocols = identity_options.alpn_protocols,
            .cipher_suites = identity_options.cipher_suites,
            .max_server_handshake_size = identity_options.max_server_handshake_size,
            .handshake_timeout = identity_options.handshake_timeout orelse
                tls_options.handshake_timeout,
        },
    );
}
