//! Blocking TLS 1.2/1.3 client/server streams backed by vail.

pub const Tls13ClientConnection = @import("client_connection.zig").Connection;
pub const Tls13ClientOptions = @import("client_connection.zig").Options;
pub const Tls13ClientVerifiedOptions =
    @import("client_connection.zig").VerifiedOptions;
pub const ClientConnection =
    @import("versioned_client_connection.zig").Connection;
pub const ClientOptions = @import("versioned_client_connection.zig").Options;
pub const ClientVerifiedOptions =
    @import("versioned_client_connection.zig").VerifiedOptions;
pub const ClientCaBundle = @import("versioned_client_connection.zig").CaBundle;
pub const StapledOcspPolicy = @import("vail").x509.trust.StapledOcspPolicy;
pub const Tls13ServerConnection = @import("server_connection.zig").Connection;
pub const Tls13ServerOptions = @import("server_connection.zig").Options;
pub const ServerConnection =
    @import("versioned_server_connection.zig").Connection;
pub const ServerOptions = @import("versioned_server_connection.zig").Options;
pub const ServerIdentityLease =
    @import("server_handshake.zig").ServerIdentityLease;
pub const ServerIdentityProvider =
    @import("server_handshake.zig").ServerIdentityProvider;
/// TLS 1.3 cipher-suite configuration retained for source compatibility.
pub const CipherSuite = @import("vail").tls.cipher_suite.Suite;
pub const TranscriptHash = @import("vail").tls.secret.Hash;
pub const KeyUpdateCounts = @import("record_stream.zig").KeyUpdateCounts;
pub const PeerCertificateChain =
    @import("server_handshake.zig").PeerCertificateChain;
pub const VersionedClientConnection = ClientConnection;
pub const VersionedClientOptions = ClientOptions;
pub const VersionedClientVerifiedOptions = ClientVerifiedOptions;
pub const VersionedServerConnection = ServerConnection;
pub const VersionedServerOptions = ServerOptions;
pub const Protocol = @import("version.zig").Protocol;
pub const VersionPolicy = @import("version.zig").Policy;
pub const NegotiatedCipherSuite =
    @import("version.zig").NegotiatedCipherSuite;
pub const Tls12CipherSuite = @import("vail").tls.tls12.Suite;
pub const Tls13SessionTicket = @import("vail").tls.ticket.Cached;
pub const Tls12SessionTicket = @import("vail").tls.tls12_ticket.Cached;
pub const Tls13TicketKeyring = @import("vail").tls.ticket_keyring.Keyring;
pub const tls13_ticket_key_len = @import("vail").tls.ticket_keyring.key_len;
pub const Tls12TicketKeyring = @import("vail").tls.ticket_keyring.Keyring;
pub const tls12_ticket_key_len = @import("vail").tls.ticket_keyring.key_len;
pub const Tls12ServerTicketPolicy =
    @import("versioned_server_connection.zig").Options.Tls12SessionTicketPolicy;
pub const Tls13ServerTicketPolicy =
    @import("versioned_server_connection.zig").Options.Tls13SessionTicketPolicy;
pub const default_tls12_cipher_suites =
    &@import("version.zig").default_tls12_cipher_suites;
pub const default_tls13_cipher_suites =
    &@import("vail").tls.cipher_suite.default_preference;

/// RFC 8879 algorithm preference shared by stream clients (advertised in
/// compress_certificate) and servers (on-demand compression candidates).
pub const default_certificate_compression_algorithms =
    @import("versioned_client_connection.zig").default_certificate_compression_algorithms;

pub const Error = @import("versioned_client_connection.zig").Error ||
    @import("versioned_server_connection.zig").Error;

test {
    _ = @import("handshake_deadline.zig");
    _ = @import("record_io.zig");
    _ = @import("record_stream.zig");
    _ = @import("version.zig");
    _ = @import("tls12_record_stream.zig");
    _ = @import("read_interruption_tests.zig");
    _ = @import("write_interruption_tests.zig");
    _ = @import("versioned_client_connection.zig");
    _ = @import("versioned_server_connection.zig");
    _ = @import("versioned_tests.zig");
    _ = @import("certificate_compression_tests.zig");
    _ = @import("client_ticket_cache.zig");
    _ = @import("server_handshake.zig");
    _ = @import("alpn_tests.zig");
    _ = @import("handshake_timeout_tests.zig");
}
