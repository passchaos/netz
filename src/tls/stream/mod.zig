//! Blocking TLS 1.3 client/server streams backed by vail.

pub const ClientConnection = @import("client_connection.zig").Connection;
pub const ClientOptions = @import("client_connection.zig").Options;
pub const ServerConnection = @import("server_connection.zig").Connection;
pub const ServerOptions = @import("server_connection.zig").Options;
pub const PeerCertificateChain =
    @import("server_handshake.zig").PeerCertificateChain;

pub const Error = @import("client_connection.zig").Error ||
    @import("server_connection.zig").Error;

test {
    _ = @import("record_io.zig");
    _ = @import("record_stream.zig");
    _ = @import("server_handshake.zig");
}
