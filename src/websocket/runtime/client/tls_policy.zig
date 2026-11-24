//! Common TLS handshake budget for every WSS transport constructor.
const runtime = @import("../../runtime.zig");

/// Explicit TLS options override the common connect shorthand. The vail
/// identity policy can then override this value with its nested budget.
pub fn effective(connect: runtime.ConnectOptions, tls: runtime.http1_runtime.TlsClientOptions) runtime.http1_runtime.TlsClientOptions {
    var options = tls;
    if (options.handshake_timeout == null) options.handshake_timeout = connect.tls_handshake_timeout;
    return options;
}
