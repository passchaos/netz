//! Transport wrappers for proxy protocols.

pub const ws = @import("ws.zig");
pub const h2_stream = @import("h2_stream.zig");
pub const grpc_stream = @import("grpc_stream.zig");
pub const quic_stream = @import("quic_stream.zig");

test {
    _ = ws;
    _ = h2_stream;
    _ = grpc_stream;
    _ = quic_stream;
}
