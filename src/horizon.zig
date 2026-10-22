//! Narrow canonical Netz surface used by Horizon.
//!
//! Stream/TLS and HTTP/1 share internal transport files, so they must belong to
//! one Zig module instance. Keeping this entrypoint narrow avoids pulling QUIC,
//! HTTP/2, HTTP/3, MQTT, and WebTransport into Horizon's build graph.

pub const stream = @import("stream.zig");
pub const http1 = @import("http1/mod.zig");

comptime {
    _ = stream;
    _ = http1;
}
