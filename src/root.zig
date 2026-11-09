//! Netz is a Zig 0.16 protocol toolkit for modern application networking.
//!
//! The package is intentionally split into codec/state-machine modules.  Network
//! I/O, TLS certificate policy, and event-loop integration are layered above the
//! byte-level protocol code so the same parsers can be fuzzed, embedded, or used
//! with different runtimes.

pub const alloc = @import("alloc.zig");
pub const runtime = @import("runtime.zig");
pub const stream = @import("stream.zig");
pub const tls = @import("tls/mod.zig");
pub const proxy = @import("proxy/mod.zig");
pub const vpn = @import("vpn/mod.zig");
pub const mesh = @import("mesh/mod.zig");
pub const http = @import("http/mod.zig");
pub const streaming = @import("http/streaming.zig");
pub const http1 = @import("http1/mod.zig");
pub const http2 = @import("http2/mod.zig");
pub const http3 = @import("http3/mod.zig");
pub const grpc = @import("grpc/mod.zig");
pub const quic = @import("quic/mod.zig");
pub const websocket = @import("websocket/mod.zig");
pub const mqtt = @import("mqtt/mod.zig");
pub const webtransport = @import("webtransport/mod.zig");

comptime {
    _ = alloc;
    _ = runtime;
    _ = stream;
    _ = tls;
    _ = proxy;
    _ = vpn;
    _ = mesh;
    _ = http;
    _ = streaming;
    _ = http1;
    _ = http2;
    _ = http3;
    _ = grpc;
    _ = quic;
    _ = websocket;
    _ = mqtt;
    _ = webtransport;
}
