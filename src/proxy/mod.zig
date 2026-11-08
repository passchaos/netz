//! Reusable application-proxy protocols and their runtime primitives.
//!
//! The wire codecs, server state machines, and transport adapters live here.
//! Product policy (Clash-style routing, DNS configuration, subscriptions, and
//! health selection) lives in the `proxyz` package and composes this layer.

pub const socks5 = @import("socks5.zig");

pub const socks = @import("socks/mod.zig");
pub const http_connect = @import("http_connect/mod.zig");
pub const shadowsocks = @import("shadowsocks/mod.zig");
pub const trojan = @import("trojan/mod.zig");
pub const vless = @import("vless/mod.zig");
pub const vmess = @import("vmess/mod.zig");
pub const tuic = @import("tuic/mod.zig");
pub const hysteria = @import("hysteria/mod.zig");
pub const tls = @import("tls/mod.zig");
pub const transport = @import("transport/mod.zig");

pub const runtime = @import("runtime/mod.zig");
pub const internal = @import("internal/mod.zig");

test {
    _ = socks5;
    _ = @import("socks5/udp_association_tests.zig");
    _ = socks;
    _ = http_connect;
    _ = shadowsocks;
    _ = trojan;
    _ = vless;
    _ = vmess;
    _ = tuic;
    _ = hysteria;
    _ = tls;
    _ = transport;
    _ = runtime;
    _ = internal;
}
