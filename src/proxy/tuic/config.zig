//! Shared TUIC server configuration.

const std = @import("std");

const netz = @import("../netz.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const limits = @import("../runtime/limits.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");

const quic = netz.quic;

pub const Config = struct {
    uuid: [16]u8,
    password: []const u8,
    identity: quic.tls.auth.ServerIdentity,
    alpn_protocol: []const u8 = "h3",
    acl: acl.Policy = .{},
    /// Optional hot-reloadable ACL. Takes precedence over `acl`.
    policy_store: ?*reload.Reloadable = null,
    limits: limits.Options = .{},
    connect_timeout: std.Io.Duration = .fromSeconds(10),
    idle_timeout: std.Io.Duration = .fromSeconds(120),
    auth_timeout: std.Io.Duration = .fromSeconds(10),
    max_datagram_size: usize = 4096,
    relay_buffer_size: usize = 16 * 1024,
    /// Maximum concurrent UDP associations per QUIC connection.
    max_assocs: usize = 64,
    max_relays: usize = 64,
    /// Per-stream bytes retained before authentication or while the destination
    /// connection is pending.
    max_pending_stream_bytes: usize = 256 * 1024,
    stats: ?*stats_mod.Stats = null,
    rate_limiter: ?*rate_limit.Limiter = null,
};
