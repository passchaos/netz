//! Runtime primitives shared by the proxy protocol servers.
//!
//! These are server access-control, connection-budget, accounting, and
//! destination-connect helpers. Product policy such as Clash-style routing,
//! DNS configuration, subscriptions, and health selection lives in `proxyz`
//! and composes these primitives.

pub const acl = @import("acl.zig");
pub const destination = @import("destination.zig");
pub const limits = @import("limits.zig");
pub const rate_limit = @import("rate_limit.zig");
pub const reload = @import("reload.zig");
pub const stats = @import("stats.zig");
