//! Acquire the ticket cache before transferring a returned connection's ticket.
const std = @import("std");
const Guard = @import("../mutex_guard.zig").Guard;
const timed_mutex = @import("../timed_mutex.zig");

pub fn remember(cache: anytype, connection: anytype, host: []const u8, port: u16, exact_alpn: bool, io: std.Io, deadline: ?std.Io.Clock.Timestamp) timed_mutex.Error!void {
    // Disabled caches still consume a captured ticket, but never need a lock.
    var guard: ?Guard = if (cache.max_entries != 0) try Guard.initBefore(&cache.mutex, io, deadline) else null;
    defer if (guard) |*owned| owned.unlock();
    const ticket = connection.takeTls13SessionTicket() catch {
        if (guard != null) {
            if (exact_alpn) {
                _ = cache.removeForAlpnLocked(host, port, connection.negotiatedAlpn() orelse "");
            } else _ = cache.removeLocked(host, port);
        }
        return;
    };
    if (ticket) |value| {
        const now = std.Io.Clock.real.now(io).nanoseconds;
        cache.storeLocked(host, port, value, if (now <= 0) 0 else @intCast(@divFloor(now, std.time.ns_per_ms)));
    }
}
