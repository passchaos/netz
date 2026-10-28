//! New-connection ticket capture and invalidation under one caller deadline.
const std = @import("std");
const Guard = @import("../mutex_guard.zig").Guard;
const deadline_policy = @import("../deadline.zig");
const tls = @import("../../tls/stream/mod.zig");

pub fn remember12(cache: anytype, connection: anytype, host: []const u8, port: u16, exact_alpn: bool, io: std.Io, deadline: ?std.Io.Clock.Timestamp) (std.Io.Cancelable || error{Timeout})!void {
    if (deadline) |until| _ = try deadline_policy.usableAwake(io, until);
    if (connection.negotiatedTlsProtocol() != .tls12) return;
    var guard: ?Guard = if (cache.max_entries != 0) try Guard.initBefore(&cache.mutex, io, deadline) else null;
    defer if (guard) |*owned| owned.unlock();
    if (connection.takeTls12SessionTicket()) |ticket| {
        const now = @max(0, std.Io.Clock.real.now(io).toSeconds());
        cache.storeLocked(host, port, ticket, @intCast(now));
    } else if (guard != null and !(connection.wasTlsSessionResumed() orelse false)) {
        remove(cache, connection, host, port, exact_alpn);
    }
}

pub fn remember13(cache: anytype, connection: anytype, host: []const u8, port: u16, exact_alpn: bool, attempted_resumption: bool, io: std.Io, deadline: ?std.Io.Clock.Timestamp) (tls.Error || std.Io.Cancelable || error{Timeout})!bool {
    if (deadline) |until| _ = try deadline_policy.usableAwake(io, until);
    if (connection.negotiatedTlsProtocol() != .tls13) return false;
    var guard: ?Guard = if (cache.max_entries != 0) try Guard.initBefore(&cache.mutex, io, deadline) else null;
    defer if (guard) |*owned| owned.unlock();
    if (try connection.takeTls13SessionTicket()) |ticket| {
        const now = std.Io.Clock.real.now(io).nanoseconds;
        cache.storeLocked(host, port, ticket, if (now <= 0) 0 else @intCast(@divFloor(now, std.time.ns_per_ms)));
        return true;
    }
    if (guard != null and attempted_resumption and !(connection.wasTlsSessionResumed() orelse false)) {
        remove(cache, connection, host, port, exact_alpn);
    }
    return false;
}

fn remove(cache: anytype, connection: anytype, host: []const u8, port: u16, exact_alpn: bool) void {
    if (exact_alpn) {
        _ = cache.removeForAlpnLocked(host, port, connection.negotiatedAlpn() orelse "");
    } else _ = cache.removeLocked(host, port);
}
