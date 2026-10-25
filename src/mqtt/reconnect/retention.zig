//! MQTT Session lifetime is separate from desired subscriptions and retry policy.
const std = @import("std");
const mqtt = @import("../mod.zig");
const persistence = @import("../persistence/codec.zig");

pub const View = struct {
    interval: u32,
    /// Null means MQTT's 0xffffffff lifetime. Finite intervals carry their
    /// remaining offline lifetime; an online image starts at its saved time.
    remaining_ns: ?u64,
};

pub const State = struct {
    interval: u32,
    expires_at: ?std.Io.Timestamp = null,

    pub fn configured(protocol: mqtt.ProtocolVersion, clean_start: bool, properties: []const mqtt.Property) State {
        return .{ .interval = if (protocol == .v5) mqtt.sessionExpiryInterval(properties) orelse 0 else if (clean_start) 0 else std.math.maxInt(u32) };
    }

    pub fn connected(self: *State, interval: u32) void {
        self.* = .{ .interval = interval };
    }

    pub fn disconnected(self: *State, now: std.Io.Timestamp) void {
        self.expires_at = if (self.interval == std.math.maxInt(u32)) null else .fromNanoseconds(now.nanoseconds +| @as(i96, self.interval) * std.time.ns_per_s);
    }

    pub fn expired(self: State, now: std.Io.Timestamp) bool {
        const deadline = self.expires_at orelse return false;
        return self.interval == 0 or now.nanoseconds >= deadline.nanoseconds;
    }

    pub fn view(self: State, now: std.Io.Timestamp) View {
        if (self.interval == std.math.maxInt(u32)) return .{ .interval = self.interval, .remaining_ns = null };
        const interval_ns = @as(u64, self.interval) * std.time.ns_per_s;
        const remaining: u64 = if (self.expires_at) |deadline|
            @intCast(std.math.clamp(deadline.nanoseconds -| now.nanoseconds, 0, interval_ns))
        else
            interval_ns;
        return .{ .interval = self.interval, .remaining_ns = remaining };
    }
};

pub fn encode(out: *std.ArrayList(u8), allocator: std.mem.Allocator, protocol: mqtt.ProtocolVersion, view: View) persistence.Error!void {
    try validate(protocol, view);
    try persistence.appendInt(out, allocator, u32, view.interval);
    try persistence.appendOptionalInt(out, allocator, u64, view.remaining_ns);
}

pub fn decode(cursor: *persistence.Cursor, protocol: mqtt.ProtocolVersion, downtime_ns: i96, now: std.Io.Timestamp) persistence.Error!State {
    const value = View{ .interval = try cursor.readInt(u32), .remaining_ns = try cursor.readOptionalInt(u64) };
    try validate(protocol, value);
    const remaining = value.remaining_ns orelse return .{ .interval = value.interval };
    const after_downtime = @max(0, @as(i96, remaining) - @max(0, downtime_ns));
    return .{ .interval = value.interval, .expires_at = .fromNanoseconds(now.nanoseconds +| after_downtime) };
}

fn validate(protocol: mqtt.ProtocolVersion, value: View) persistence.Error!void {
    if (protocol != .v5 and value.interval != std.math.maxInt(u32)) return error.CorruptSnapshot;
    if (value.interval == std.math.maxInt(u32)) {
        if (value.remaining_ns != null) return error.CorruptSnapshot;
    } else {
        const remaining = value.remaining_ns orelse return error.CorruptSnapshot;
        if (remaining > @as(u64, value.interval) * std.time.ns_per_s) return error.CorruptSnapshot;
    }
}
