//! Atomically swappable ACL policy snapshot.
//!
//! Rules are borrowed from the caller and must outlive the store. Readers get
//! a consistent policy plus generation number without holding the lock while
//! performing network I/O.

const std = @import("std");

const acl = @import("acl.zig");

/// Resolve the policy a server should use for one request.
pub fn policyFor(static_policy: acl.Policy, store: ?*Reloadable) acl.Policy {
    if (store) |value| return value.snapshot().policy;
    return static_policy;
}

pub const Snapshot = struct {
    policy: acl.Policy,
    generation: u64,
};

pub const Reloadable = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    policy: acl.Policy,
    generation: u64 = 0,

    pub fn init(io: std.Io, policy: acl.Policy) Reloadable {
        return .{
            .io = io,
            .policy = policy,
        };
    }

    pub fn update(self: *Reloadable, policy: acl.Policy) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.policy = policy;
        self.generation +%= 1;
    }

    pub fn snapshot(self: *Reloadable) Snapshot {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return .{
            .policy = self.policy,
            .generation = self.generation,
        };
    }
};

test "reloadable policy swaps snapshots and bumps generation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const allow_rules = [_]acl.Rule{.{
        .action = .allow,
        .matcher = .{ .ip = .{
            .family = .ip4,
            .network = .{ 127, 0, 0, 1 } ++ ([_]u8{0} ** 12),
            .prefix = 32,
        } },
    }};
    var store = Reloadable.init(io, .{});
    const denied = store.snapshot();
    try std.testing.expectEqual(@as(u64, 0), denied.generation);
    try std.testing.expectEqual(
        acl.Action.deny,
        denied.policy.decideIp(
            .{ .ip4 = .loopback(9) },
            9,
            .connect,
        ),
    );

    store.update(.{ .rules = &allow_rules });
    const allowed = store.snapshot();
    try std.testing.expectEqual(@as(u64, 1), allowed.generation);
    try std.testing.expectEqual(
        acl.Action.allow,
        allowed.policy.decideIp(
            .{ .ip4 = .loopback(9) },
            9,
            .connect,
        ),
    );
}
