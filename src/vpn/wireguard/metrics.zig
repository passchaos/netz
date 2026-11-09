//! WireGuard protocol counters for lifecycle and operational measurement.
//!
//! Counters are deliberately simple saturating-free u64 values updated on the
//! owning thread. They give callers evidence for handshake health, rekeying,
//! cookie pressure, and data transfer without touching hot-path allocations.

const std = @import("std");

pub const Snapshot = struct {
    handshakes_initiated: u64,
    handshakes_completed: u64,
    handshakes_failed: u64,
    cookie_replies_issued: u64,
    sessions_installed: u64,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
};

pub const Metrics = struct {
    handshakes_initiated: u64 = 0,
    handshakes_completed: u64 = 0,
    handshakes_failed: u64 = 0,
    cookie_replies_issued: u64 = 0,
    sessions_installed: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,

    pub fn reset(self: *Metrics) void {
        self.* = .{};
    }

    pub fn snapshot(self: *const Metrics) Snapshot {
        return .{
            .handshakes_initiated = self.handshakes_initiated,
            .handshakes_completed = self.handshakes_completed,
            .handshakes_failed = self.handshakes_failed,
            .cookie_replies_issued = self.cookie_replies_issued,
            .sessions_installed = self.sessions_installed,
            .packets_sent = self.packets_sent,
            .packets_received = self.packets_received,
            .bytes_sent = self.bytes_sent,
            .bytes_received = self.bytes_received,
        };
    }
};

test "snapshot is an independent copy" {
    var metrics = Metrics{};
    metrics.handshakes_initiated = 3;
    metrics.bytes_sent = 42;
    const snapshot = metrics.snapshot();
    metrics.handshakes_initiated = 4;
    try std.testing.expectEqual(@as(u64, 3), snapshot.handshakes_initiated);
    try std.testing.expectEqual(@as(u64, 42), snapshot.bytes_sent);
}
