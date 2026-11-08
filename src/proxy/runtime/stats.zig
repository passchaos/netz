//! Atomic proxy statistics.

const std = @import("std");

pub const Snapshot = struct {
    connections_total: u64,
    active_connections: u64,
    bytes_in: u64,
    bytes_out: u64,
    auth_failures: u64,
    denied_requests: u64,
    errors: u64,
};

pub const Stats = struct {
    connections_total: std.atomic.Value(u64) = .init(0),
    active_connections: std.atomic.Value(u64) = .init(0),
    bytes_in: std.atomic.Value(u64) = .init(0),
    bytes_out: std.atomic.Value(u64) = .init(0),
    auth_failures: std.atomic.Value(u64) = .init(0),
    denied_requests: std.atomic.Value(u64) = .init(0),
    errors: std.atomic.Value(u64) = .init(0),

    pub fn connectionOpened(self: *Stats) void {
        _ = self.connections_total.fetchAdd(1, .monotonic);
        _ = self.active_connections.fetchAdd(1, .monotonic);
    }

    pub fn connectionClosed(self: *Stats) void {
        _ = self.active_connections.fetchSub(1, .monotonic);
    }

    pub fn addBytesIn(self: *Stats, count: u64) void {
        _ = self.bytes_in.fetchAdd(count, .monotonic);
    }

    pub fn addBytesOut(self: *Stats, count: u64) void {
        _ = self.bytes_out.fetchAdd(count, .monotonic);
    }

    pub fn authFailure(self: *Stats) void {
        _ = self.auth_failures.fetchAdd(1, .monotonic);
    }

    pub fn deniedRequest(self: *Stats) void {
        _ = self.denied_requests.fetchAdd(1, .monotonic);
    }

    pub fn recordError(self: *Stats) void {
        _ = self.errors.fetchAdd(1, .monotonic);
    }

    pub fn snapshot(self: *const Stats) Snapshot {
        return .{
            .connections_total = self.connections_total.load(.monotonic),
            .active_connections = self.active_connections.load(.monotonic),
            .bytes_in = self.bytes_in.load(.monotonic),
            .bytes_out = self.bytes_out.load(.monotonic),
            .auth_failures = self.auth_failures.load(.monotonic),
            .denied_requests = self.denied_requests.load(.monotonic),
            .errors = self.errors.load(.monotonic),
        };
    }
};

test "stats count connections bytes and failures" {
    var stats = Stats{};
    stats.connectionOpened();
    stats.connectionOpened();
    stats.connectionClosed();
    stats.addBytesIn(1024);
    stats.addBytesOut(2048);
    stats.authFailure();
    stats.deniedRequest();
    stats.recordError();

    const snapshot = stats.snapshot();
    try std.testing.expectEqual(@as(u64, 2), snapshot.connections_total);
    try std.testing.expectEqual(@as(u64, 1), snapshot.active_connections);
    try std.testing.expectEqual(@as(u64, 1024), snapshot.bytes_in);
    try std.testing.expectEqual(@as(u64, 2048), snapshot.bytes_out);
    try std.testing.expectEqual(@as(u64, 1), snapshot.auth_failures);
    try std.testing.expectEqual(@as(u64, 1), snapshot.denied_requests);
    try std.testing.expectEqual(@as(u64, 1), snapshot.errors);
}

test "stats are safe under concurrent increments" {
    var stats = Stats{};
    const Worker = struct {
        stats: *Stats,
        fn run(self: *@This()) void {
            for (0..1000) |_| {
                self.stats.addBytesIn(1);
            }
        }
    };
    var workers: [4]Worker = undefined;
    var threads: [4]std.Thread = undefined;
    for (&workers, &threads) |*worker, *thread| {
        worker.* = .{ .stats = &stats };
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{worker});
    }
    for (&threads) |thread| thread.join();
    try std.testing.expectEqual(@as(u64, 4000), stats.snapshot().bytes_in);
}
