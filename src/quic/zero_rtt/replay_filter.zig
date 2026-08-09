//! Bounded, thread-safe replay gate for accepted TLS 1.3 early data.
//!
//! A replay filter cannot make 0-RTT intrinsically replay-safe, but it gives a
//! server deployment a strict single-acceptance gate for an application-chosen
//! replay key. Entries expire at the ticket's expiry and the oldest expiry is
//! evicted when the configured bound is reached.

const std = @import("std");
const vail = @import("vail");

pub const Error = std.mem.Allocator.Error || error{
    InvalidCapacity,
    InvalidReplayKey,
    ReplayedEarlyData,
};

const Entry = struct {
    key: [32]u8,
    expires_at_ms: u64,
};

pub const Filter = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    entries: std.ArrayList(Entry) = .empty,
    max_entries: usize,
    mutex: std.Io.Mutex = .init,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        max_entries: usize,
    ) Error!Filter {
        if (max_entries == 0) return error.InvalidCapacity;
        return .{
            .allocator = allocator,
            .io = io,
            .max_entries = max_entries,
        };
    }

    pub fn deinit(self: *Filter) void {
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Atomically reject a replay or remember the key until ticket expiry.
    pub fn checkAndMark(
        self: *Filter,
        replay_key: []const u8,
        now_ms: u64,
        expires_at_ms: u64,
    ) Error!void {
        if (replay_key.len == 0 or expires_at_ms <= now_ms) {
            return error.InvalidReplayKey;
        }
        const digest = digestReplayKey(replay_key);

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        self.pruneExpired(now_ms);
        for (self.entries.items) |entry| {
            if (vail.crypto.sha256.eql(entry.key, digest)) {
                return error.ReplayedEarlyData;
            }
        }

        if (self.entries.items.len < self.max_entries) {
            try self.entries.ensureUnusedCapacity(self.allocator, 1);
        } else {
            const evict = self.earliestExpiryIndex();
            _ = self.entries.swapRemove(evict);
        }
        self.entries.appendAssumeCapacity(.{
            .key = digest,
            .expires_at_ms = expires_at_ms,
        });
    }

    pub fn count(self: *Filter) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.entries.items.len;
    }

    fn pruneExpired(self: *Filter, now_ms: u64) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (self.entries.items[index].expires_at_ms <= now_ms) {
                _ = self.entries.swapRemove(index);
            } else {
                index += 1;
            }
        }
    }

    fn earliestExpiryIndex(self: Filter) usize {
        var earliest: usize = 0;
        for (self.entries.items[1..], 1..) |entry, index| {
            if (entry.expires_at_ms <
                self.entries.items[earliest].expires_at_ms)
            {
                earliest = index;
            }
        }
        return earliest;
    }
};

fn digestReplayKey(replay_key: []const u8) [32]u8 {
    return vail.crypto.sha256.hash(replay_key);
}

test "0-RTT replay filter rejects duplicates and expires bounded entries" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var filter = try Filter.init(
        std.testing.allocator,
        threaded.io(),
        2,
    );
    defer filter.deinit();

    try filter.checkAndMark("first", 1000, 2000);
    try std.testing.expectError(
        error.ReplayedEarlyData,
        filter.checkAndMark("first", 1001, 2000),
    );
    try filter.checkAndMark("second", 1001, 1500);
    try filter.checkAndMark("third", 1002, 3000);
    try std.testing.expectEqual(@as(usize, 2), filter.count());

    try filter.checkAndMark("first", 3000, 4000);
    try std.testing.expectEqual(@as(usize, 1), filter.count());
}
