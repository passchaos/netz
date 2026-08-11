//! Bounded, thread-safe replay gate for accepted TLS 1.3 early data.
//!
//! A replay filter cannot make 0-RTT intrinsically replay-safe, but it gives a
//! server deployment a strict single-acceptance gate for an application-chosen
//! replay key. Entries expire at the ticket's expiry and the oldest expiry is
//! evicted when the configured bound is reached. A digest-to-entry index keeps
//! the hot duplicate check O(1), while the entry list preserves the bounded
//! eviction/snapshot working set.

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

pub const SnapshotEntry = struct {
    key: [32]u8,
    expires_at_ms: u64,
};

pub const Snapshot = struct {
    entries: []SnapshotEntry,

    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        self.* = undefined;
    }
};

pub const Filter = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    entries: std.ArrayList(Entry) = .empty,
    /// Maps replay-key digests to their current physical slot in `entries`.
    /// `entries` is allowed to swap-remove for O(1) pruning/eviction, so every
    /// removal must update the moved entry's slot before any future lookup.
    entry_index: std.AutoHashMapUnmanaged([32]u8, usize) = .empty,
    earliest_index: ?usize = null,
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

    pub fn initWithSnapshot(
        allocator: std.mem.Allocator,
        io: std.Io,
        max_entries: usize,
        snapshot: Snapshot,
        now_ms: u64,
    ) Error!Filter {
        var filter = try Filter.init(allocator, io, max_entries);
        errdefer filter.deinit();
        try filter.restoreSnapshot(snapshot, now_ms);
        return filter;
    }

    pub fn deinit(self: *Filter) void {
        self.entries.deinit(self.allocator);
        self.entry_index.deinit(self.allocator);
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

        _ = self.pruneExpiredUnlocked(now_ms);
        const slot = try self.entry_index.getOrPut(self.allocator, digest);
        if (slot.found_existing) return error.ReplayedEarlyData;
        errdefer _ = self.entry_index.remove(digest);

        if (self.entries.items.len < self.max_entries) {
            try self.entries.ensureUnusedCapacity(self.allocator, 1);
            self.appendEntryAssumeCapacity(.{
                .key = digest,
                .expires_at_ms = expires_at_ms,
            }, slot.value_ptr);
        } else {
            self.removeEntryAt(self.earliestExpiryIndex());
            // Eviction mutates entry_index, so reacquire the slot after the
            // old digest is removed. The non-evicting hot path above still
            // performs one map lookup for duplicate detection and insertion.
            const fresh_slot = self.entry_index.getPtr(digest).?;
            self.appendEntryAssumeCapacity(.{
                .key = digest,
                .expires_at_ms = expires_at_ms,
            }, fresh_slot);
        }
    }

    pub fn exportSnapshot(self: *Filter, allocator: std.mem.Allocator) Error!Snapshot {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const entries = try allocator.alloc(SnapshotEntry, self.entries.items.len);
        errdefer allocator.free(entries);
        for (self.entries.items, entries) |entry, *out| {
            out.* = .{
                .key = entry.key,
                .expires_at_ms = entry.expires_at_ms,
            };
        }
        return .{ .entries = entries };
    }

    pub fn count(self: *Filter) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.entries.items.len;
    }

    pub fn entryCount(self: *Filter) usize {
        return self.count();
    }

    pub fn nextExpiryMillis(self: *Filter) ?u64 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const index = self.earliest_index orelse return null;
        return self.entries.items[index].expires_at_ms;
    }

    pub fn pruneExpired(self: *Filter, now_ms: u64) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.pruneExpiredUnlocked(now_ms);
    }

    fn pruneExpiredUnlocked(self: *Filter, now_ms: u64) usize {
        const earliest = self.earliest_index orelse return 0;
        if (self.entries.items[earliest].expires_at_ms > now_ms) return 0;

        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (self.entries.items[index].expires_at_ms <= now_ms) {
                self.removeEntryAt(index);
                removed += 1;
            } else {
                index += 1;
            }
        }
        return removed;
    }

    fn restoreSnapshot(self: *Filter, snapshot: Snapshot, now_ms: u64) Error!void {
        for (snapshot.entries) |entry| {
            if (entry.expires_at_ms <= now_ms) continue;
            if (self.entry_index.count() != 0) {
                if (self.entry_index.get(entry.key)) |existing| {
                    if (entry.expires_at_ms > self.entries.items[existing].expires_at_ms) {
                        self.entries.items[existing].expires_at_ms = entry.expires_at_ms;
                        if (self.earliest_index == existing) self.recomputeEarliest();
                    }
                    continue;
                }
            }
            if (self.entries.items.len < self.max_entries) {
                const slot = try self.entry_index.getOrPut(
                    self.allocator,
                    entry.key,
                );
                std.debug.assert(!slot.found_existing);
                errdefer _ = self.entry_index.remove(entry.key);
                try self.entries.ensureUnusedCapacity(self.allocator, 1);
                self.appendEntryAssumeCapacity(.{
                    .key = entry.key,
                    .expires_at_ms = entry.expires_at_ms,
                }, slot.value_ptr);
                continue;
            }
            const evict = self.earliestExpiryIndex();
            if (entry.expires_at_ms <= self.entries.items[evict].expires_at_ms) continue;
            self.removeEntryAt(evict);
            const slot = self.entry_index.getOrPutAssumeCapacity(entry.key);
            std.debug.assert(!slot.found_existing);
            self.appendEntryAssumeCapacity(.{
                .key = entry.key,
                .expires_at_ms = entry.expires_at_ms,
            }, slot.value_ptr);
        }
    }

    fn appendEntryAssumeCapacity(
        self: *Filter,
        entry: Entry,
        index_slot: *usize,
    ) void {
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(entry);
        index_slot.* = index;
        self.considerEarliest(index);
    }

    fn removeEntryAt(self: *Filter, index: usize) void {
        const last_index = self.entries.items.len - 1;
        const earliest = self.earliest_index;
        const removed = self.entries.swapRemove(index);
        _ = self.entry_index.remove(removed.key);
        if (index != last_index) {
            const moved = self.entries.items[index];
            self.entry_index.getPtr(moved.key).?.* = index;
        }
        if (self.entries.items.len == 0) {
            self.earliest_index = null;
        } else if (earliest == index) {
            self.recomputeEarliest();
        } else if (earliest == last_index) {
            self.earliest_index = index;
        }
    }

    fn earliestExpiryIndex(self: *const Filter) usize {
        return self.earliest_index.?;
    }

    fn considerEarliest(self: *Filter, index: usize) void {
        const earliest = self.earliest_index orelse {
            self.earliest_index = index;
            return;
        };
        if (self.entries.items[index].expires_at_ms <
            self.entries.items[earliest].expires_at_ms)
        {
            self.earliest_index = index;
        }
    }

    fn recomputeEarliest(self: *Filter) void {
        if (self.entries.items.len == 0) {
            self.earliest_index = null;
            return;
        }
        var earliest: usize = 0;
        for (self.entries.items[1..], 1..) |entry, index| {
            if (entry.expires_at_ms <
                self.entries.items[earliest].expires_at_ms)
            {
                earliest = index;
            }
        }
        self.earliest_index = earliest;
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
    try std.testing.expect(filter.entry_index.contains(digestReplayKey("first")));
    try std.testing.expectError(
        error.ReplayedEarlyData,
        filter.checkAndMark("first", 1001, 2000),
    );
    try filter.checkAndMark("second", 1001, 1500);
    try std.testing.expectEqual(@as(?usize, 1), filter.earliest_index);
    try filter.checkAndMark("third", 1002, 3000);
    try std.testing.expectEqual(@as(usize, 2), filter.entryCount());
    try std.testing.expect(!filter.entry_index.contains(digestReplayKey("second")));
    try std.testing.expect(filter.entry_index.contains(digestReplayKey("third")));
    try std.testing.expectEqual(@as(?u64, 2000), filter.nextExpiryMillis());
    try std.testing.expect(filter.earliest_index != null);

    try filter.checkAndMark("first", 3000, 4000);
    try std.testing.expectEqual(@as(usize, 1), filter.count());
    try std.testing.expectEqual(@as(?u64, 4000), filter.nextExpiryMillis());
}

test "0-RTT replay filter prunes expired entries explicitly" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var filter = try Filter.init(
        std.testing.allocator,
        threaded.io(),
        4,
    );
    defer filter.deinit();

    try filter.checkAndMark("expired", 1000, 1500);
    try filter.checkAndMark("live", 1000, 2500);
    try std.testing.expectEqual(@as(usize, 2), filter.count());
    try std.testing.expectEqual(@as(?u64, 1500), filter.nextExpiryMillis());
    try std.testing.expectEqual(@as(usize, 1), filter.pruneExpired(1500));
    try std.testing.expectEqual(@as(usize, 1), filter.count());
    try std.testing.expectEqual(@as(?u64, 2500), filter.nextExpiryMillis());
    try filter.checkAndMark("expired", 1501, 3000);
    try std.testing.expectError(
        error.ReplayedEarlyData,
        filter.checkAndMark("live", 1501, 2500),
    );
}

test "0-RTT replay filter exports and restores snapshots" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var filter = try Filter.init(std.testing.allocator, io, 2);
    defer filter.deinit();
    try filter.checkAndMark("first", 1000, 2000);
    try filter.checkAndMark("second", 1001, 1500);
    try filter.checkAndMark("third", 1002, 3000);

    var snapshot = try filter.exportSnapshot(std.testing.allocator);
    defer snapshot.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), snapshot.entries.len);

    var restored = try Filter.initWithSnapshot(
        std.testing.allocator,
        io,
        2,
        snapshot,
        1003,
    );
    defer restored.deinit();
    try std.testing.expectError(
        error.ReplayedEarlyData,
        restored.checkAndMark("first", 1004, 2000),
    );
    try std.testing.expectError(
        error.ReplayedEarlyData,
        restored.checkAndMark("third", 1004, 3000),
    );

    var trimmed = try Filter.initWithSnapshot(
        std.testing.allocator,
        io,
        1,
        snapshot,
        1003,
    );
    defer trimmed.deinit();
    try std.testing.expectEqual(@as(usize, 1), trimmed.count());
    try std.testing.expectError(
        error.ReplayedEarlyData,
        trimmed.checkAndMark("third", 1004, 3000),
    );
    try trimmed.checkAndMark("first", 1004, 2000);
}

test "0-RTT replay filter snapshot restore skips expired and duplicate entries" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var entries = [_]SnapshotEntry{
        .{ .key = digestReplayKey("old"), .expires_at_ms = 900 },
        .{ .key = digestReplayKey("first"), .expires_at_ms = 2000 },
        .{ .key = digestReplayKey("first"), .expires_at_ms = 2500 },
        .{ .key = digestReplayKey("second"), .expires_at_ms = 3000 },
    };
    const snapshot = Snapshot{ .entries = &entries };

    var restored = try Filter.initWithSnapshot(
        std.testing.allocator,
        io,
        2,
        snapshot,
        1000,
    );
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 2), restored.count());
    try std.testing.expectEqual(@as(usize, 2), restored.entry_index.count());
    try std.testing.expect(restored.earliest_index != null);
    try std.testing.expectError(
        error.ReplayedEarlyData,
        restored.checkAndMark("first", 1001, 4000),
    );
    try std.testing.expectError(
        error.ReplayedEarlyData,
        restored.checkAndMark("second", 1001, 4000),
    );
    try restored.checkAndMark("old", 1001, 4000);
}
