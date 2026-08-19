//! RFC 9204 dynamic table storage, eviction, and lookup indexes.

const std = @import("std");

pub const Error = error{QpackEncoderStreamError} || std.mem.Allocator.Error;

pub const dynamic_entry_overhead: usize = 32;

fn dynamicStringHash(bytes: []const u8) u64 {
    return std.hash.Wyhash.hash(0, bytes);
}

const DynamicExactKey = struct {
    name_hash: u64,
    value_hash: u64,
};

pub const DynamicEntry = struct {
    absolute_index: u64,
    name: []u8,
    value: []u8,
    name_hash: u64,
    value_hash: u64,

    pub fn size(self: DynamicEntry) usize {
        return self.name.len + self.value.len + dynamic_entry_overhead;
    }

    fn deinit(self: *DynamicEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.name.ptr[0 .. self.name.len + self.value.len]);
        self.* = undefined;
    }
};

/// RFC 9204 dynamic table, ordered oldest-to-newest.
///
/// `head` avoids O(n) shifts on eviction. Compaction is deferred until the
/// consumed prefix is at least half the allocation, keeping inserts and
/// normal capacity pressure amortized O(1) while absolute indexes remain
/// explicit and independent of storage position.
pub const DynamicTable = struct {
    pub const Match = struct {
        absolute_index: u64,
        full_match: bool,
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(DynamicEntry) = .empty,
    /// These indexes deliberately key hashes rather than borrowed slices:
    /// entries own the strings and can move during compaction. A hash hit
    /// is always verified against the entry bytes, so collisions preserve
    /// correctness and only fall back to the reverse scan.
    latest_name: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    latest_exact: std.AutoHashMapUnmanaged(DynamicExactKey, u64) = .empty,
    head: usize = 0,
    current_size: usize = 0,
    capacity: usize = 0,
    max_capacity: usize,
    insert_count: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, max_capacity: usize) DynamicTable {
        return .{ .allocator = allocator, .max_capacity = max_capacity };
    }

    pub fn deinit(self: *DynamicTable) void {
        for (self.entries.items[self.head..]) |*entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.latest_name.deinit(self.allocator);
        self.latest_exact.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn entryCount(self: DynamicTable) usize {
        return self.entries.items.len - self.head;
    }

    pub fn maxEntries(self: DynamicTable) u64 {
        return @intCast(self.max_capacity / dynamic_entry_overhead);
    }

    pub fn setCapacity(self: *DynamicTable, new_capacity: usize) Error!void {
        if (new_capacity > self.max_capacity) return error.QpackEncoderStreamError;
        self.capacity = new_capacity;
        self.evictToFit(0);
    }

    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) Error!u64 {
        const entry_size = dynamicEntrySize(name, value) catch return error.QpackEncoderStreamError;
        if (entry_size > self.capacity) {
            self.clearEntries();
            return error.QpackEncoderStreamError;
        }
        const next_insert_count = std.math.add(u64, self.insert_count, 1) catch
            return error.QpackEncoderStreamError;
        const name_hash = dynamicStringHash(name);
        const value_hash = dynamicStringHash(value);
        // Name/value can borrow from an entry that this insertion evicts
        // (Duplicate and dynamic-name-reference instructions both allow
        // this). Stabilize them before changing table ownership.
        self.compactIfNeeded();
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        // Reserve both indexes before eviction. Once table ownership
        // changes, every following operation is allocation-free and the
        // insertion cannot leave entries and indexes out of sync.
        const name_slot = try self.latest_name.getOrPut(
            self.allocator,
            name_hash,
        );
        errdefer if (!name_slot.found_existing) {
            _ = self.latest_name.remove(name_hash);
        };
        const exact_key = DynamicExactKey{
            .name_hash = name_hash,
            .value_hash = value_hash,
        };
        const exact_slot = try self.latest_exact.getOrPut(
            self.allocator,
            exact_key,
        );
        errdefer if (!exact_slot.found_existing) {
            _ = self.latest_exact.remove(exact_key);
        };
        const string_len = std.math.add(usize, name.len, value.len) catch
            return error.QpackEncoderStreamError;
        const strings = try self.allocator.alloc(u8, string_len);
        errdefer self.allocator.free(strings);
        @memcpy(strings[0..name.len], name);
        @memcpy(strings[name.len..], value);
        const absolute_index = self.insert_count;
        // A capacity eviction below may retire the previous latest entry for
        // this name/exact key. Point the index at the new absolute index before
        // eviction so removing that old entry does not delete the freshly
        // reserved slot.
        name_slot.value_ptr.* = absolute_index;
        exact_slot.value_ptr.* = absolute_index;
        self.evictToFit(entry_size);

        self.entries.appendAssumeCapacity(.{
            .absolute_index = absolute_index,
            .name = strings[0..name.len],
            .value = strings[name.len..],
            .name_hash = name_hash,
            .value_hash = value_hash,
        });
        self.current_size += entry_size;
        self.insert_count = next_insert_count;
        return absolute_index;
    }

    pub fn duplicate(self: *DynamicTable, relative_index: u64) Error!u64 {
        const entry = self.relative(relative_index) orelse return error.QpackEncoderStreamError;
        return self.insert(entry.name, entry.value);
    }

    /// Encoder-stream relative indexes use the current insertion point:
    /// zero identifies the most recently inserted entry.
    pub fn relative(self: DynamicTable, relative_index: u64) ?DynamicEntry {
        const count = self.entryCount();
        const index = std.math.cast(usize, relative_index) orelse return null;
        if (index >= count) return null;
        return self.entries.items[self.entries.items.len - 1 - index];
    }

    pub fn absolute(self: DynamicTable, absolute_index: u64) ?DynamicEntry {
        if (self.entryCount() == 0) return null;
        const oldest = self.entries.items[self.head].absolute_index;
        if (absolute_index < oldest or absolute_index >= self.insert_count) return null;
        const offset = std.math.cast(usize, absolute_index - oldest) orelse return null;
        const index = self.head + offset;
        if (index >= self.entries.items.len) return null;
        const entry = self.entries.items[index];
        if (entry.absolute_index != absolute_index) return null;
        return entry;
    }

    pub fn fieldRelativeToBase(self: DynamicTable, base: u64, relative_index: u64) ?DynamicEntry {
        if (relative_index >= base) return null;
        return self.absolute(base - relative_index - 1);
    }

    pub fn fieldPostBase(self: DynamicTable, base: u64, post_base_index: u64) ?DynamicEntry {
        const absolute_index = std.math.add(u64, base, post_base_index) catch return null;
        return self.absolute(absolute_index);
    }

    pub fn findExact(self: DynamicTable, name: []const u8, value: []const u8) ?u64 {
        const match = self.findMatchBefore(
            name,
            value,
            self.insert_count,
        ) orelse return null;
        return if (match.full_match) match.absolute_index else null;
    }

    pub fn findExactBefore(
        self: DynamicTable,
        name: []const u8,
        value: []const u8,
        absolute_index_limit: u64,
    ) ?u64 {
        const match = self.findMatchBefore(
            name,
            value,
            absolute_index_limit,
        ) orelse return null;
        return if (match.full_match) match.absolute_index else null;
    }

    /// Find the newest exact match, or otherwise the newest name match,
    /// before `absolute_index_limit`. Unrestricted current-table lookups
    /// normally use the indexes; restricted or colliding keys scan.
    pub fn findMatchBefore(
        self: DynamicTable,
        name: []const u8,
        value: []const u8,
        absolute_index_limit: u64,
    ) ?Match {
        // Non-blocking encoders often pass Known Received Count as the limit.
        // Before the decoder acknowledges any inserts (or after the table is
        // emptied) no dynamic reference can be legal, so skip hash-map probes.
        if (absolute_index_limit == 0 or self.entryCount() == 0) return null;
        const name_hash = dynamicStringHash(name);
        const value_hash = dynamicStringHash(value);
        const exact_key = DynamicExactKey{
            .name_hash = name_hash,
            .value_hash = value_hash,
        };
        if (self.latest_exact.get(exact_key)) |absolute_index| {
            if (absolute_index < absolute_index_limit) {
                if (self.absolute(absolute_index)) |entry| {
                    if (entry.name_hash == name_hash and
                        entry.value_hash == value_hash and
                        std.mem.eql(u8, entry.name, name) and
                        std.mem.eql(u8, entry.value, value))
                    {
                        return .{
                            .absolute_index = absolute_index,
                            .full_match = true,
                        };
                    }
                }
            }
            // An ineligible newest entry can hide an older eligible
            // entry, and a hash collision can hide an unrelated key.
            // Preserve exact-before-name preference with the full scan.
            return self.findMatchBeforeLinear(
                name,
                value,
                name_hash,
                value_hash,
                absolute_index_limit,
            );
        }

        if (self.latest_name.get(name_hash)) |absolute_index| {
            if (absolute_index < absolute_index_limit) {
                if (self.absolute(absolute_index)) |entry| {
                    if (entry.name_hash == name_hash and
                        std.mem.eql(u8, entry.name, name))
                    {
                        return .{
                            .absolute_index = absolute_index,
                            .full_match = false,
                        };
                    }
                }
            }
            return self.findMatchBeforeLinear(
                name,
                value,
                name_hash,
                value_hash,
                absolute_index_limit,
            );
        }
        return null;
    }

    fn findMatchBeforeLinear(
        self: DynamicTable,
        name: []const u8,
        value: []const u8,
        name_hash: u64,
        value_hash: u64,
        absolute_index_limit: u64,
    ) ?Match {
        var name_match: ?u64 = null;
        var index = self.entries.items.len;
        while (index > self.head) {
            index -= 1;
            const entry = self.entries.items[index];
            if (entry.absolute_index >= absolute_index_limit) continue;
            if (entry.name_hash != name_hash) continue;
            if (!std.mem.eql(u8, entry.name, name)) continue;
            if (entry.value_hash == value_hash and
                std.mem.eql(u8, entry.value, value))
            {
                return .{
                    .absolute_index = entry.absolute_index,
                    .full_match = true,
                };
            }
            if (name_match == null) name_match = entry.absolute_index;
        }
        return if (name_match) |absolute_index| .{
            .absolute_index = absolute_index,
            .full_match = false,
        } else null;
    }

    pub fn findName(self: DynamicTable, name: []const u8) ?u64 {
        return self.findNameBefore(name, self.insert_count);
    }

    pub fn findNameBefore(
        self: DynamicTable,
        name: []const u8,
        absolute_index_limit: u64,
    ) ?u64 {
        if (absolute_index_limit == 0 or self.entryCount() == 0) return null;
        const name_hash = dynamicStringHash(name);
        if (self.latest_name.get(name_hash)) |absolute_index| {
            if (absolute_index < absolute_index_limit) {
                if (self.absolute(absolute_index)) |entry| {
                    if (entry.name_hash == name_hash and
                        std.mem.eql(u8, entry.name, name))
                    {
                        return absolute_index;
                    }
                }
            }
            return self.findNameBeforeLinear(
                name,
                name_hash,
                absolute_index_limit,
            );
        }
        return null;
    }

    fn findNameBeforeLinear(
        self: DynamicTable,
        name: []const u8,
        name_hash: u64,
        absolute_index_limit: u64,
    ) ?u64 {
        var index = self.entries.items.len;
        while (index > self.head) {
            index -= 1;
            const entry = self.entries.items[index];
            if (entry.absolute_index >= absolute_index_limit) continue;
            if (entry.name_hash != name_hash) continue;
            if (std.mem.eql(u8, entry.name, name)) return entry.absolute_index;
        }
        return null;
    }

    fn evictToFit(self: *DynamicTable, incoming_size: usize) void {
        while (self.entryCount() != 0 and
            (self.current_size > self.capacity or
                incoming_size > self.capacity - self.current_size))
        {
            var entry = &self.entries.items[self.head];
            self.current_size -= entry.size();
            self.removeLatestIndexes(entry.*);
            entry.deinit(self.allocator);
            self.head += 1;
        }
        self.compactIfNeeded();
    }

    fn clearEntries(self: *DynamicTable) void {
        for (self.entries.items[self.head..]) |*entry| entry.deinit(self.allocator);
        self.entries.clearRetainingCapacity();
        self.latest_name.clearRetainingCapacity();
        self.latest_exact.clearRetainingCapacity();
        self.head = 0;
        self.current_size = 0;
    }

    fn removeLatestIndexes(self: *DynamicTable, entry: DynamicEntry) void {
        if (self.latest_name.get(entry.name_hash) == entry.absolute_index) {
            // Eviction is strictly oldest-to-newest. If the "latest" entry for
            // this hash is the one being evicted, no newer live representative
            // can exist, so removal is sufficient and avoids a reverse scan on
            // every capacity-pressure pop.
            _ = self.latest_name.remove(entry.name_hash);
        }
        const exact_key = DynamicExactKey{
            .name_hash = entry.name_hash,
            .value_hash = entry.value_hash,
        };
        if (self.latest_exact.get(exact_key) == entry.absolute_index) {
            // Same FIFO invariant as above, but scoped to exact name/value
            // hashes. Collisions are still verified by lookup; this only
            // removes a stale newest pointer.
            _ = self.latest_exact.remove(exact_key);
        }
    }

    fn compactIfNeeded(self: *DynamicTable) void {
        if (self.head == 0) return;
        if (self.head < self.entries.items.len / 2 and self.entryCount() != 0) return;
        const remaining = self.entryCount();
        @memmove(self.entries.items[0..remaining], self.entries.items[self.head..]);
        self.entries.items.len = remaining;
        self.head = 0;
    }
};

fn dynamicEntrySize(name: []const u8, value: []const u8) error{IntegerOverflow}!usize {
    const strings = std.math.add(usize, name.len, value.len) catch return error.IntegerOverflow;
    return std.math.add(usize, strings, dynamic_entry_overhead) catch error.IntegerOverflow;
}
