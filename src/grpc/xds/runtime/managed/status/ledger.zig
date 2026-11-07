//! Owned per-resource diagnostic history; preparation never changes the owner.
const std = @import("std");
const csds = @import("../../../csds.zig");
pub const Error = std.mem.Allocator.Error || error{XdsLimitExceeded};
pub const Options = struct {
    max_resources: usize = 65536,
    /// Includes candidate and retained history while an update is staged.
    max_storage_bytes: usize = 64 * 1024 * 1024,
};
pub const Token = struct { owner_id: u64, epoch: u64, sequence: u64 };

pub const Record = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    refs: usize = 1,
    resource: csds.Resource,
    source_key: [32]u8,
    wire_bytes: []u8 = &.{},
    accepted_token: ?Token = null,

    pub fn create(gpa: std.mem.Allocator, resource: csds.Resource, source_key: []const u8) std.mem.Allocator.Error!*Record {
        std.debug.assert(source_key.len == 32);
        const self = try gpa.create(Record);
        self.* = .{ .allocator = gpa, .arena = .init(gpa), .resource = resource, .source_key = source_key[0..32].* };
        errdefer self.release();
        const arena = self.arena.allocator();
        self.resource.type_url = try arena.dupe(u8, resource.type_url);
        self.resource.name = try arena.dupe(u8, resource.name);
        self.resource.version = try arena.dupe(u8, resource.version);
        self.wire_bytes = try gpa.dupe(u8, resource.wire);
        self.resource.wire = self.wire_bytes;
        if (resource.error_state) |failure| {
            self.resource.error_state = .{
                .details = try arena.dupe(u8, failure.details),
                .version_info = try arena.dupe(u8, failure.version_info),
                .last_update_attempt = failure.last_update_attempt,
            };
        }
        return self;
    }
    pub fn retain(self: *Record) *Record {
        self.refs += 1;
        return self;
    }
    pub fn release(self: *Record) void {
        self.refs -= 1;
        if (self.refs != 0) return;
        self.allocator.free(self.wire_bytes);
        self.arena.deinit();
        self.allocator.destroy(self);
    }
    pub fn storageBytes(self: *const Record) Error!usize {
        const metadata = std.math.add(usize, @sizeOf(Record), self.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        return std.math.add(usize, metadata, self.wire_bytes.len) catch error.XdsLimitExceeded;
    }
    pub fn discardWire(self: *Record) void {
        self.allocator.free(self.wire_bytes);
        self.wire_bytes = &.{};
        self.resource.wire = "";
    }
};

fn order(record: *const Record, url: []const u8, name: []const u8) std.math.Order {
    const type_order = std.mem.order(u8, record.resource.type_url, url);
    return if (type_order == .eq) std.mem.order(u8, record.resource.name, name) else type_order;
}

fn position(records: []const *Record, url: []const u8, name: []const u8) struct { index: usize, found: bool } {
    var first: usize = 0;
    var last = records.len;
    while (first < last) {
        const middle = first + (last - first) / 2;
        switch (order(records[middle], url, name)) {
            .lt => first = middle + 1,
            .gt => last = middle,
            .eq => return .{ .index = middle, .found = true },
        }
    }
    return .{ .index = first, .found = false };
}

pub const Ledger = struct {
    allocator: std.mem.Allocator,
    options: Options,
    records: std.ArrayList(*Record) = .empty,
    pub fn init(gpa: std.mem.Allocator, options: Options) Ledger {
        return .{ .allocator = gpa, .options = options };
    }
    pub fn deinit(self: *Ledger) void {
        for (self.records.items) |record| record.release();
        self.records.deinit(self.allocator);
    }
    pub fn find(self: *const Ledger, url: []const u8, name: []const u8) ?*const Record {
        const slot = position(self.records.items, url, name);
        return if (slot.found) self.records.items[slot.index] else null;
    }
    pub fn prepare(self: *Ledger) std.mem.Allocator.Error!Prepared {
        var result = Prepared{ .owner = self };
        try result.records.ensureTotalCapacity(self.allocator, self.records.items.len);
        for (self.records.items) |record| result.records.appendAssumeCapacity(record.retain());
        return result;
    }
    pub fn prune(self: *Ledger, registry: anytype) void {
        var index: usize = 0;
        while (index < self.records.items.len) {
            const record = self.records.items[index];
            if (desired(registry, record.resource.type_url, record.resource.name)) {
                index += 1;
                continue;
            }
            _ = self.records.orderedRemove(index);
            record.release();
        }
    }
};

pub const Prepared = struct {
    owner: *Ledger,
    records: std.ArrayList(*Record) = .empty,
    pub fn deinit(self: *Prepared) void {
        for (self.records.items) |record| record.release();
        self.records.deinit(self.owner.allocator);
    }
    pub fn find(self: *const Prepared, url: []const u8, name: []const u8) ?*const Record {
        const slot = position(self.records.items, url, name);
        return if (slot.found) self.records.items[slot.index] else null;
    }
    pub fn put(self: *Prepared, resource: csds.Resource, source_key: []const u8) Error!void {
        const slot = position(self.records.items, resource.type_url, resource.name);
        if (!slot.found and self.records.items.len >= self.owner.options.max_resources) return error.XdsLimitExceeded;
        const record = try Record.create(self.owner.allocator, resource, source_key);
        errdefer record.release();
        if (slot.found) {
            const previous = self.records.items[slot.index];
            self.records.items[slot.index] = record;
            previous.release();
        } else try self.records.insert(self.owner.allocator, slot.index, record);
    }
    pub fn tag(self: *Prepared, url: []const u8, name: []const u8, token: anytype) void {
        const slot = position(self.records.items, url, name);
        std.debug.assert(slot.found and self.records.items[slot.index].refs == 1);
        self.records.items[slot.index].accepted_token = .{ .owner_id = token.owner_id, .epoch = token.epoch, .sequence = token.sequence };
    }
    /// Restore an uncommitted candidate after an application rejection.
    pub fn restore(self: *Prepared, url: []const u8, name: []const u8) void {
        const slot = position(self.records.items, url, name);
        if (!slot.found) return;
        const old_slot = position(self.owner.records.items, url, name);
        const candidate = self.records.items[slot.index];
        if (old_slot.found) {
            self.records.items[slot.index] = self.owner.records.items[old_slot.index].retain();
        } else _ = self.records.orderedRemove(slot.index);
        candidate.release();
    }
    pub fn checkBudget(self: *const Prepared) Error!void {
        const capacity = std.math.add(usize, self.records.capacity, self.owner.records.capacity) catch return error.XdsLimitExceeded;
        var total = std.math.mul(usize, capacity, @sizeOf(*Record)) catch return error.XdsLimitExceeded;
        for (self.owner.records.items) |record| total = std.math.add(usize, total, try record.storageBytes()) catch return error.XdsLimitExceeded;
        for (self.records.items) |record| {
            // Shared immutable records are retained once during preparation.
            const old = self.owner.find(record.resource.type_url, record.resource.name);
            if (old == record) continue;
            total = std.math.add(usize, total, try record.storageBytes()) catch return error.XdsLimitExceeded;
        }
        if (total > self.owner.options.max_storage_bytes) return error.XdsLimitExceeded;
    }
    pub fn prune(self: *Prepared, registry: anytype) void {
        var index: usize = 0;
        while (index < self.records.items.len) {
            const record = self.records.items[index];
            if (desired(registry, record.resource.type_url, record.resource.name)) {
                index += 1;
                continue;
            }
            _ = self.records.orderedRemove(index);
            record.release();
        }
    }
    pub fn commit(self: *Prepared) void {
        const previous = self.owner.records;
        self.owner.records = self.records;
        self.records = previous;
    }
};

pub fn desired(registry: anytype, url: []const u8, name: []const u8) bool {
    for (registry.desired.items) |watch| {
        if (!std.mem.eql(u8, watch.type_url, url)) continue;
        for (watch.values) |value| if (std.mem.eql(u8, value, name)) return true;
    }
    return false;
}
