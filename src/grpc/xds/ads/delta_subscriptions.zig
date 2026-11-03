//! Owned delta subscriptions, per-resource accepted versions and per-stream
//! ACK/NACK state. A reconnect resubscribes the full desired set and sends the
//! accepted versions as `initial_resource_versions`.
const std = @import("std");
const codec = @import("delta_codec.zig");
const sotw = @import("codec.zig");
pub const Error = codec.Error || error{ DiscoveryTypeLimit, UnknownDiscoveryType, StaleDiscoveryResponse };
pub const Options = struct { max_types: usize = 16, max_names_per_type: usize = 4096, max_name_bytes: usize = 4096 };
pub const Token = struct { owner_id: u64, epoch: u64, sequence: u64 };
pub const Subscription = struct { type_url: []const u8, names: []const []const u8 };
var next_owner_id: std.atomic.Value(u64) = .init(1);

pub const Version = struct { name: []u8, version: []u8 };

pub const Entry = struct {
    type_url: []u8,
    /// Desired resource names, sorted and unique.
    names: [][]const u8,
    names_storage: []u8,
    /// Accepted per-resource versions, sorted by name and limited to the
    /// desired set. Unsolicited server resources are applied but not retained.
    versions: []Version,
    versions_storage: []u8,
    /// Pending diff for the next request. Names are individually owned so a
    /// reconnect can rebuild them independently of the desired storage.
    subscribe: std.ArrayList([]const u8) = .empty,
    unsubscribe: std.ArrayList([]const u8) = .empty,
    nonce: []u8,
    error_detail: ?codec.Nack = null,
    dirty: bool = true,
    stream_started: bool = false,
    pending_sequence: ?u64 = null,

    fn deinit(self: *Entry, gpa: std.mem.Allocator) void {
        gpa.free(self.type_url);
        gpa.free(self.names);
        gpa.free(self.names_storage);
        // Version names and values are sub-slices of versions_storage.
        gpa.free(self.versions);
        gpa.free(self.versions_storage);
        clearPending(&self.subscribe, gpa);
        clearPending(&self.unsubscribe, gpa);
        self.subscribe.deinit(gpa);
        self.unsubscribe.deinit(gpa);
        gpa.free(self.nonce);
        if (self.error_detail) |value| gpa.free(value.message);
    }

    pub fn hasVersion(self: *const Entry, name: []const u8) bool {
        return findVersion(self.versions, name) != null;
    }
};

fn clearPending(list: *std.ArrayList([]const u8), gpa: std.mem.Allocator) void {
    for (list.items) |name| gpa.free(name);
    list.clearRetainingCapacity();
}

fn findVersion(versions: []const Version, name: []const u8) ?*const Version {
    for (versions) |*version| if (std.mem.eql(u8, version.name, name)) return version;
    return null;
}

fn findName(names: anytype, name: []const u8) bool {
    for (names) |value| if (std.mem.eql(u8, value, name)) return true;
    return false;
}

fn appendPending(list: *std.ArrayList([]const u8), gpa: std.mem.Allocator, name: []const u8) Error!void {
    for (list.items) |value| if (std.mem.eql(u8, value, name)) return;
    const copy = try gpa.dupe(u8, name);
    errdefer gpa.free(copy);
    try list.append(gpa, copy);
}

fn removePending(list: *std.ArrayList([]const u8), gpa: std.mem.Allocator, name: []const u8) void {
    for (list.items, 0..) |value, index| {
        if (!std.mem.eql(u8, value, name)) continue;
        gpa.free(value);
        _ = list.orderedRemove(index);
        return;
    }
}

pub const State = struct {
    allocator: std.mem.Allocator,
    options: Options,
    entries: std.ArrayList(Entry) = .empty,
    owner_id: u64 = 0,
    epoch: u64 = 0,
    sequence: u64 = 0,

    pub fn deinit(self: *State) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn find(self: *State, type_url: []const u8) ?*Entry {
        for (self.entries.items) |*entry| if (std.mem.eql(u8, type_url, entry.type_url)) return entry;
        return null;
    }

    /// Stage a complete desired set. Pending subscribe/unsubscribe lists are
    /// derived from the previous desired set and survive until a request is
    /// successfully written.
    pub fn prepare(self: *State, type_url: []const u8, names: []const []const u8) Error!Prepared {
        try sotw.typeUrl(type_url);
        if (type_url.len > self.options.max_name_bytes or names.len > self.options.max_names_per_type) return error.DiscoveryLimitExceeded;
        const existing = self.find(type_url);
        if (existing == null and self.entries.items.len >= self.options.max_types) return error.DiscoveryTypeLimit;
        var total: usize = 0;
        for (names) |name| {
            try sotw.validText(name);
            if (name.len == 0 or name.len > self.options.max_name_bytes) return error.InvalidDiscoveryMessage;
            total = std.math.add(usize, total, name.len) catch return error.DiscoveryLimitExceeded;
        }
        const storage = try self.allocator.alloc(u8, total);
        const owned_names = self.allocator.alloc([]const u8, names.len) catch |err| {
            self.allocator.free(storage);
            return err;
        };
        var transferred = false;
        errdefer if (!transferred) {
            self.allocator.free(owned_names);
            self.allocator.free(storage);
        };
        var offset: usize = 0;
        for (names, owned_names) |name, *owned| {
            owned.* = storage[offset..][0..name.len];
            @memcpy(@constCast(owned.*), name);
            offset += name.len;
        }
        std.mem.sort([]const u8, owned_names, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.less);
        if (owned_names.len > 1) for (owned_names[1..], 0..) |name, index| if (std.mem.eql(u8, name, owned_names[index])) return error.InvalidDiscoveryMessage;
        const key = try self.allocator.dupe(u8, type_url);

        var staged: Entry = .{
            .type_url = key,
            .names = owned_names,
            .names_storage = storage,
            .versions = &.{},
            .versions_storage = &.{},
            .nonce = &.{},
        };
        var staged_owned = true;
        errdefer {
            if (staged_owned) staged.deinit(self.allocator);
        }
        // From here staged owns the key, names and storage.
        transferred = true;

        if (existing) |old| {
            for (old.subscribe.items) |name| try appendPending(&staged.subscribe, self.allocator, name);
            for (old.unsubscribe.items) |name| try appendPending(&staged.unsubscribe, self.allocator, name);
            for (old.names) |name| {
                if (!findName(owned_names, name)) {
                    removePending(&staged.subscribe, self.allocator, name);
                    try appendPending(&staged.unsubscribe, self.allocator, name);
                }
            }
            for (owned_names) |name| {
                removePending(&staged.unsubscribe, self.allocator, name);
                if (!findName(old.names, name)) try appendPending(&staged.subscribe, self.allocator, name);
            }
            // Keep accepted versions for resources that remain desired.
            var count: usize = 0;
            var version_bytes: usize = 0;
            for (old.versions) |version| {
                if (!findName(owned_names, version.name)) continue;
                count += 1;
                version_bytes = std.math.add(usize, version_bytes, version.name.len + version.version.len) catch return error.DiscoveryLimitExceeded;
            }
            const versions = try self.allocator.alloc(Version, count);
            const version_storage = self.allocator.alloc(u8, version_bytes) catch |err| {
                self.allocator.free(versions);
                return err;
            };
            var index: usize = 0;
            var used: usize = 0;
            for (old.versions) |version| {
                if (!findName(owned_names, version.name)) continue;
                const name_copy = version_storage[used..][0..version.name.len];
                used += version.name.len;
                @memcpy(name_copy, version.name);
                const value_copy = version_storage[used..][0..version.version.len];
                used += version.version.len;
                @memcpy(value_copy, version.version);
                versions[index] = .{ .name = name_copy, .version = value_copy };
                index += 1;
            }
            staged.versions = versions;
            staged.versions_storage = version_storage;
            staged.nonce = try self.allocator.dupe(u8, old.nonce);
            if (old.error_detail) |value| {
                staged.error_detail = .{ .code = value.code, .message = try self.allocator.dupe(u8, value.message) };
            }
            staged.dirty = old.dirty or staged.subscribe.items.len != 0 or staged.unsubscribe.items.len != 0;
            staged.stream_started = old.stream_started;
            staged.pending_sequence = old.pending_sequence;
        } else {
            for (owned_names) |name| try appendPending(&staged.subscribe, self.allocator, name);
        }
        if (existing == null) try self.entries.ensureUnusedCapacity(self.allocator, 1);
        staged_owned = false;
        return .{ .state = self, .value = staged };
    }

    pub fn set(self: *State, type_url: []const u8, names: []const []const u8) Error!void {
        var prepared = try self.prepare(type_url, names);
        defer prepared.deinit();
        prepared.commit();
    }

    pub fn prepareMany(self: *State, requested: []const Subscription) Error!Batch {
        if (requested.len > self.options.max_types) return error.DiscoveryTypeLimit;
        var missing: usize = 0;
        for (requested, 0..) |item, index| {
            for (requested[0..index]) |previous| if (std.mem.eql(u8, previous.type_url, item.type_url)) return error.InvalidDiscoveryMessage;
            if (self.find(item.type_url) == null) missing += 1;
        }
        if (missing > self.options.max_types -| self.entries.items.len) return error.DiscoveryTypeLimit;
        try self.entries.ensureUnusedCapacity(self.allocator, missing);
        const items = try self.allocator.alloc(Prepared, requested.len);
        var count: usize = 0;
        errdefer {
            for (items[0..count]) |*item| item.deinit();
            self.allocator.free(items);
        }
        for (requested, items) |item, *prepared| {
            prepared.* = try self.prepare(item.type_url, item.names);
            count += 1;
        }
        return .{ .allocator = self.allocator, .items = items };
    }

    /// Nonces and undecided responses belong to one stream. Accepted versions
    /// survive reconnect. The new stream resubscribes every desired name so a
    /// lost stream cannot silently drop a subscription that had no accepted
    /// version yet.
    pub fn resetStream(self: *State) void {
        self.epoch +%= 1;
        for (self.entries.items) |*entry| {
            self.allocator.free(entry.nonce);
            entry.nonce = &.{};
            entry.pending_sequence = null;
            if (entry.error_detail) |value| self.allocator.free(value.message);
            entry.error_detail = null;
            clearPending(&entry.subscribe, self.allocator);
            clearPending(&entry.unsubscribe, self.allocator);
            entry.stream_started = false;
            entry.dirty = true;
        }
    }

    pub fn received(self: *State, response: codec.Response) Error!Token {
        const entry = self.find(response.type_url) orelse return error.UnknownDiscoveryType;
        const nonce = try self.allocator.dupe(u8, response.nonce);
        errdefer self.allocator.free(nonce);
        self.allocator.free(entry.nonce);
        if (entry.error_detail) |value| self.allocator.free(value.message);
        entry.nonce = nonce;
        entry.error_detail = null;
        if (self.owner_id == 0) self.owner_id = next_owner_id.fetchAdd(1, .monotonic);
        self.sequence +%= 1;
        entry.pending_sequence = self.sequence;
        return .{ .owner_id = self.owner_id, .epoch = self.epoch, .sequence = self.sequence };
    }

    pub fn validateToken(self: *State, type_url: []const u8, token: Token) Error!void {
        const entry = self.find(type_url) orelse return error.UnknownDiscoveryType;
        if (token.owner_id != self.owner_id or token.epoch != self.epoch or entry.pending_sequence != token.sequence) return error.StaleDiscoveryResponse;
    }

    /// Acceptance applies the response's per-resource versions atomically. A
    /// NACK keeps every accepted version and records the error for the next
    /// request, which carries the same nonce.
    pub fn decide(self: *State, type_url: []const u8, token: Token, nack: ?codec.Nack, response: codec.Response) Error!*Entry {
        const entry = self.find(type_url) orelse return error.UnknownDiscoveryType;
        if (token.owner_id != self.owner_id or token.epoch != self.epoch or entry.pending_sequence != token.sequence) return error.StaleDiscoveryResponse;
        if (nack) |value| {
            if (value.code == .ok) return error.InvalidDiscoveryMessage;
            try sotw.validText(value.message);
            if (value.message.len > self.options.max_name_bytes) return error.DiscoveryLimitExceeded;
            const message = try self.allocator.dupe(u8, value.message);
            if (entry.error_detail) |previous| self.allocator.free(previous.message);
            entry.error_detail = .{ .code = value.code, .message = message };
            entry.pending_sequence = null;
            entry.dirty = true;
            return entry;
        }
        if (!std.mem.eql(u8, response.type_url, type_url)) return error.InvalidDiscoveryMessage;
        for (response.resources) |resource| if (resource.resource) |any| if (!std.mem.eql(u8, any.type_url, type_url)) return error.InvalidDiscoveryMessage;
        // Upserts and removals are computed against the current accepted map.
        // Only names still desired are retained; an unsolicited update is
        // applied by the caller but does not become reconnect state.
        var capacity: usize = 0;
        var bytes: usize = 0;
        for (entry.versions) |version| {
            if (findName(response.removed, version.name)) continue;
            capacity += 1;
            const updated = for (response.resources) |resource| {
                if (std.mem.eql(u8, resource.name, version.name)) break resource.version;
            } else version.version;
            bytes = std.math.add(usize, bytes, version.name.len + updated.len) catch return error.DiscoveryLimitExceeded;
        }
        for (response.resources) |resource| {
            if (!findName(entry.names, resource.name)) continue;
            if (findVersion(entry.versions, resource.name) != null) continue;
            capacity += 1;
            bytes = std.math.add(usize, bytes, resource.name.len + resource.version.len) catch return error.DiscoveryLimitExceeded;
        }
        if (capacity > self.options.max_names_per_type) return error.DiscoveryLimitExceeded;
        const versions = try self.allocator.alloc(Version, capacity);
        errdefer self.allocator.free(versions);
        const storage = try self.allocator.alloc(u8, bytes);
        errdefer self.allocator.free(storage);
        var index: usize = 0;
        var used: usize = 0;
        for (entry.versions) |version| {
            if (findName(response.removed, version.name)) continue;
            const updated = for (response.resources) |resource| {
                if (std.mem.eql(u8, resource.name, version.name)) break resource.version;
            } else version.version;
            const name_copy = storage[used..][0..version.name.len];
            used += version.name.len;
            @memcpy(name_copy, version.name);
            const value_copy = storage[used..][0..updated.len];
            used += updated.len;
            @memcpy(value_copy, updated);
            versions[index] = .{ .name = name_copy, .version = value_copy };
            index += 1;
        }
        for (response.resources) |resource| {
            if (!findName(entry.names, resource.name)) continue;
            if (findVersion(entry.versions, resource.name) != null) continue;
            const name_copy = storage[used..][0..resource.name.len];
            used += resource.name.len;
            @memcpy(name_copy, resource.name);
            const value_copy = storage[used..][0..resource.version.len];
            used += resource.version.len;
            @memcpy(value_copy, resource.version);
            versions[index] = .{ .name = name_copy, .version = value_copy };
            index += 1;
        }
        std.debug.assert(index == capacity and used == bytes);
        std.mem.sort(Version, versions, {}, struct {
            fn less(_: void, a: Version, b: Version) bool {
                return std.mem.order(u8, a.name, b.name) == .lt;
            }
        }.less);
        self.allocator.free(entry.versions);
        self.allocator.free(entry.versions_storage);
        entry.versions = versions;
        entry.versions_storage = storage;
        if (entry.error_detail) |value| self.allocator.free(value.message);
        entry.error_detail = null;
        entry.pending_sequence = null;
        entry.dirty = true;
        return entry;
    }
};

pub const Prepared = struct {
    state: *State,
    value: ?Entry,
    pub fn deinit(self: *Prepared) void {
        if (self.value) |*entry| entry.deinit(self.state.allocator);
        self.value = null;
    }
    pub fn commit(self: *Prepared) void {
        const staged = &self.value.?;
        if (self.state.find(staged.type_url)) |entry| {
            entry.deinit(self.state.allocator);
            entry.* = staged.*;
            self.value = null;
        } else {
            self.state.entries.appendAssumeCapacity(staged.*);
            self.value = null;
        }
    }
};

pub const Batch = struct {
    allocator: std.mem.Allocator,
    items: []Prepared,
    pub fn deinit(self: *Batch) void {
        for (self.items) |*item| item.deinit();
        self.allocator.free(self.items);
        self.* = undefined;
    }
    pub fn commit(self: *Batch) void {
        for (self.items) |*item| item.commit();
    }
};
