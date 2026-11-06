//! Owned desired subscriptions, accepted versions and per-stream ACK/NACK state.
const std = @import("std");
const codec = @import("codec.zig");
pub const Error = codec.Error || error{ DiscoveryTypeLimit, UnknownDiscoveryType, StaleDiscoveryResponse };
pub const Options = struct { max_types: usize = 16, max_names_per_type: usize = 4096, max_name_bytes: usize = 4096 };
pub const Subscription = @import("prepared_batch.zig").Subscription;
pub const Batch = @import("prepared_batch.zig").Batch;
var next_owner_id: std.atomic.Value(u64) = .init(1);
pub const Token = struct { owner_id: u64, epoch: u64, sequence: u64 };
pub const Entry = struct {
    type_url: []u8,
    names: [][]const u8,
    names_storage: []u8,
    version: []u8,
    /// Wall-clock nanoseconds since the epoch when the accepted version was
    /// committed. Shared by every resource of this type in a SotW response.
    accepted_ns: i128 = 0,
    nonce: []u8,
    candidate: ?[]u8 = null,
    pending_sequence: ?u64 = null,
    nack: ?codec.Nack = null,
    dirty: bool = true,
    fn deinit(self: *Entry, gpa: std.mem.Allocator) void {
        gpa.free(self.type_url);
        gpa.free(self.names);
        gpa.free(self.names_storage);
        gpa.free(self.version);
        gpa.free(self.nonce);
        if (self.candidate) |v| gpa.free(v);
        if (self.nack) |v| gpa.free(v.message);
    }
};
pub const State = struct {
    allocator: std.mem.Allocator,
    options: Options,
    entries: std.ArrayList(Entry) = .empty,
    /// Capacity reserved by prepared entries that have not committed yet.
    pending_new: usize = 0,
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
    /// Prepare all storage before an application publication. One serialized
    /// caller must commit or discard it before preparing another subscription.
    pub fn prepare(self: *State, type_url: []const u8, names: []const []const u8) Error!Prepared {
        try codec.typeUrl(type_url);
        if (type_url.len > self.options.max_name_bytes or names.len > self.options.max_names_per_type) return error.DiscoveryLimitExceeded;
        const existing = self.find(type_url);
        if (existing == null and self.entries.items.len + self.pending_new >= self.options.max_types) return error.DiscoveryTypeLimit;
        var total: usize = 0;
        for (names) |name| {
            try codec.validText(name);
            if (name.len == 0 or name.len > self.options.max_name_bytes) return error.InvalidDiscoveryMessage;
            total = std.math.add(usize, total, name.len) catch return error.DiscoveryLimitExceeded;
        }
        const storage = try self.allocator.alloc(u8, total);
        errdefer self.allocator.free(storage);
        const owned_names = try self.allocator.alloc([]const u8, names.len);
        errdefer self.allocator.free(owned_names);
        var offset: usize = 0;
        for (names, owned_names) |name, *owned| {
            owned.* = storage[offset..][0..name.len];
            @memcpy(storage[offset..][0..name.len], name);
            offset += name.len;
        }
        // Names form a set. Sort and reject duplicates to make coalescing and replay stable.
        std.mem.sort([]const u8, owned_names, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.less);
        if (owned_names.len > 1) for (owned_names[1..], 0..) |name, index| if (std.mem.eql(u8, name, owned_names[index])) return error.InvalidDiscoveryMessage;
        const key = try self.allocator.dupe(u8, type_url);
        errdefer self.allocator.free(key);
        if (existing == null) {
            try self.entries.ensureUnusedCapacity(self.allocator, self.pending_new + 1);
            self.pending_new += 1;
        }
        return .{ .state = self, .value = .{ .type_url = key, .names = owned_names, .names_storage = storage, .version = &.{}, .nonce = &.{} }, .new_entry = existing == null };
    }
    pub fn set(self: *State, type_url: []const u8, names: []const []const u8) Error!void {
        var prepared = try self.prepare(type_url, names);
        defer prepared.deinit();
        prepared.commit();
    }
    pub fn prepareMany(self: *State, requested: []const Subscription) Error!Batch {
        return @import("prepared_batch.zig").prepare(self, requested);
    }
    /// Nonces and undecided responses belong to one stream; accepted versions
    /// and desired subscriptions survive reconnect and are replayed.
    pub fn resetStream(self: *State) void {
        self.epoch +%= 1;
        for (self.entries.items) |*entry| {
            self.allocator.free(entry.nonce);
            entry.nonce = &.{};
            if (entry.candidate) |value| self.allocator.free(value);
            entry.candidate = null;
            entry.pending_sequence = null;
            if (entry.nack) |value| self.allocator.free(value.message);
            entry.nack = null;
            entry.dirty = true;
        }
    }
    pub fn received(self: *State, response: codec.Response) Error!Token {
        const entry = self.find(response.type_url) orelse return error.UnknownDiscoveryType;
        const nonce = try self.allocator.dupe(u8, response.nonce);
        errdefer self.allocator.free(nonce);
        const candidate = try self.allocator.dupe(u8, response.version);
        self.allocator.free(entry.nonce);
        if (entry.candidate) |value| self.allocator.free(value);
        if (entry.nack) |value| self.allocator.free(value.message);
        entry.nonce = nonce;
        entry.candidate = candidate;
        entry.nack = null;
        if (self.owner_id == 0) self.owner_id = next_owner_id.fetchAdd(1, .monotonic);
        self.sequence +%= 1;
        entry.pending_sequence = self.sequence;
        return .{ .owner_id = self.owner_id, .epoch = self.epoch, .sequence = self.sequence };
    }
    pub fn validateToken(self: *State, type_url: []const u8, token: Token) Error!void {
        const entry = self.find(type_url) orelse return error.UnknownDiscoveryType;
        if (token.owner_id != self.owner_id or token.epoch != self.epoch or entry.pending_sequence != token.sequence) return error.StaleDiscoveryResponse;
    }
    /// The application's acceptance is authoritative even if the ACK write
    /// later fails: a reconnect must advertise the version actually applied.
    pub fn decide(self: *State, type_url: []const u8, token: Token, nack: ?codec.Nack) Error!*Entry {
        const entry = self.find(type_url) orelse return error.UnknownDiscoveryType;
        if (token.owner_id != self.owner_id or token.epoch != self.epoch or entry.pending_sequence != token.sequence) return error.StaleDiscoveryResponse;
        if (nack) |value| {
            if (value.code == .ok) return error.InvalidDiscoveryMessage;
            try codec.validText(value.message);
            const message = try self.allocator.dupe(u8, value.message);
            if (entry.nack) |previous| self.allocator.free(previous.message);
            entry.nack = .{ .code = value.code, .message = message };
        } else {
            if (entry.nack) |previous| self.allocator.free(previous.message);
            entry.nack = null;
            self.allocator.free(entry.version);
            entry.version = entry.candidate.?;
            entry.candidate = null;
        }
        entry.pending_sequence = null;
        if (entry.candidate) |value| self.allocator.free(value);
        entry.candidate = null;
        entry.dirty = true;
        return entry;
    }
};

/// Owned subscription transaction. Preparing may grow the entry array, so
/// commit re-finds the entry instead of retaining an invalidatable pointer.
pub const Prepared = struct {
    state: *State,
    value: ?Entry,
    new_entry: bool = false,
    pub fn deinit(self: *Prepared) void {
        const owned = self.value != null;
        if (self.value) |*entry| entry.deinit(self.state.allocator);
        self.value = null;
        if (owned and self.new_entry) self.state.pending_new -= 1;
        self.new_entry = false;
    }
    pub fn commit(self: *Prepared) void {
        const staged = &self.value.?;
        if (self.state.find(staged.type_url)) |entry| {
            var same = entry.names.len == staged.names.len;
            if (same) for (entry.names, staged.names) |a, b| {
                if (!std.mem.eql(u8, a, b)) same = false;
            };
            self.state.allocator.free(entry.names);
            self.state.allocator.free(entry.names_storage);
            entry.names = staged.names;
            entry.names_storage = staged.names_storage;
            entry.dirty = entry.dirty or !same;
            staged.names = &.{};
            staged.names_storage = &.{};
            self.deinit();
        } else {
            self.state.entries.appendAssumeCapacity(staged.*);
            self.value = null;
        }
        if (self.new_entry) self.state.pending_new -= 1;
        self.new_entry = false;
    }
};
