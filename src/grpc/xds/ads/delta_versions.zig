//! Owned accepted-subset map, committed after a runtime cache transaction.
const std = @import("std");
const subscriptions = @import("delta_subscriptions.zig");
const codec = @import("delta_codec.zig");

fn contains(names: []const []const u8, name: []const u8) bool {
    for (names) |value| if (std.mem.eql(u8, value, name)) return true;
    return false;
}
fn acceptedResource(response: codec.Response, names: []const []const u8, name: []const u8) ?codec.Resource {
    if (!contains(names, name)) return null;
    for (response.resources) |resource| if (std.mem.eql(u8, resource.name, name)) return resource;
    return null;
}
fn resourceVersion(resource: codec.Resource, previous: []const u8) []const u8 {
    return if (resource.resource == null and resource.version.len == 0) previous else resource.version;
}
fn addBytes(total: usize, name: []const u8, version: []const u8) subscriptions.Error!usize {
    const size = std.math.add(usize, name.len, version.len) catch return error.DiscoveryLimitExceeded;
    return std.math.add(usize, total, size) catch return error.DiscoveryLimitExceeded;
}

pub const Prepared = struct {
    state: *subscriptions.State,
    allocator: std.mem.Allocator,
    type_url: []u8,
    token: subscriptions.Token,
    versions: []subscriptions.Version,
    storage: []u8,
    committed: bool = false,

    pub fn storageBytes(self: *const Prepared) subscriptions.Error!usize {
        const entries = std.math.mul(usize, self.versions.len, @sizeOf(subscriptions.Version)) catch return error.DiscoveryLimitExceeded;
        const owned = std.math.add(usize, self.type_url.len, self.storage.len) catch return error.DiscoveryLimitExceeded;
        return std.math.add(usize, owned, entries) catch return error.DiscoveryLimitExceeded;
    }
    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.type_url);
        if (!self.committed) {
            self.allocator.free(self.versions);
            self.allocator.free(self.storage);
        }
        self.* = undefined;
    }
    pub fn commit(self: *Prepared) void {
        std.debug.assert(!self.committed);
        self.state.validateToken(self.type_url, self.token) catch unreachable;
        const entry = self.state.find(self.type_url).?;
        self.allocator.free(entry.versions);
        self.allocator.free(entry.versions_storage);
        entry.versions = self.versions;
        entry.versions_storage = self.storage;
        entry.applied_sequence = self.token.sequence;
        self.committed = true;
    }
    /// Runtime publication succeeded. Stamp only payloads accepted by that
    /// transaction; heartbeats retain the acceptance time of their payload.
    pub fn commitAt(self: *Prepared, response: codec.Response, accepted: []const []const u8, now_ns: i128) void {
        std.debug.assert(!self.committed);
        for (self.versions) |*version| {
            const resource = acceptedResource(response, accepted, version.name) orelse continue;
            if (resource.resource != null) version.accepted_ns = now_ns;
        }
        self.commit();
    }
};

pub fn prepare(state: *subscriptions.State, type_url: []const u8, token: subscriptions.Token, response: codec.Response, accepted: []const []const u8, withdrawn: []const []const u8, desired: []const []const u8, now_ns: i128) subscriptions.Error!Prepared {
    try state.validateToken(type_url, token);
    if (!std.mem.eql(u8, type_url, response.type_url)) return error.InvalidDiscoveryMessage;
    for (response.resources, 0..) |resource, index| {
        if (resource.resource) |any| if (!std.mem.eql(u8, any.type_url, type_url)) return error.InvalidDiscoveryMessage;
        for (response.resources[0..index]) |previous| if (std.mem.eql(u8, previous.name, resource.name)) return error.InvalidDiscoveryMessage;
    }
    const entry = state.find(type_url).?;
    const allocator = state.allocator;
    const key = try allocator.dupe(u8, type_url);
    errdefer allocator.free(key);
    var count: usize = 0;
    var bytes: usize = 0;
    for (entry.versions) |previous| {
        if (!contains(desired, previous.name) or contains(withdrawn, previous.name)) continue;
        const resource = acceptedResource(response, accepted, previous.name);
        const version = if (resource) |value| resourceVersion(value, previous.version) else previous.version;
        bytes = try addBytes(bytes, previous.name, version);
        count += 1;
    }
    for (response.resources) |resource| {
        if (resource.resource == null or !contains(accepted, resource.name) or !contains(desired, resource.name) or contains(withdrawn, resource.name) or entry.hasVersion(resource.name)) continue;
        bytes = try addBytes(bytes, resource.name, resource.version);
        count += 1;
    }
    if (count > state.options.max_names_per_type) return error.DiscoveryLimitExceeded;
    const versions = try allocator.alloc(subscriptions.Version, count);
    errdefer allocator.free(versions);
    const storage = try allocator.alloc(u8, bytes);
    errdefer allocator.free(storage);
    var index: usize = 0;
    var offset: usize = 0;
    for (entry.versions) |previous| {
        if (!contains(desired, previous.name) or contains(withdrawn, previous.name)) continue;
        const resource = acceptedResource(response, accepted, previous.name);
        const version = if (resource) |value| resourceVersion(value, previous.version) else previous.version;
        const accepted_payload = if (resource) |value| value.resource != null else false;
        versions[index] = copy(storage, &offset, previous.name, version, if (accepted_payload) now_ns else previous.accepted_ns);
        index += 1;
    }
    for (response.resources) |resource| {
        if (resource.resource == null or !contains(accepted, resource.name) or !contains(desired, resource.name) or contains(withdrawn, resource.name) or entry.hasVersion(resource.name)) continue;
        versions[index] = copy(storage, &offset, resource.name, resource.version, now_ns);
        index += 1;
    }
    std.debug.assert(index == count and offset == bytes);
    std.mem.sort(subscriptions.Version, versions, {}, struct {
        fn less(_: void, a: subscriptions.Version, b: subscriptions.Version) bool {
            return std.mem.order(u8, a.name, b.name) == .lt;
        }
    }.less);
    return .{ .state = state, .allocator = allocator, .type_url = key, .token = token, .versions = versions, .storage = storage };
}

fn copy(storage: []u8, offset: *usize, name: []const u8, version: []const u8, now_ns: i128) subscriptions.Version {
    const owned_name = storage[offset.*..][0..name.len];
    offset.* += name.len;
    @memcpy(owned_name, name);
    const owned_version = storage[offset.*..][0..version.len];
    offset.* += version.len;
    @memcpy(owned_version, version);
    return .{ .name = owned_name, .version = owned_version, .accepted_ns = now_ns };
}
