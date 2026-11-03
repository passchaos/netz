//! Envoy v3 delta ADS envelopes. Each Resource carries its own version, so a
//! response is a diff instead of a complete snapshot.
const std = @import("std");
const protobuf = @import("../../protobuf.zig");
const details = @import("../../status_details.zig");
const wire = @import("../../wire.zig");
const sotw = @import("codec.zig");
pub const Error = protobuf.Error || details.Error || std.mem.Allocator.Error || error{ InvalidDiscoveryMessage, DiscoveryLimitExceeded, InvalidResourceTtl };
pub const Any = details.Any;
pub const Node = sotw.Node;
pub const Nack = sotw.Nack;
pub const Limits = sotw.Limits;

/// google.protobuf.Duration restricted to the non-negative range used by TTLs.
pub const Duration = struct {
    seconds: u64 = 0,
    nanos: u32 = 0,

    pub fn nanoseconds(self: Duration) Error!u64 {
        if (self.nanos >= std.time.ns_per_s) return error.InvalidResourceTtl;
        const seconds = std.math.mul(u64, self.seconds, std.time.ns_per_s) catch return error.InvalidResourceTtl;
        return std.math.add(u64, seconds, self.nanos) catch return error.InvalidResourceTtl;
    }
};

pub const Resource = struct {
    name: []const u8,
    version: []const u8 = "",
    /// Absent for a TTL/heartbeat refresh that does not repeat the payload.
    resource: ?Any = null,
    aliases: []const []const u8 = &.{},
    ttl: ?Duration = null,
};

pub const InitialVersion = struct { name: []const u8, version: []const u8 };

pub const Request = struct {
    node: ?[]const u8 = null,
    type_url: []const u8,
    subscribe: []const []const u8 = &.{},
    unsubscribe: []const []const u8 = &.{},
    /// Sorted by name; sent only in the first request of each type per stream.
    initial_versions: []const InitialVersion = &.{},
    nonce: []const u8 = "",
    nack: ?Nack = null,
};

pub const Response = struct {
    system_version: []const u8 = "",
    resources: []const Resource = &.{},
    type_url: []const u8,
    removed: []const []const u8 = &.{},
    nonce: []const u8 = "",
};

pub const OwnedResponse = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    resources: []Resource,
    removed: [][]const u8,
    value: Response,
    pub fn deinit(self: *OwnedResponse) void {
        for (self.resources) |resource| self.allocator.free(resource.aliases);
        self.allocator.free(self.resources);
        self.allocator.free(self.removed);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const OwnedRequest = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    subscribe: [][]const u8,
    unsubscribe: [][]const u8,
    initial_versions: []InitialVersion,
    value: Request,
    pub fn deinit(self: *OwnedRequest) void {
        self.allocator.free(self.initial_versions);
        self.allocator.free(self.unsubscribe);
        self.allocator.free(self.subscribe);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn integer(out: *std.ArrayList(u8), gpa: std.mem.Allocator, raw: u64) Error!void {
    var value = raw;
    while (value >= 128) : (value >>= 7) try out.append(gpa, @as(u8, @truncate(value)) | 0x80);
    try out.append(gpa, @intCast(value));
}

fn bytesField(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, bytes: []const u8) Error!void {
    try integer(out, gpa, @as(u64, field) * 8 + 2);
    try integer(out, gpa, bytes.len);
    try out.appendSlice(gpa, bytes);
}

fn textField(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, text: []const u8) Error!void {
    try sotw.validText(text);
    if (text.len != 0) try bytesField(out, gpa, field, text);
}

fn boundedName(name: []const u8, limits: Limits) Error!void {
    try sotw.validText(name);
    if (name.len == 0 or name.len > limits.max_name_bytes) return error.InvalidDiscoveryMessage;
}

fn boundedVersion(version: []const u8, limits: Limits) Error!void {
    try sotw.validText(version);
    if (version.len > limits.max_name_bytes) return error.InvalidDiscoveryMessage;
}

fn encodeAny(out: *std.ArrayList(u8), gpa: std.mem.Allocator, value: Any) Error!void {
    if (value.type_url.len == 0) return error.InvalidDiscoveryMessage;
    try sotw.typeUrl(value.type_url);
    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(gpa);
    try bytesField(&nested, gpa, 1, value.type_url);
    if (value.value.len != 0) try bytesField(&nested, gpa, 2, value.value);
    try bytesField(out, gpa, 2, nested.items);
}

fn encodeResource(out: *std.ArrayList(u8), gpa: std.mem.Allocator, resource: Resource, limits: Limits) Error!void {
    try boundedName(resource.name, limits);
    try boundedVersion(resource.version, limits);
    if (resource.aliases.len > limits.max_resources) return error.DiscoveryLimitExceeded;
    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(gpa);
    try textField(&nested, gpa, 1, resource.version);
    if (resource.resource) |value| try encodeAny(&nested, gpa, value);
    try bytesField(&nested, gpa, 3, resource.name);
    for (resource.aliases) |alias| {
        try boundedName(alias, limits);
        try bytesField(&nested, gpa, 4, alias);
    }
    if (resource.ttl) |ttl| {
        _ = try ttl.nanoseconds();
        var duration: std.ArrayList(u8) = .empty;
        defer duration.deinit(gpa);
        if (ttl.seconds != 0) {
            try integer(&duration, gpa, 8);
            try integer(&duration, gpa, ttl.seconds);
        }
        if (ttl.nanos != 0) {
            try integer(&duration, gpa, 16);
            try integer(&duration, gpa, ttl.nanos);
        }
        try bytesField(&nested, gpa, 6, duration.items);
    }
    try bytesField(out, gpa, 2, nested.items);
}

pub fn encodeRequest(gpa: std.mem.Allocator, request: Request, limits: Limits) Error![]u8 {
    try sotw.typeUrl(request.type_url);
    if (request.subscribe.len > limits.max_resources or request.unsubscribe.len > limits.max_resources or request.initial_versions.len > limits.max_resources) return error.DiscoveryLimitExceeded;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    if (request.node) |node| try bytesField(&out, gpa, 1, node);
    try textField(&out, gpa, 2, request.type_url);
    for (request.subscribe) |name| {
        try boundedName(name, limits);
        try bytesField(&out, gpa, 3, name);
    }
    for (request.unsubscribe) |name| {
        try boundedName(name, limits);
        try bytesField(&out, gpa, 4, name);
    }
    for (request.subscribe, 0..) |name, index| {
        if (index != 0) for (request.subscribe[0..index]) |previous| if (std.mem.eql(u8, previous, name)) return error.InvalidDiscoveryMessage;
        for (request.unsubscribe) |other| if (std.mem.eql(u8, other, name)) return error.InvalidDiscoveryMessage;
    }
    for (request.unsubscribe, 0..) |name, index| {
        if (index != 0) for (request.unsubscribe[0..index]) |previous| if (std.mem.eql(u8, previous, name)) return error.InvalidDiscoveryMessage;
    }
    var previous: ?[]const u8 = null;
    for (request.initial_versions) |entry| {
        try boundedName(entry.name, limits);
        try boundedVersion(entry.version, limits);
        if (previous) |name| if (!std.mem.eql(u8, name, entry.name) and std.mem.order(u8, name, entry.name) == .gt) return error.InvalidDiscoveryMessage;
        if (previous) |name| if (std.mem.eql(u8, name, entry.name)) return error.InvalidDiscoveryMessage;
        previous = entry.name;
        var nested: std.ArrayList(u8) = .empty;
        defer nested.deinit(gpa);
        try bytesField(&nested, gpa, 1, entry.name);
        if (entry.version.len != 0) try bytesField(&nested, gpa, 2, entry.version);
        try bytesField(&out, gpa, 5, nested.items);
    }
    try textField(&out, gpa, 6, request.nonce);
    if (request.nack) |nack| {
        if (nack.code == .ok) return error.InvalidDiscoveryMessage;
        const encoded = try details.encodeAlloc(gpa, nack.code, nack.message, &.{});
        defer gpa.free(encoded);
        try bytesField(&out, gpa, 7, encoded);
    }
    if (out.items.len > limits.max_message_bytes) return error.DiscoveryLimitExceeded;
    return out.toOwnedSlice(gpa);
}

pub fn encodeResponse(gpa: std.mem.Allocator, response: Response, limits: Limits) Error![]u8 {
    try sotw.typeUrl(response.type_url);
    if (response.resources.len > limits.max_resources or response.removed.len > limits.max_resources) return error.DiscoveryLimitExceeded;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try textField(&out, gpa, 1, response.system_version);
    for (response.resources) |resource| try encodeResource(&out, gpa, resource, limits);
    try textField(&out, gpa, 4, response.type_url);
    try textField(&out, gpa, 5, response.nonce);
    for (response.removed) |name| {
        try boundedName(name, limits);
        try bytesField(&out, gpa, 6, name);
    }
    if (out.items.len > limits.max_message_bytes) return error.DiscoveryLimitExceeded;
    return out.toOwnedSlice(gpa);
}

fn parseAny(bytes: []const u8, limits: Limits) Error!Any {
    var result: Any = .{};
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) result.type_url = try reader.string() else if (field.number == 2 and field.wire_type == 2) result.value = try reader.bytesValue() else try reader.skip(field);
    }
    if (result.type_url.len == 0) return error.InvalidDiscoveryMessage;
    try sotw.typeUrl(result.type_url);
    if (result.value.len > limits.max_resource_bytes) return error.DiscoveryLimitExceeded;
    return result;
}

fn parseDuration(bytes: []const u8) Error!Duration {
    var result: Duration = .{};
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) {
            const raw = try reader.varint();
            if (raw > std.math.maxInt(i64)) return error.InvalidResourceTtl;
            result.seconds = raw;
        } else if (field.number == 2 and field.wire_type == 0) {
            const raw = try reader.varint();
            if (raw > std.math.maxInt(i32) or raw >= std.time.ns_per_s) return error.InvalidResourceTtl;
            result.nanos = @intCast(raw);
        } else try reader.skip(field);
    }
    _ = try result.nanoseconds();
    return result;
}

fn parseResource(gpa: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Resource {
    var resource: Resource = .{ .name = "" };
    var aliases: std.ArrayList([]const u8) = .empty;
    errdefer aliases.deinit(gpa);
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) resource.version = try reader.string() else if (field.number == 2 and field.wire_type == 2) {
            if (resource.resource != null) return error.InvalidDiscoveryMessage;
            resource.resource = try parseAny(try reader.bytesValue(), limits);
        } else if (field.number == 3 and field.wire_type == 2) resource.name = try reader.string() else if (field.number == 4 and field.wire_type == 2) {
            if (aliases.items.len >= limits.max_resources) return error.DiscoveryLimitExceeded;
            try aliases.append(gpa, try reader.string());
        } else if (field.number == 6 and field.wire_type == 2) {
            if (resource.ttl != null) return error.InvalidDiscoveryMessage;
            resource.ttl = try parseDuration(try reader.bytesValue());
        } else if (field.number == 8 and field.wire_type == 2) {
            // Dynamic-parameter resource variants are outside the supported
            // subscription model; reject instead of applying the wrong name.
            return error.InvalidDiscoveryMessage;
        } else try reader.skip(field);
    }
    try boundedName(resource.name, limits);
    try boundedVersion(resource.version, limits);
    for (aliases.items) |alias| try boundedName(alias, limits);
    resource.aliases = try aliases.toOwnedSlice(gpa);
    return resource;
}

pub fn decodeResponse(gpa: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!OwnedResponse {
    if (bytes.len > limits.max_message_bytes) return error.DiscoveryLimitExceeded;
    const owned = try gpa.dupe(u8, bytes);
    errdefer gpa.free(owned);
    var resources: std.ArrayList(Resource) = .empty;
    errdefer {
        for (resources.items) |resource| gpa.free(resource.aliases);
        resources.deinit(gpa);
    }
    var removed: std.ArrayList([]const u8) = .empty;
    errdefer removed.deinit(gpa);
    var response: Response = .{ .type_url = "" };
    var reader: protobuf.Reader = .{ .bytes = owned };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) response.system_version = try reader.string() else if (field.number == 2 and field.wire_type == 2) {
            if (resources.items.len >= limits.max_resources) return error.DiscoveryLimitExceeded;
            try resources.append(gpa, try parseResource(gpa, try reader.bytesValue(), limits));
        } else if (field.number == 4 and field.wire_type == 2) response.type_url = try reader.string() else if (field.number == 5 and field.wire_type == 2) response.nonce = try reader.string() else if (field.number == 6 and field.wire_type == 2) {
            if (removed.items.len >= limits.max_resources) return error.DiscoveryLimitExceeded;
            try removed.append(gpa, try reader.string());
        } else if (field.number == 8 and field.wire_type == 2) {
            return error.InvalidDiscoveryMessage;
        } else if (field.number == 9 and field.wire_type == 2) {
            // Resource errors carry per-resource NOT_FOUND semantics that this
            // codec does not implement; do not silently drop them.
            return error.InvalidDiscoveryMessage;
        } else try reader.skip(field);
    }
    try sotw.typeUrl(response.type_url);
    for (removed.items) |name| try boundedName(name, limits);
    // Names are a set per response. Reject duplicates and names that are both
    // updated and removed rather than letting the application pick a winner.
    for (resources.items, 0..) |resource, index| {
        if (index != 0) for (resources.items[0..index]) |previous| if (std.mem.eql(u8, previous.name, resource.name)) return error.InvalidDiscoveryMessage;
        for (removed.items) |name| if (std.mem.eql(u8, name, resource.name)) return error.InvalidDiscoveryMessage;
    }
    for (removed.items, 0..) |name, index| {
        if (index != 0) for (removed.items[0..index]) |previous| if (std.mem.eql(u8, previous, name)) return error.InvalidDiscoveryMessage;
    }
    const resource_values = try resources.toOwnedSlice(gpa);
    errdefer gpa.free(resource_values);
    const removed_values = try removed.toOwnedSlice(gpa);
    response.resources = resource_values;
    response.removed = removed_values;
    return .{ .allocator = gpa, .bytes = owned, .resources = resource_values, .removed = removed_values, .value = response };
}

fn parseInitialVersion(bytes: []const u8, limits: Limits) Error!InitialVersion {
    var entry: InitialVersion = .{ .name = "", .version = "" };
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) entry.name = try reader.string() else if (field.number == 2 and field.wire_type == 2) entry.version = try reader.string() else try reader.skip(field);
    }
    try boundedName(entry.name, limits);
    try boundedVersion(entry.version, limits);
    return entry;
}

pub fn decodeRequest(gpa: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!OwnedRequest {
    if (bytes.len > limits.max_message_bytes) return error.DiscoveryLimitExceeded;
    const owned = try gpa.dupe(u8, bytes);
    errdefer gpa.free(owned);
    var subscribe: std.ArrayList([]const u8) = .empty;
    errdefer subscribe.deinit(gpa);
    var unsubscribe: std.ArrayList([]const u8) = .empty;
    errdefer unsubscribe.deinit(gpa);
    var initial: std.ArrayList(InitialVersion) = .empty;
    errdefer initial.deinit(gpa);
    var request: Request = .{ .type_url = "" };
    var reader: protobuf.Reader = .{ .bytes = owned };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) request.node = try reader.bytesValue() else if (field.number == 2 and field.wire_type == 2) request.type_url = try reader.string() else if (field.number == 3 and field.wire_type == 2) {
            if (subscribe.items.len >= limits.max_resources) return error.DiscoveryLimitExceeded;
            try subscribe.append(gpa, try reader.string());
        } else if (field.number == 4 and field.wire_type == 2) {
            if (unsubscribe.items.len >= limits.max_resources) return error.DiscoveryLimitExceeded;
            try unsubscribe.append(gpa, try reader.string());
        } else if (field.number == 5 and field.wire_type == 2) {
            if (initial.items.len >= limits.max_resources) return error.DiscoveryLimitExceeded;
            try initial.append(gpa, try parseInitialVersion(try reader.bytesValue(), limits));
        } else if (field.number == 6 and field.wire_type == 2) request.nonce = try reader.string() else if (field.number == 7 and field.wire_type == 2) {
            const status = try details.parse(try reader.bytesValue());
            const code = status.code orelse .ok;
            if (code == .ok) return error.InvalidDiscoveryMessage;
            request.nack = .{ .code = code, .message = status.message };
        } else try reader.skip(field);
    }
    try sotw.typeUrl(request.type_url);
    for (subscribe.items, 0..) |name, index| {
        try boundedName(name, limits);
        if (index != 0) for (subscribe.items[0..index]) |previous| if (std.mem.eql(u8, previous, name)) return error.InvalidDiscoveryMessage;
        for (unsubscribe.items) |other| if (std.mem.eql(u8, other, name)) return error.InvalidDiscoveryMessage;
    }
    for (unsubscribe.items, 0..) |name, index| {
        try boundedName(name, limits);
        if (index != 0) for (unsubscribe.items[0..index]) |previous| if (std.mem.eql(u8, previous, name)) return error.InvalidDiscoveryMessage;
    }
    for (initial.items, 0..) |entry, index| {
        if (index != 0 and std.mem.order(u8, initial.items[index - 1].name, entry.name) != .lt) return error.InvalidDiscoveryMessage;
    }
    const subscribe_values = try subscribe.toOwnedSlice(gpa);
    errdefer gpa.free(subscribe_values);
    const unsubscribe_values = try unsubscribe.toOwnedSlice(gpa);
    errdefer gpa.free(unsubscribe_values);
    const initial_values = try initial.toOwnedSlice(gpa);
    request.subscribe = subscribe_values;
    request.unsubscribe = unsubscribe_values;
    request.initial_versions = initial_values;
    return .{ .allocator = gpa, .bytes = owned, .subscribe = subscribe_values, .unsubscribe = unsubscribe_values, .initial_versions = initial_values, .value = request };
}
