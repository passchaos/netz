//! Envoy v3 state-of-the-world ADS envelopes. Resource schemas stay opaque.
const std = @import("std");
const protobuf = @import("../../protobuf.zig");
const details = @import("../../status_details.zig");
const wire = @import("../../wire.zig");
pub const Error = protobuf.Error || details.Error || std.mem.Allocator.Error || error{ InvalidDiscoveryMessage, DiscoveryLimitExceeded };
pub const Any = details.Any;
pub const Node = struct {
    id: []const u8,
    cluster: []const u8 = "",
    /// Serialized google.protobuf.Struct, e.g. from the application pbz codec.
    metadata: ?[]const u8 = null,
    locality: ?struct { region: []const u8 = "", zone: []const u8 = "", sub_zone: []const u8 = "" } = null,
    user_agent_name: []const u8 = "netz",
    user_agent_version: []const u8 = "0.1.0",
    client_features: []const []const u8 = &.{},
};
pub const Nack = struct { code: wire.Status = .invalid_argument, message: []const u8 };
pub const Request = struct {
    version: []const u8 = "",
    node: ?[]const u8 = null,
    names: []const []const u8 = &.{},
    type_url: []const u8,
    nonce: []const u8 = "",
    nack: ?Nack = null,
};
pub const Response = struct {
    version: []const u8 = "",
    resources: []const Any = &.{},
    type_url: []const u8,
    nonce: []const u8 = "",
    canary: bool = false,
};
pub const Limits = struct {
    max_message_bytes: usize = 16 * 1024 * 1024,
    max_resources: usize = 4096,
    max_resource_bytes: usize = 8 * 1024 * 1024,
};
pub const OwnedResponse = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    resources: []Any,
    value: Response,
    pub fn deinit(self: *OwnedResponse) void {
        self.allocator.free(self.resources);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};
pub fn validText(bytes: []const u8) Error!void {
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidUtf8;
}
pub fn typeUrl(bytes: []const u8) Error!void {
    try validText(bytes);
    if (bytes.len == 0) return error.InvalidDiscoveryMessage;
}
fn bytesField(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, bytes: []const u8) Error!void {
    try integer(out, gpa, @as(u64, field) * 8 + 2);
    try integer(out, gpa, bytes.len);
    try out.appendSlice(gpa, bytes);
}
fn integer(out: *std.ArrayList(u8), gpa: std.mem.Allocator, raw: u64) Error!void {
    var value = raw;
    while (value >= 128) : (value >>= 7) try out.append(gpa, @as(u8, @truncate(value)) | 0x80);
    try out.append(gpa, @intCast(value));
}
fn textField(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, text: []const u8) Error!void {
    try validText(text);
    if (text.len != 0) try bytesField(out, gpa, field, text);
}
pub fn encodeNode(gpa: std.mem.Allocator, node: Node) Error![]u8 {
    if (node.id.len == 0) return error.InvalidDiscoveryMessage;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try textField(&out, gpa, 1, node.id);
    try textField(&out, gpa, 2, node.cluster);
    if (node.metadata) |metadata| {
        var reader: protobuf.Reader = .{ .bytes = metadata };
        while (try reader.next()) |field| try reader.skip(field);
        try bytesField(&out, gpa, 3, metadata);
    }
    if (node.locality) |locality| {
        var nested: std.ArrayList(u8) = .empty;
        defer nested.deinit(gpa);
        try textField(&nested, gpa, 1, locality.region);
        try textField(&nested, gpa, 2, locality.zone);
        try textField(&nested, gpa, 3, locality.sub_zone);
        try bytesField(&out, gpa, 4, nested.items);
    }
    try textField(&out, gpa, 6, node.user_agent_name);
    try textField(&out, gpa, 7, node.user_agent_version);
    for (node.client_features) |feature| {
        try validText(feature);
        try bytesField(&out, gpa, 10, feature);
    }
    return out.toOwnedSlice(gpa);
}
pub fn encodeRequest(gpa: std.mem.Allocator, request: Request, limit: usize) Error![]u8 {
    try typeUrl(request.type_url);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try textField(&out, gpa, 1, request.version);
    if (request.node) |node| try bytesField(&out, gpa, 2, node);
    for (request.names) |name| {
        try validText(name);
        try bytesField(&out, gpa, 3, name);
    }
    try textField(&out, gpa, 4, request.type_url);
    try textField(&out, gpa, 5, request.nonce);
    if (request.nack) |nack| {
        if (nack.code == .ok) return error.InvalidDiscoveryMessage;
        const encoded = try details.encodeAlloc(gpa, nack.code, nack.message, &.{});
        defer gpa.free(encoded);
        try bytesField(&out, gpa, 6, encoded);
    }
    if (out.items.len > limit) return error.DiscoveryLimitExceeded;
    return out.toOwnedSlice(gpa);
}
pub fn encodeResponse(gpa: std.mem.Allocator, response: Response, limit: usize) Error![]u8 {
    try typeUrl(response.type_url);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try textField(&out, gpa, 1, response.version);
    for (response.resources) |resource| {
        try typeUrl(resource.type_url);
        var nested: std.ArrayList(u8) = .empty;
        defer nested.deinit(gpa);
        try textField(&nested, gpa, 1, resource.type_url);
        if (resource.value.len != 0) try bytesField(&nested, gpa, 2, resource.value);
        try bytesField(&out, gpa, 2, nested.items);
    }
    if (response.canary) {
        try integer(&out, gpa, 24);
        try integer(&out, gpa, 1);
    }
    try textField(&out, gpa, 4, response.type_url);
    try textField(&out, gpa, 5, response.nonce);
    if (out.items.len > limit) return error.DiscoveryLimitExceeded;
    return out.toOwnedSlice(gpa);
}
fn any(bytes: []const u8, limits: Limits) Error!Any {
    var result: Any = .{};
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) result.type_url = try reader.string() else if (field.number == 2 and field.wire_type == 2) result.value = try reader.bytesValue() else try reader.skip(field);
    }
    // Type agreement is semantic validation for the caller's ACK/NACK decision.
    if (result.value.len > limits.max_resource_bytes) return error.DiscoveryLimitExceeded;
    return result;
}
pub fn decodeResponse(gpa: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!OwnedResponse {
    if (bytes.len > limits.max_message_bytes) return error.DiscoveryLimitExceeded;
    const owned = try gpa.dupe(u8, bytes);
    errdefer gpa.free(owned);
    var resources: std.ArrayList(Any) = .empty;
    errdefer resources.deinit(gpa);
    var response: Response = .{ .type_url = "" };
    var reader: protobuf.Reader = .{ .bytes = owned };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) response.version = try reader.string() else if (field.number == 2 and field.wire_type == 2) {
            if (resources.items.len >= limits.max_resources) return error.DiscoveryLimitExceeded;
            try resources.append(gpa, try any(try reader.bytesValue(), limits));
        } else if (field.number == 3 and field.wire_type == 0) response.canary = try reader.varint() != 0 else if (field.number == 4 and field.wire_type == 2) response.type_url = try reader.string() else if (field.number == 5 and field.wire_type == 2) response.nonce = try reader.string() else try reader.skip(field);
    }
    try typeUrl(response.type_url);
    const values = try resources.toOwnedSlice(gpa);
    response.resources = values;
    return .{ .allocator = gpa, .bytes = owned, .resources = values, .value = response };
}

pub const OwnedRequest = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    names: [][]const u8,
    value: Request,
    pub fn deinit(self: *OwnedRequest) void {
        self.allocator.free(self.names);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};
pub fn decodeRequest(gpa: std.mem.Allocator, bytes: []const u8, limit: usize, max_names: usize) Error!OwnedRequest {
    if (bytes.len > limit) return error.DiscoveryLimitExceeded;
    const owned = try gpa.dupe(u8, bytes);
    errdefer gpa.free(owned);
    var names: std.ArrayList([]const u8) = .empty;
    errdefer names.deinit(gpa);
    var request: Request = .{ .type_url = "" };
    var reader: protobuf.Reader = .{ .bytes = owned };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) request.version = try reader.string() else if (field.number == 2 and field.wire_type == 2) request.node = try reader.bytesValue() else if (field.number == 3 and field.wire_type == 2) {
            if (names.items.len >= max_names) return error.DiscoveryLimitExceeded;
            try names.append(gpa, try reader.string());
        } else if (field.number == 4 and field.wire_type == 2) request.type_url = try reader.string() else if (field.number == 5 and field.wire_type == 2) request.nonce = try reader.string() else if (field.number == 6 and field.wire_type == 2) {
            const status = try details.parse(try reader.bytesValue());
            request.nack = .{ .code = status.code orelse .ok, .message = status.message };
        } else try reader.skip(field);
    }
    try typeUrl(request.type_url);
    const values = try names.toOwnedSlice(gpa);
    request.names = values;
    return .{ .allocator = gpa, .bytes = owned, .names = values, .value = request };
}
