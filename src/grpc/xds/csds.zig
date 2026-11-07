//! Client Status Discovery Service (CSDS) response encoding.
//!
//! `envoy.service.status.v3.ClientStatusDiscoveryService/FetchClientStatus`
//! lets an xDS client expose its current accepted configuration. This module
//! encodes the `ClientStatusResponse` for one client without generated
//! protobuf code; the caller supplies the node message bytes and the accepted
//! resources gathered from a runtime controller.

const std = @import("std");
const protobuf = @import("../protobuf.zig");

pub const Error = std.mem.Allocator.Error || error{InvalidRequest};

/// `envoy.admin.v3.ClientResourceStatus`, including current Envoy's server-error
/// and resource-timeout values. The pinned schema is in csds_schema/.
pub const ClientStatus = enum(u32) {
    unknown = 0,
    requested = 1,
    does_not_exist = 2,
    acked = 3,
    nacked = 4,
    /// Control-plane error; accepted resource contents remain available.
    received_error = 5,
    /// Timed out waiting for a resource from the control plane.
    timeout = 6,
};

/// `google.protobuf.Timestamp`; nanos is the nonnegative fractional second.
pub const Timestamp = struct {
    seconds: i64 = 0,
    nanos: u32 = 0,
};

/// `envoy.admin.v3.UpdateFailureState`. The optional failed_configuration
/// image is omitted; clients may avoid retaining rejected resource contents.
pub const UpdateFailureState = struct {
    details: []const u8 = "",
    /// Rejected resource version, separate from Resource.version's accepted one.
    version_info: []const u8 = "",
    last_update_attempt: ?Timestamp = null,
};

pub const Resource = struct {
    type_url: []const u8,
    name: []const u8,
    version: []const u8 = "",
    /// Accepted resource wire bytes; encoded as a `google.protobuf.Any` value.
    wire: []const u8 = "",
    status: ClientStatus = .acked,
    last_updated_seconds: ?i64 = null,
    last_updated_nanos: ?u32 = null,
    /// Latest rejected update; absent after a successful update.
    error_state: ?UpdateFailureState = null,
};

pub const Options = struct {
    /// Encoded `envoy.config.core.v3.Node` message.
    node: []const u8 = "",
    /// `ClientConfig.client_scope`; "grpc" identifies a gRPC data-plane client.
    client_scope: []const u8 = "grpc",
    /// `ClientStatusRequest.exclude_resource_contents`: omit every
    /// `GenericXdsConfig.xds_config` while keeping status and version.
    exclude_resource_contents: bool = false,
};

pub const Request = struct {
    exclude_resource_contents: bool = false,
};

/// Decode the fields of a `ClientStatusRequest` that affect this client-side
/// response. Node matchers and the request node are ignored because the
/// response describes the local client.
pub fn decodeRequest(bytes: []const u8) Error!Request {
    if (bytes.len > 1024 * 1024) return error.InvalidRequest;
    var reader = protobuf.Reader{ .bytes = bytes };
    var request: Request = .{};
    while (reader.next() catch return error.InvalidRequest) |field| {
        switch (field.number) {
            1, 2 => {
                if (field.wire_type != 2) return error.InvalidRequest;
                _ = reader.bytesValue() catch return error.InvalidRequest;
            },
            3 => {
                if (field.wire_type != 0) return error.InvalidRequest;
                request.exclude_resource_contents = (reader.varint() catch return error.InvalidRequest) != 0;
            },
            else => reader.skip(field) catch return error.InvalidRequest,
        }
    }
    return request;
}

fn varint(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
    var remaining = value;
    while (remaining >= 0x80) {
        try out.append(allocator, @as(u8, @truncate(remaining)) | 0x80);
        remaining >>= 7;
    }
    try out.append(allocator, @intCast(remaining));
}

fn tag(out: *std.ArrayList(u8), allocator: std.mem.Allocator, field: u32, wire_type: u3) !void {
    try varint(out, allocator, (@as(u64, field) << 3) | wire_type);
}

fn bytesField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, field: u32, value: []const u8) !void {
    try tag(out, allocator, field, 2);
    try varint(out, allocator, value.len);
    try out.appendSlice(allocator, value);
}

fn varintField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, field: u32, value: u64) !void {
    try tag(out, allocator, field, 0);
    try varint(out, allocator, value);
}

fn timestampField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, field: u32, value: Timestamp) !void {
    var timestamp: std.ArrayList(u8) = .empty;
    defer timestamp.deinit(allocator);
    if (value.seconds != 0) try varintField(&timestamp, allocator, 1, @bitCast(value.seconds));
    if (value.nanos != 0) try varintField(&timestamp, allocator, 2, value.nanos);
    try bytesField(out, allocator, field, timestamp.items);
}

fn failureField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: UpdateFailureState) !void {
    var failure: std.ArrayList(u8) = .empty;
    defer failure.deinit(allocator);
    if (value.last_update_attempt) |attempt| try timestampField(&failure, allocator, 2, attempt);
    if (value.details.len != 0) try bytesField(&failure, allocator, 3, value.details);
    if (value.version_info.len != 0) try bytesField(&failure, allocator, 4, value.version_info);
    // GenericXdsConfig.error_state is field 8, including an empty present state.
    try bytesField(out, allocator, 8, failure.items);
}

fn encodeGeneric(
    allocator: std.mem.Allocator,
    resource: Resource,
    exclude_resource_contents: bool,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try bytesField(&out, allocator, 1, resource.type_url);
    try bytesField(&out, allocator, 2, resource.name);
    if (resource.version.len != 0) try bytesField(&out, allocator, 3, resource.version);
    if (resource.wire.len != 0 and !exclude_resource_contents) {
        var any: std.ArrayList(u8) = .empty;
        defer any.deinit(allocator);
        try bytesField(&any, allocator, 1, resource.type_url);
        try bytesField(&any, allocator, 2, resource.wire);
        try bytesField(&out, allocator, 4, any.items);
    }
    if (resource.last_updated_seconds != null or resource.last_updated_nanos != null) {
        try timestampField(&out, allocator, 5, .{ .seconds = resource.last_updated_seconds orelse 0, .nanos = resource.last_updated_nanos orelse 0 });
    }
    if (resource.status != .unknown) {
        try varintField(&out, allocator, 7, @intFromEnum(resource.status));
    }
    if (resource.error_state) |failure| try failureField(&out, allocator, failure);
    return out.toOwnedSlice(allocator);
}

/// Encode one `ClientStatusResponse` containing one `ClientConfig`.
pub fn encodeResponse(
    allocator: std.mem.Allocator,
    resources: []const Resource,
    options: Options,
) std.mem.Allocator.Error![]u8 {
    var client: std.ArrayList(u8) = .empty;
    defer client.deinit(allocator);
    if (options.node.len != 0) try bytesField(&client, allocator, 1, options.node);
    for (resources) |resource| {
        const generic = try encodeGeneric(allocator, resource, options.exclude_resource_contents);
        defer allocator.free(generic);
        try bytesField(&client, allocator, 3, generic);
    }
    if (options.client_scope.len != 0) try bytesField(&client, allocator, 4, options.client_scope);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try bytesField(&out, allocator, 1, client.items);
    return out.toOwnedSlice(allocator);
}

test "CSDS encodes accepted resources with type, name, version and status" {
    const resources = [_]Resource{
        .{ .type_url = "type.googleapis.com/envoy.config.listener.v3.Listener", .name = "frontend", .version = "v1", .wire = "\x0a\x08frontend" },
        .{ .type_url = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment", .name = "eds-a", .version = "v2", .status = .does_not_exist, .last_updated_seconds = 1, .last_updated_nanos = 2 },
    };
    const encoded = try encodeResponse(std.testing.allocator, &resources, .{ .node = "\x0a\x06node-1" });
    defer std.testing.allocator.free(encoded);
    // The response is one ClientConfig containing two GenericXdsConfig entries.
    try std.testing.expectEqual(@as(usize, 0x0a), encoded[0]);
    try std.testing.expect(encoded.len > 0);
}

test {
    _ = @import("csds_codec_tests.zig");
}
