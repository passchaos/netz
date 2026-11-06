//! Client Status Discovery Service adapter for the gRPC server runtime.
//!
//! The application owns the admin listener. This helper answers an already
//! read unary request when it targets `FetchClientStatus`, leaving other paths
//! to the caller.

const std = @import("std");
const runtime = @import("../runtime.zig");
const Controller = @import("runtime/controller.zig").Controller;

pub const fetch_path = "/envoy.service.status.v3.ClientStatusDiscoveryService/FetchClientStatus";

pub fn isFetch(path: []const u8) bool {
    return std.mem.eql(u8, path, fetch_path);
}

/// Answer one unary request when it targets FetchClientStatus. Returns false
/// for any other path without writing a response, so the caller can dispatch
/// the same request normally.
pub fn respondFetch(
    connection: *runtime.ServerConnection,
    request: *const runtime.OwnedUnaryRequest,
    controller: *Controller,
    client: anytype,
    allocator: std.mem.Allocator,
    node: []const u8,
) !bool {
    if (!isFetch(request.request.path)) return false;
    const encoded = try controller.fetchClientStatus(
        client,
        allocator,
        request.request.message.payload,
        .{ .node = node },
    );
    defer allocator.free(encoded);
    try connection.writeUnary(request.request.stream_id, .{ .message = encoded });
    return true;
}
