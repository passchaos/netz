//! Immutable retained per-RPC configuration, distinct from endpoint LB picks.
const std = @import("std");
const call = @import("../call.zig");
const service = @import("../service_config.zig");
const wire = @import("../wire.zig");
pub const Error = call.Error || service.Error || error{ NoMatchingRoute, InvalidRouteAction, RouteMetadataLimitExceeded, PermissionDenied };
pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    channel_id: u64,
    deadline: ?std.Io.Clock.Timestamp,
    service_config: ?*const service.ServiceConfig = null,
    pub fn check(self: Context) Error!void {
        try self.io.checkCancel();
        if (self.deadline) |deadline| if (deadline.clock != .awake or deadline.durationFromNow(self.io).raw.nanoseconds <= 0) return error.Timeout;
    }
};
pub const Selector = struct {
    context: *anyopaque,
    retain_fn: *const fn (*anyopaque) void,
    release_fn: *const fn (*anyopaque) void,
    unary_fn: *const fn (*anyopaque, Context, service.ResolvedUnary) Error!service.ResolvedUnary,
    streaming_fn: *const fn (*anyopaque, Context, service.ResolvedStreaming) Error!service.ResolvedStreaming,
    /// Exact cluster-manager keys that must exist in the same publication.
    required_clusters: []const []const u8 = &.{},
    pub fn retain(self: Selector) Selector {
        self.retain_fn(self.context);
        return self;
    }
    pub fn release(self: Selector) void {
        self.release_fn(self.context);
    }
};
pub fn unavailable(gpa: std.mem.Allocator, err: Error) std.mem.Allocator.Error!call.UnaryResponse {
    return .{ .allocator = gpa, .transport = null, .status = .unavailable, .status_message = try gpa.dupe(u8, if (err == error.NoMatchingRoute) "No matching route found in xDS route config" else "Matching route has inappropriate action"), .message = null, .was_compressed = false, .encoding = null, .owned_message = null };
}
pub fn permissionDenied(gpa: std.mem.Allocator) std.mem.Allocator.Error!call.UnaryResponse {
    return .{ .allocator = gpa, .transport = null, .status = .permission_denied, .status_message = try gpa.dupe(u8, "RBAC policy denied the request"), .message = null, .was_compressed = false, .encoding = null, .owned_message = null };
}
pub fn faultAborted(gpa: std.mem.Allocator, status: wire.Status, message: []const u8) std.mem.Allocator.Error!call.UnaryResponse {
    return .{ .allocator = gpa, .transport = null, .status = status, .status_message = try gpa.dupe(u8, message), .message = null, .was_compressed = false, .encoding = null, .owned_message = null };
}
