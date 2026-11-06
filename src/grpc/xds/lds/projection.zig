//! Immutable HCM timeout and RBAC projection over parsed route state.
const std = @import("std");
const rds = @import("../rds.zig");
const rbac = @import("rbac.zig");
const routing = @import("../routing/mod.zig");
const selector = @import("../../channel/call_selector.zig");
const service = @import("../../service_config.zig");
pub const Projection = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    source: *rds.Snapshot,
    maximum: ?std.Io.Duration,
    arena: std.heap.ArenaAllocator,
    rbac: ?*rbac.Policy = null,
    pub fn create(
        gpa: std.mem.Allocator,
        source: *rds.Snapshot,
        maximum: ?std.Io.Duration,
        rbac_config: ?[]const u8,
    ) (std.mem.Allocator.Error || rbac.Error)!*Projection {
        const self = try gpa.create(Projection);
        errdefer gpa.destroy(self);
        source.retain();
        errdefer source.release();
        self.* = .{
            .allocator = gpa,
            .source = source,
            .maximum = maximum,
            .arena = .init(gpa),
        };
        errdefer self.arena.deinit();
        if (rbac_config) |bytes| {
            const policy = try self.arena.allocator().create(rbac.Policy);
            policy.* = try rbac.decode(self.arena.allocator(), bytes, .{});
            self.rbac = policy;
        }
        return self;
    }
    pub fn retain(self: *Projection) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Projection) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.source.release();
        self.arena.deinit();
        self.allocator.destroy(self);
    }
    fn view(self: *Projection) rds.Snapshot {
        // Copy only immutable data, never the concurrently modified atomic
        // reference counter. This borrowed view is used only for resolution.
        var snapshot = rds.Snapshot{ .allocator = self.source.allocator, .resource = self.source.resource, .authority = self.source.authority, .virtual_host = self.source.virtual_host, .required_clusters = self.source.required_clusters, .options = self.source.options };
        snapshot.options.default_max_stream_duration = self.maximum;
        return snapshot;
    }
    fn authorize(self: *Projection, active: selector.Context, options: anytype) selector.Error!void {
        const policy = self.rbac orelse return;
        const request = routing.header.Request{
            .path = options.path,
            .authority = options.authority orelse self.source.authority,
            .scheme = options.scheme,
            .metadata = options.metadata,
            .max_header_bytes = self.source.options.max_header_bytes,
        };
        const allowed = rbac.evaluate(policy, active.allocator, request) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.PermissionDenied,
        };
        if (!allowed) return error.PermissionDenied;
    }
    fn retainContext(context: *anyopaque) void {
        const self: *Projection = @ptrCast(@alignCast(context));
        self.retain();
    }
    fn releaseContext(context: *anyopaque) void {
        const self: *Projection = @ptrCast(@alignCast(context));
        self.release();
    }
    fn unary(context: *anyopaque, active: selector.Context, base: service.ResolvedUnary) selector.Error!service.ResolvedUnary {
        const self: *Projection = @ptrCast(@alignCast(context));
        try self.authorize(active, base.options);
        var snapshot = self.view();
        return snapshot.resolveUnary(active, base);
    }
    fn streaming(context: *anyopaque, active: selector.Context, base: service.ResolvedStreaming) selector.Error!service.ResolvedStreaming {
        const self: *Projection = @ptrCast(@alignCast(context));
        try self.authorize(active, base.options);
        var snapshot = self.view();
        return snapshot.resolveStreaming(active, base);
    }
    pub fn descriptor(self: *Projection) selector.Selector {
        return .{ .context = self, .retain_fn = retainContext, .release_fn = releaseContext, .unary_fn = unary, .streaming_fn = streaming, .required_clusters = self.source.required_clusters };
    }
    pub fn publishWithDeadline(self: *Projection, destination: @import("../../channel/shared.zig").SharedChannel, deadline: std.Io.Clock.Timestamp) @import("../../channel/shared.zig").Error!u64 {
        return destination.updateWithDeadline(.{ .call_selector = .{ .replace = self.descriptor() } }, deadline);
    }
};
