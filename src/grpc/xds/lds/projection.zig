//! Immutable HCM timeout projection over an already parsed route snapshot.
const std = @import("std");
const rds = @import("../rds.zig");
const selector = @import("../../channel/call_selector.zig");
const service = @import("../../service_config.zig");
pub const Projection = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    source: *rds.Snapshot,
    maximum: ?std.Io.Duration,
    pub fn create(gpa: std.mem.Allocator, source: *rds.Snapshot, maximum: ?std.Io.Duration) std.mem.Allocator.Error!*Projection {
        const self = try gpa.create(Projection);
        source.retain();
        self.* = .{ .allocator = gpa, .source = source, .maximum = maximum };
        return self;
    }
    pub fn retain(self: *Projection) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Projection) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.source.release();
        self.allocator.destroy(self);
    }
    fn view(self: *Projection) rds.Snapshot {
        // Copy only immutable data, never the concurrently modified atomic
        // reference counter. This borrowed view is used only for resolution.
        var snapshot = rds.Snapshot{ .allocator = self.source.allocator, .resource = self.source.resource, .authority = self.source.authority, .virtual_host = self.source.virtual_host, .required_clusters = self.source.required_clusters, .options = self.source.options };
        snapshot.options.default_max_stream_duration = self.maximum;
        return snapshot;
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
        var snapshot = self.view();
        return snapshot.resolveUnary(active, base);
    }
    fn streaming(context: *anyopaque, active: selector.Context, base: service.ResolvedStreaming) selector.Error!service.ResolvedStreaming {
        const self: *Projection = @ptrCast(@alignCast(context));
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
