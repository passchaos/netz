//! One serialized discovery client for one bootstrap resource authority.
const std = @import("std");
const ads = @import("../../ads.zig");
const delta = @import("../../ads/delta.zig");
const bootstrap = @import("../../bootstrap.zig");
const plane = @import("../../control_plane.zig");
pub const Mode = enum { sotw, delta };
pub const Error = plane.Error;

pub fn Session(comptime mode: Mode) type {
    return struct {
        const Self = @This();
        pub const Client = if (mode == .sotw) ads.Client else delta.Client;
        pub const Event = if (mode == .sotw) ads.Event else delta.Event;
        pub const ClientError = if (mode == .sotw) ads.Error else delta.Error;
        allocator: std.mem.Allocator,
        refs: std.atomic.Value(usize) = .init(1),
        authority: []u8,
        control_plane: *plane.ControlPlane,
        client: Client,
        pending: ?(ClientError!Event) = null,
        provisional: bool = false,
        pending_prepares: usize = 0,

        pub fn create(gpa: std.mem.Allocator, io: std.Io, configuration: *bootstrap.Bootstrap, authority: []const u8, options: plane.Options) Error!*Self {
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            const key = try gpa.dupe(u8, authority);
            errdefer gpa.free(key);
            var selected = options;
            selected.authority = if (key.len == 0) null else key;
            const control = try plane.ControlPlane.init(gpa, io, configuration, selected);
            errdefer control.deinit();
            const limits = options.limits;
            const subscriptions = options.subscriptions;
            const client = if (mode == .sotw)
                try control.newSotwClient(.{ .node = control.source.node, .request = control.source.request, .subscriptions = .{ .max_types = subscriptions.max_types, .max_names_per_type = subscriptions.max_names_per_type, .max_name_bytes = subscriptions.max_name_bytes }, .limits = .{ .max_message_bytes = limits.max_message_bytes, .max_resources = limits.max_resources, .max_resource_bytes = limits.max_resource_bytes, .max_name_bytes = limits.max_name_bytes } })
            else
                try control.newDeltaClient(.{ .node = control.source.node, .request = control.source.request, .subscriptions = subscriptions, .limits = limits });
            self.* = .{ .allocator = gpa, .authority = key, .control_plane = control, .client = client };
            return self;
        }

        pub fn retain(self: *Self) *Self {
            _ = self.refs.fetchAdd(1, .monotonic);
            return self;
        }

        pub fn release(self: *Self) void {
            if (self.refs.fetchSub(1, .acq_rel) != 1) return;
            if (self.pending) |value| if (value) |event_value| {
                var event = event_value;
                event.deinit();
            } else |_| {};
            self.client.deinit();
            self.control_plane.deinit();
            self.allocator.free(self.authority);
            self.allocator.destroy(self);
        }

        pub fn reconnect(self: *Self, deadline: std.Io.Clock.Timestamp, failover: bool) Error!void {
            if (failover) {
                try self.control_plane.moveToNextServer(deadline);
                if (mode == .sotw) try self.control_plane.rebindSotw(&self.client, self.client.request) else try self.control_plane.rebindDelta(&self.client, self.client.request);
            }
            try self.client.connectWithDeadline(deadline);
        }
    };
}
