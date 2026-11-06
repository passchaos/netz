//! Serialized client listener/RDS state; publication commits before ACK output.
const std = @import("std");
const model = @import("model.zig");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const rds = @import("../rds.zig");
const shared = @import("../../channel/shared.zig");
const Projection = @import("projection.zig").Projection;
pub const Error = model.Error || ads.Error || delta.Error || rds.Error || shared.Error || @import("../runtime/errors.zig").PublishError || error{ InvalidLdsOptions, WrongLdsResource, DuplicateLdsResource };
pub const Publisher = struct {
    context: *anyopaque,
    publish_fn: *const fn (*anyopaque, *ads.Client, *@import("projection.zig").Projection, shared.SharedChannel, std.Io.Clock.Timestamp) @import("../runtime/errors.zig").PublishError!u64,
};
pub const DeltaPublisher = struct {
    context: *anyopaque,
    publish_fn: *const fn (*anyopaque, *delta.Client, *@import("projection.zig").Projection, shared.SharedChannel, std.Io.Clock.Timestamp) @import("../runtime/errors.zig").PublishError!u64,
};
pub const Options = struct {
    listener_name: []const u8,
    authority: []const u8,
    max_header_bytes: usize = 65536,
    limits: model.Limits = .{},
    publisher: ?Publisher = null,
    delta_publisher: ?DeltaPublisher = null,
    /// gRPC `ignore_resource_deletion`: retain resources omitted or removed.
    ignore_resource_deletion: bool = false,
    /// gRPC `fail_on_data_errors`: drop the cached listener/routes when the
    /// resource fails typed validation, then NACK the response.
    fail_on_data_errors: bool = false,
    /// gRPC `trusted_xds_server`: allow this control plane to request
    /// automatic host rewriting from the selected endpoint.
    trusted_xds_server: bool = false,
};
pub const Controller = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    options: Options,
    listener: ?model.Owned = null,
    routes: ?*rds.Snapshot = null,
    /// A real route payload has been accepted; an empty placeholder has not.
    routes_accepted: bool = false,
    /// Delta TTL deadlines; null means no timer.
    listener_deadline: ?std.Io.Clock.Timestamp = null,
    routes_deadline: ?std.Io.Clock.Timestamp = null,
    /// Raw RBAC config from the accepted listener; projections compile it.
    rbac_config: ?[]const u8 = null,
    /// Raw fault-injection config from the accepted listener.
    fault_config: ?[]const u8 = null,
    pub fn init(gpa: std.mem.Allocator, options: Options) Error!Controller {
        if (options.listener_name.len == 0 or options.listener_name.len > options.limits.max_text_bytes or !std.unicode.utf8ValidateSlice(options.listener_name) or options.authority.len == 0 or options.authority.len > options.limits.rds.max_text_bytes or !std.unicode.utf8ValidateSlice(options.authority) or options.max_header_bytes == 0) return error.InvalidLdsOptions;
        var self = Controller{ .allocator = gpa, .arena = .init(gpa), .options = options };
        errdefer self.deinit();
        self.options.listener_name = try self.arena.allocator().dupe(u8, options.listener_name);
        self.options.authority = try self.arena.allocator().dupe(u8, options.authority);
        return self;
    }
    pub fn deinit(self: *Controller) void {
        if (self.listener) |*value| value.deinit();
        if (self.routes) |snapshot| snapshot.release();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn subscribe(self: *Controller, client: *ads.Client) Error!void {
        try client.setSubscription(model.type_url, &.{self.options.listener_name});
    }
    pub fn subscribeDelta(self: *Controller, client: *delta.Client) Error!void {
        try client.setSubscription(model.type_url, &.{self.options.listener_name});
    }
    pub fn routeOptions(self: *const Controller) rds.Options {
        return .{
            .authority = self.options.authority,
            .max_header_bytes = self.options.max_header_bytes,
            .trusted_xds_server = self.options.trusted_xds_server,
        };
    }
    pub fn publish(self: *Controller, client: *ads.Client, projection: *@import("projection.zig").Projection, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        if (self.options.publisher) |publisher| return publisher.publish_fn(publisher.context, client, projection, destination, deadline);
        return projection.publishWithDeadline(destination, deadline);
    }
    pub fn publishDelta(self: *Controller, client: *delta.Client, projection: *@import("projection.zig").Projection, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        if (self.options.delta_publisher) |publisher| return publisher.publish_fn(publisher.context, client, projection, destination, deadline);
        return projection.publishWithDeadline(destination, deadline);
    }
    pub fn empty(self: *Controller, name: []const u8) Error!*rds.Snapshot {
        var writer: std.Io.Writer.Allocating = .init(self.allocator);
        defer writer.deinit();
        writer.writer.writeByte(10) catch return error.OutOfMemory;
        var length = name.len;
        while (length >= 128) : (length >>= 7) writer.writer.writeByte(@as(u8, @truncate(length)) | 0x80) catch return error.OutOfMemory;
        writer.writer.writeByte(@intCast(length)) catch return error.OutOfMemory;
        writer.writer.writeAll(name) catch return error.OutOfMemory;
        return rds.Snapshot.create(self.allocator, writer.written(), self.options.limits.rds, self.routeOptions());
    }
    pub fn takeInline(self: *Controller, candidate: *model.Owned) Error!*rds.Snapshot {
        var resource = candidate.inline_rds orelse return error.InvalidLdsResource;
        candidate.inline_rds = null;
        return rds.Snapshot.takeResource(self.allocator, &resource, self.options.limits.rds, self.routeOptions()) catch |err| {
            resource.deinit();
            return err;
        };
    }
    pub fn applyWithDeadline(self: *Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        try client.validateUpdate(update);
        const url = update.response.value.type_url;
        const revision = if (std.mem.eql(u8, url, model.type_url))
            try @import("apply_listener.zig").apply(self, client, update, destination, deadline)
        else if (std.mem.eql(u8, url, rds.type_url))
            try @import("apply_routes.zig").apply(self, client, update, destination, deadline)
        else
            return error.WrongLdsResource;
        try client.acceptAppliedUpdate(update);
        _ = try client.flushWithDeadline(deadline);
        return revision;
    }
    pub fn applyDeltaWithDeadline(self: *Controller, client: *delta.Client, update: delta.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        try client.validateUpdate(update);
        const url = update.response.value.type_url;
        const revision = if (std.mem.eql(u8, url, model.type_url))
            try @import("apply_delta.zig").applyListener(self, client, update, destination, deadline)
        else if (std.mem.eql(u8, url, rds.type_url))
            try @import("apply_delta.zig").applyRoutes(self, client, update, destination, deadline)
        else
            return error.WrongLdsResource;
        try client.acceptAppliedUpdate(update);
        _ = try client.flushWithDeadline(deadline);
        return revision;
    }
    pub fn nextDeadline(self: *const Controller) ?std.Io.Clock.Timestamp {
        var result: ?std.Io.Clock.Timestamp = null;
        if (self.listener_deadline) |value| result = value;
        if (self.routes_deadline) |value| {
            if (result == null or value.raw.nanoseconds < result.?.raw.nanoseconds) result = value;
        }
        return result;
    }
    /// Remove an expired listener. The resource remains desired; only the
    /// accepted version is forgotten so a reconnect asks for it again.
    pub fn expireListenerWithDeadline(self: *Controller, client: *delta.Client, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        if (self.listener == null) return @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
        if (client.subscriptions.find(model.type_url) != null) try client.subscriptions.forget(model.type_url, self.options.listener_name);
        var subscription: ?delta.subscriptions.Prepared = null;
        defer if (subscription) |*prepared| prepared.deinit();
        if (self.listener.?.value.hcm.route_source == .rds) {
            const name = self.listener.?.value.hcm.route_source.rds;
            if (client.subscriptions.find(rds.type_url) != null) try client.subscriptions.forget(rds.type_url, name);
            if (client.subscriptions.find(rds.type_url) != null) {
                subscription = try client.subscriptions.prepare(rds.type_url, &.{});
            }
        }
        const rejecting = try self.empty("_");
        defer rejecting.release();
        const projection = try Projection.create(self.allocator, rejecting, null, null, null);
        defer projection.release();
        const revision = try self.publishDelta(client, projection, destination, deadline);
        if (subscription) |*prepared| prepared.commit();
        if (self.listener) |*previous| previous.deinit();
        self.listener = null;
        self.rbac_config = null;
        self.fault_config = null;
        if (self.routes) |previous| previous.release();
        self.routes = null;
        self.routes_accepted = false;
        self.listener_deadline = null;
        self.routes_deadline = null;
        return revision;
    }
    /// Remove an expired route configuration. The listener stays accepted and
    /// the RDS name stays subscribed.
    pub fn expireRoutesWithDeadline(self: *Controller, client: *delta.Client, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        const listener = self.listener orelse {
            self.routes_deadline = null;
            return @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
        };
        if (listener.value.hcm.route_source != .rds or !self.routes_accepted or self.routes == null) {
            self.routes_deadline = null;
            return @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
        }
        const name = listener.value.hcm.route_source.rds;
        if (client.subscriptions.find(rds.type_url) != null) try client.subscriptions.forget(rds.type_url, name);
        const rejecting = try self.empty(name);
        defer rejecting.release();
        const projection = try Projection.create(self.allocator, rejecting, listener.value.hcm.max_stream_duration, self.rbac_config, self.fault_config);
        defer projection.release();
        const revision = try self.publishDelta(client, projection, destination, deadline);
        rejecting.retain();
        if (self.routes) |previous| previous.release();
        self.routes = rejecting;
        self.routes_accepted = false;
        self.routes_deadline = null;
        return revision;
    }
};
