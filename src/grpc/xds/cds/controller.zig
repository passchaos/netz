//! One serialized application's selected CDS cluster and matching EDS image.
const std = @import("std");
const resource = @import("decode.zig");
const ads = @import("../ads.zig");
const eds = @import("../eds.zig");
const shared = @import("../../channel/shared.zig");
pub const Error = resource.Error || eds.Error || ads.Error || error{ InvalidCdsOptions, WrongCdsResource, DuplicateCdsResource };
pub const Options = struct {
    cluster_name: []const u8,
    target: eds.TargetOptions,
    cds_limits: resource.Limits = .{},
    eds_limits: eds.resource.Limits = .{},
};
pub const Controller = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    options: Options,
    cluster: ?resource.Owned = null,
    eds_image: ?[]u8 = null,
    pub fn init(gpa: std.mem.Allocator, options: Options) Error!Controller {
        if (options.cluster_name.len == 0 or options.target.authority.len == 0 or options.target.attempt_delay.nanoseconds <= 0) return error.InvalidCdsOptions;
        try ads.codec.validText(options.cluster_name);
        var self = Controller{ .allocator = gpa, .arena = .init(gpa), .options = options };
        errdefer self.deinit();
        const arena = self.arena.allocator();
        self.options.cluster_name = try arena.dupe(u8, options.cluster_name);
        self.options.target.authority = try arena.dupe(u8, options.target.authority);
        if (self.options.target.tls) |*tls| tls.host = try arena.dupe(u8, tls.host);
        // All policy/identity data is derived from accepted CDS resources.
        self.options.target.cluster = null;
        self.options.target.child_policy_json = "[{\"round_robin\":{}}]";
        return self;
    }
    pub fn deinit(self: *Controller) void {
        if (self.cluster) |*value| value.deinit();
        if (self.eds_image) |image| self.allocator.free(image);
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn subscribe(self: *Controller, client: *ads.Client) Error!void {
        try client.setSubscription(resource.type_url, &.{self.options.cluster_name});
    }
    fn targetOptions(self: *Controller, cluster: resource.Cluster) eds.TargetOptions {
        var options = self.options.target;
        options.cluster = cluster.name;
        options.max_concurrent_requests = cluster.max_concurrent_requests;
        options.child_policy_json = cluster.policy.child_json;
        options.locality_weighted = cluster.policy.locality_weighted;
        return options;
    }
    fn empty(self: *Controller, name: []const u8) Error![]u8 {
        var writer: std.Io.Writer.Allocating = .init(self.allocator);
        defer writer.deinit();
        writer.writer.writeByte(10) catch return error.OutOfMemory;
        var len = name.len;
        while (len >= 128) : (len >>= 7) writer.writer.writeByte(@as(u8, @truncate(len)) | 0x80) catch return error.OutOfMemory;
        writer.writer.writeByte(@intCast(len)) catch return error.OutOfMemory;
        writer.writer.writeAll(name) catch return error.OutOfMemory;
        return self.allocator.dupe(u8, writer.written());
    }
    pub fn applyWithDeadline(self: *Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        try client.validateUpdate(update);
        const type_url = update.response.value.type_url;
        const revision = if (std.mem.eql(u8, type_url, resource.type_url)) try self.applyCluster(client, update, destination, deadline) else if (std.mem.eql(u8, type_url, eds.type_url)) try self.applyEndpoints(update, destination, deadline) else return error.WrongCdsResource;
        // The committed configuration/version survives a failed ACK write.
        try client.acceptAppliedUpdate(update);
        _ = try client.flushWithDeadline(deadline);
        return revision;
    }
    fn applyCluster(self: *Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        var candidates: std.ArrayList(?resource.Owned) = .empty;
        defer {
            for (candidates.items) |*candidate| if (candidate.*) |*value| value.deinit();
            candidates.deinit(self.allocator);
        }
        var selected: ?usize = null;
        for (update.response.value.resources) |raw| {
            var candidate = try resource.decode(self.allocator, raw.value, self.options.cds_limits);
            errdefer candidate.deinit();
            for (candidates.items) |previous| if (std.mem.eql(u8, previous.?.value.name, candidate.value.name)) return error.DuplicateCdsResource;
            if (std.mem.eql(u8, candidate.value.name, self.options.cluster_name)) selected = candidates.items.len;
            try candidates.append(self.allocator, candidate);
        }
        if (selected) |index| {
            const cluster = candidates.items[index].?.value;
            const same = if (self.cluster) |previous| std.mem.eql(u8, previous.value.edsName(), cluster.edsName()) else false;
            var subscription = try client.subscriptions.prepare(eds.type_url, &.{cluster.edsName()});
            defer subscription.deinit();
            const cached = same and self.eds_image != null;
            const image = if (cached) self.eds_image.? else try self.empty(cluster.edsName());
            defer if (!cached) self.allocator.free(image);
            const snapshot = try eds.Snapshot.create(self.allocator, image, self.options.eds_limits, self.targetOptions(cluster));
            defer snapshot.release();
            const revision = try snapshot.publishWithDeadline(destination, deadline);
            subscription.commit();
            if (!same) {
                if (self.eds_image) |previous| self.allocator.free(previous);
                self.eds_image = null;
            }
            if (self.cluster) |*previous| previous.deinit();
            self.cluster = candidates.items[index];
            candidates.items[index] = null;
            return revision;
        }
        const revision = try destination.updateWithDeadline(.{ .target = .{ .resolved = .{ .endpoints = &.{} } }, .service_config = .{ .replace = "{\"loadBalancingConfig\":[{\"round_robin\":{}}]}" }, .drop_categories = .{ .replace = &.{} }, .circuit_breaker = .{ .replace = null } }, deadline);
        if (self.cluster) |*previous| previous.deinit();
        self.cluster = null;
        if (self.eds_image) |image| self.allocator.free(image);
        self.eds_image = null;
        // Keep the last named EDS subscription; an empty list means wildcard.
        // Late responses are validated/ACKed but cannot restore a deleted CDS.
        return revision;
    }
    fn applyEndpoints(self: *Controller, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        var candidates: std.ArrayList(eds.resource.Owned) = .empty;
        defer {
            for (candidates.items) |*candidate| candidate.deinit();
            candidates.deinit(self.allocator);
        }
        var selected: ?[]const u8 = null;
        for (update.response.value.resources) |raw| {
            var candidate = try eds.decode(self.allocator, raw.value, self.options.eds_limits);
            errdefer candidate.deinit();
            for (candidates.items) |previous| if (std.mem.eql(u8, previous.value.cluster_name, candidate.value.cluster_name)) return error.DuplicateEdsResource;
            if (self.cluster) |cluster| if (std.mem.eql(u8, cluster.value.edsName(), candidate.value.cluster_name)) {
                selected = raw.value;
            };
            try candidates.append(self.allocator, candidate);
        }
        const cluster = self.cluster orelse return destination.configurationRevision();
        const image = if (selected) |bytes| try self.allocator.dupe(u8, bytes) else try self.empty(cluster.value.edsName());
        var image_owned = true;
        defer if (image_owned) self.allocator.free(image);
        const snapshot = try eds.Snapshot.create(self.allocator, image, self.options.eds_limits, self.targetOptions(cluster.value));
        defer snapshot.release();
        const revision = try snapshot.publishWithDeadline(destination, deadline);
        if (self.eds_image) |previous| self.allocator.free(previous);
        self.eds_image = image;
        image_owned = false;
        return revision;
    }
};
