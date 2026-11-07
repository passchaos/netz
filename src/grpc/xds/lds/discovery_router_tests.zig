//! Routed dependencies commit only after listener projection publication.
const std = @import("std");
const grpc = @import("../../mod.zig");
const ads = @import("../ads.zig");
const delta = ads.delta;
const ctl = @import("controller.zig");
const lds = @import("model.zig");
const rds = @import("../rds.zig");
const discovery = @import("../runtime/discovery.zig");
const PublishError = @import("../runtime/errors.zig").PublishError;
const Projection = @import("projection.zig").Projection;
const fixture = @import("testing.zig");
const gpa = std.testing.allocator;
const first_name = "xdstp://B/envoy.config.route.v3.RouteConfiguration/first";
const next_name = "xdstp://B/envoy.config.route.v3.RouteConfiguration/next";
const cds = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

fn Hooks(comptime is_delta: bool) type {
    return struct {
        const Self = @This();
        const Client = if (is_delta) delta.Client else ads.Client;
        const Subscription = if (is_delta) delta.subscriptions.Prepared else ads.subscriptions.Prepared;
        remote: *Client,
        prepares: usize = 0,
        commits: usize = 0,
        releases: usize = 0,
        publications: usize = 0,
        active: usize = 0,
        fail_prepare: bool = false,
        fail_publish: bool = false,
        deadline: ?std.Io.Clock.Timestamp = null,

        const Owned = struct {
            owner: *Self,
            subscription: Subscription,
            committed: bool = false,
            fn commit(context: *anyopaque) void {
                const self: *@This() = @ptrCast(@alignCast(context));
                self.subscription.commit();
                self.committed = true;
                self.owner.commits += 1;
                self.owner.active -= 1;
            }
            fn deinit(context: *anyopaque) void {
                const self: *@This() = @ptrCast(@alignCast(context));
                self.subscription.deinit();
                if (!self.committed) self.owner.active -= 1;
                self.owner.releases += 1;
                gpa.destroy(self);
            }
        };
        fn prepare(context: *anyopaque, watches: []const discovery.Watch, deadline: std.Io.Clock.Timestamp) PublishError!discovery.Transaction {
            const self: *Self = @ptrCast(@alignCast(context));
            std.debug.assert(watches.len == 1 and std.mem.eql(u8, watches[0].type_url, rds.type_url));
            if (self.fail_prepare) return error.OutOfMemory;
            const transaction = try gpa.create(Owned);
            errdefer gpa.destroy(transaction);
            transaction.* = .{ .owner = self, .subscription = try self.remote.subscriptions.prepare(watches[0].type_url, watches[0].names) };
            self.prepares += 1;
            self.active += 1;
            self.deadline = deadline;
            return .{ .context = transaction, .commit_fn = Owned.commit, .deinit_fn = Owned.deinit };
        }
        fn publish(context: *anyopaque, _: *Client, projection: *Projection, destination: grpc.SharedChannel, _: std.Io.Clock.Timestamp) PublishError!u64 {
            const self: *Self = @ptrCast(@alignCast(context));
            std.debug.assert(self.active == 1);
            self.publications += 1;
            // The publisher may stage a child dependency while the outer RDS
            // transaction is pending on this same session.
            var child = try discovery.prepare(self.remote, null, cds, &.{"published-cluster"}, self.deadline.?);
            defer child.deinit();
            if (self.fail_publish) return error.InvalidSharedOptions;
            const revision = try projection.publishWithDeadline(destination, self.deadline.?);
            child.commit();
            return revision;
        }
        fn router(self: *Self) discovery.Router {
            return .{ .context = self, .prepare_fn = prepare };
        }
    };
}

fn update(comptime is_delta: bool, client: anytype, version: []const u8, bytes: ?[]const u8) !(if (is_delta) delta.Update else ads.Update) {
    const encoded = if (is_delta)
        try delta.codec.encodeResponse(gpa, .{ .type_url = lds.type_url, .nonce = version, .resources = if (bytes) |value| &.{.{ .name = "frontend", .version = version, .resource = .{ .type_url = lds.type_url, .value = value } }} else &.{}, .removed = if (bytes == null) &.{"frontend"} else &.{} }, .{})
    else
        try ads.codec.encodeResponse(gpa, .{ .type_url = lds.type_url, .version = version, .nonce = version, .resources = if (bytes) |value| &.{.{ .type_url = lds.type_url, .value = value }} else &.{} }, 4096);
    defer gpa.free(encoded);
    var response = if (is_delta) try delta.codec.decodeResponse(gpa, encoded, .{}) else try ads.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}

fn apply(comptime is_delta: bool, controller: *ctl.Controller, client: anytype, event: anytype, destination: grpc.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    return if (is_delta)
        controller.applyDeltaWithDeadline(client, event, destination, deadline)
    else
        controller.applyWithDeadline(client, event, destination, deadline);
}

fn routedListener(comptime is_delta: bool) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    var destination = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer destination.deinit();
    var sender = destination.sender();
    defer sender.deinit();
    const Client = if (is_delta) delta.Client else ads.Client;
    var local = try Client.init(gpa, sender, .{ .node = .{ .id = "authority-A" } });
    defer local.deinit();
    var remote = try Client.init(gpa, sender, .{ .node = .{ .id = "authority-B" } });
    defer remote.deinit();
    var hooks = Hooks(is_delta){ .remote = &remote };
    var options = ctl.Options{ .listener_name = "frontend", .authority = "backend.test", .discovery_router = hooks.router() };
    if (is_delta) options.delta_publisher = .{ .context = &hooks, .publish_fn = Hooks(is_delta).publish } else options.publisher = .{ .context = &hooks, .publish_fn = Hooks(is_delta).publish };
    var controller = try ctl.Controller.init(gpa, options);
    defer controller.deinit();
    if (is_delta) try controller.subscribeDelta(&local) else try controller.subscribe(&local);
    const first = try fixture.encode(gpa, .{ .route_name = first_name });
    defer gpa.free(first);
    var initial = try update(is_delta, &local, "l1", first);
    defer initial.deinit();
    try std.testing.expectError(error.AdsNotConnected, apply(is_delta, &controller, &local, initial, destination, deadline));
    try std.testing.expectEqualStrings(first_name, remote.subscriptions.find(rds.type_url).?.names[0]);
    try std.testing.expect(local.subscriptions.find(rds.type_url) == null);
    try std.testing.expectEqualStrings("published-cluster", remote.subscriptions.find(cds).?.names[0]);
    try std.testing.expect(local.stream == null and remote.stream == null);
    try std.testing.expectEqual(@as(usize, 1), hooks.commits);
    try std.testing.expectEqual(deadline.raw.nanoseconds, hooks.deadline.?.raw.nanoseconds);
    const revision = destination.configurationRevision();
    const next = try fixture.encode(gpa, .{ .route_name = next_name });
    defer gpa.free(next);
    var candidate = try update(is_delta, &local, "l2", next);
    defer candidate.deinit();
    hooks.fail_publish = true;
    try std.testing.expectError(error.InvalidSharedOptions, apply(is_delta, &controller, &local, candidate, destination, deadline));
    try std.testing.expectEqual(revision, destination.configurationRevision());
    try std.testing.expectEqualStrings(first_name, controller.listener.?.value.hcm.route_source.rds);
    try std.testing.expectEqualStrings(first_name, remote.subscriptions.find(rds.type_url).?.names[0]);
    try std.testing.expectEqualStrings("published-cluster", remote.subscriptions.find(cds).?.names[0]);
    try std.testing.expectEqual(@as(usize, 1), hooks.commits);
    try std.testing.expectEqual(@as(usize, 0), hooks.active);
    try std.testing.expectEqualStrings("l1", if (is_delta) local.acceptedVersion(lds.type_url, "frontend").? else local.acceptedVersion(lds.type_url).?);
    hooks.fail_publish = false;
    hooks.fail_prepare = true;
    const publications = hooks.publications;
    try std.testing.expectError(error.OutOfMemory, apply(is_delta, &controller, &local, candidate, destination, deadline));
    try std.testing.expectEqual(publications, hooks.publications);
    try std.testing.expectEqual(revision, destination.configurationRevision());
    hooks.fail_prepare = false;
    try std.testing.expectError(error.AdsNotConnected, apply(is_delta, &controller, &local, candidate, destination, deadline));
    try std.testing.expectEqualStrings(next_name, remote.subscriptions.find(rds.type_url).?.names[0]);
    try std.testing.expectEqualStrings(next_name, controller.listener.?.value.hcm.route_source.rds);
    if (is_delta) {
        var removed = try update(true, &local, "l3", null);
        defer removed.deinit();
        try std.testing.expectError(error.AdsNotConnected, apply(true, &controller, &local, removed, destination, deadline));
        try std.testing.expect(controller.listener == null);
        try std.testing.expectEqual(@as(usize, 0), remote.subscriptions.find(rds.type_url).?.names.len);
        var restored = try update(true, &local, "l4", first);
        defer restored.deinit();
        try std.testing.expectError(error.AdsNotConnected, apply(true, &controller, &local, restored, destination, deadline));
        try std.testing.expect(local.subscriptions.find(rds.type_url) == null);
        _ = try controller.expireListenerWithDeadline(&local, destination, deadline);
        try std.testing.expect(controller.listener == null);
        try std.testing.expectEqual(@as(usize, 0), remote.subscriptions.find(rds.type_url).?.names.len);
    }
    try std.testing.expectEqual(hooks.prepares, hooks.releases);
    try std.testing.expectEqualStrings("published-cluster", remote.subscriptions.find(cds).?.names[0]);
    try std.testing.expectEqual(@as(usize, 0), hooks.active);
}

test "SotW LDS routes its RDS dependency before publication and rolls it back on failure" {
    try routedListener(false);
}

test "delta LDS routes RDS updates removal and expiry through committed transactions" {
    try routedListener(true);
}
