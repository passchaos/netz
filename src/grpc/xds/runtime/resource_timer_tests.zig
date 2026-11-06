//! gRPC xDS initial resource timers and the `resource_timer_is_transient_error`
//! status surface.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const lds = @import("../lds.zig");
const rds = @import("../rds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const lds_fixture = @import("../lds/testing.zig");
const rds_fixture = @import("../rds/testing.zig");
const cds_fixture = @import("../cds/testing.zig");
const gpa = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

fn deltaUpdate(client: *delta.Client, url: []const u8, nonce: []const u8, resources: []const delta.codec.Resource) !delta.Update {
    const encoded = try delta.codec.encodeResponse(gpa, .{ .type_url = url, .nonce = nonce, .resources = resources }, .{});
    defer gpa.free(encoded);
    var response = try delta.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}

fn deltaPayload(url: []const u8, name: []const u8, version: []const u8, bytes: []const u8) delta.codec.Resource {
    return .{ .name = name, .version = version, .resource = .{ .type_url = url, .value = bytes } };
}

fn adsUpdate(client: *ads.Client, url: []const u8, version: []const u8, resources: []const ads.codec.Any) !ads.Update {
    const encoded = try ads.codec.encodeResponse(gpa, .{ .type_url = url, .version = version, .nonce = version, .resources = resources }, 65536);
    defer gpa.free(encoded);
    var response = try ads.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}

test "gRPC delta xDS resource timer reports does-not-exist or transient timeout" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    inline for (.{ false, true }) |transient| {
        var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
        defer channel.deinit();
        var sender = channel.sender();
        defer sender.deinit();
        var client = try delta.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
        defer client.deinit();
        const controller = try runtime.Controller.create(gpa, .{
            .listener_name = "frontend",
            .target = .{ .authority = "backend.test" },
            .resource_timer_timeout = .fromMilliseconds(5),
            .resource_timer_is_transient_error = transient,
        });
        defer controller.deinit();
        _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));

        try controller.pollResourceTimers(&client);
        try std.testing.expectEqual(runtime.ResourceStatus.requested, controller.resourceStatus(lds.type_url, "frontend").?);
        try std.testing.expect((try controller.nextResourceTimerExpiry(&client)) != null);

        try std.Io.sleep(io, .fromMilliseconds(10), .awake);
        try controller.pollResourceTimers(&client);
        const expected: runtime.ResourceStatus = if (transient) .timeout else .does_not_exist;
        try std.testing.expectEqual(expected, controller.resourceStatus(lds.type_url, "frontend").?);
        // The subscription remains desired but the timer is no longer armed.
        try std.testing.expect((try controller.nextResourceTimerExpiry(&client)) == null);
    }
}

test "gRPC delta xDS delivered listener clears its timer and registers its cluster" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try delta.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
        .resource_timer_timeout = .fromMilliseconds(5),
    });
    defer controller.deinit();
    _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var update = try deltaUpdate(&client, lds.type_url, "l1", &.{deltaPayload(lds.type_url, "frontend", "v1", listener)});
    defer update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, update, channel, deadline(io)));

    try controller.pollResourceTimers(&client);
    try std.testing.expectEqual(runtime.ResourceStatus.acked, controller.resourceStatus(lds.type_url, "frontend").?);
    // Publishing the inline routes subscribed CDS "a"; it is still pending.
    try std.testing.expectEqual(runtime.ResourceStatus.requested, controller.resourceStatus(cds.type_url, "a").?);
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    try controller.pollResourceTimers(&client);
    try std.testing.expectEqual(runtime.ResourceStatus.does_not_exist, controller.resourceStatus(cds.type_url, "a").?);
    try std.testing.expectEqual(runtime.ResourceStatus.acked, controller.resourceStatus(lds.type_url, "frontend").?);
}

test "gRPC delta xDS endpoint timer expires independently of its cluster" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    inline for (.{ false, true }) |transient| {
        var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
        defer channel.deinit();
        var sender = channel.sender();
        defer sender.deinit();
        var client = try delta.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
        defer client.deinit();
        const controller = try runtime.Controller.create(gpa, .{
            .listener_name = "frontend",
            .target = .{ .authority = "backend.test" },
            .resource_timer_timeout = .fromMilliseconds(5),
            .resource_timer_is_transient_error = transient,
        });
        defer controller.deinit();
        _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));

        const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
        defer gpa.free(routes);
        const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
        defer gpa.free(listener);
        var listener_update = try deltaUpdate(&client, lds.type_url, "l1", &.{deltaPayload(lds.type_url, "frontend", "v1", listener)});
        defer listener_update.deinit();
        try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, listener_update, channel, deadline(io)));

        const cluster = try cds_fixture.cluster(gpa, "a", "eds-a", "");
        defer gpa.free(cluster);
        var cluster_update = try deltaUpdate(&client, cds.type_url, "c1", &.{deltaPayload(cds.type_url, "a", "v1", cluster)});
        defer cluster_update.deinit();
        try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, cluster_update, channel, deadline(io)));

        try controller.pollResourceTimers(&client);
        try std.testing.expectEqual(runtime.ResourceStatus.acked, controller.resourceStatus(cds.type_url, "a").?);
        try std.testing.expectEqual(runtime.ResourceStatus.requested, controller.resourceStatus(eds.type_url, "eds-a").?);

        try std.Io.sleep(io, .fromMilliseconds(10), .awake);
        // The does-not-exist path publishes an empty EDS assignment; the
        // transient-error feature leaves the endpoint set pending.
        try std.testing.expectError(error.AdsNotConnected, controller.expireResourceTimersWithDeadline(&client, channel, deadline(io)));
        const expected: runtime.ResourceStatus = if (transient) .timeout else .does_not_exist;
        try std.testing.expectEqual(expected, controller.resourceStatus(eds.type_url, "eds-a").?);
        try std.testing.expectEqual(runtime.ResourceStatus.acked, controller.resourceStatus(cds.type_url, "a").?);
        var eds_seen = false;
        for (controller.entries.items) |entry| {
            if (std.mem.eql(u8, entry.identity.name, "a")) eds_seen = entry.eds_seen;
        }
        try std.testing.expectEqual(!transient, eds_seen);
    }
}

test "gRPC SotW xDS resource timer uses the same status surface" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
        .resource_timer_timeout = .fromMilliseconds(5),
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));

    try controller.pollResourceTimers(&client);
    try std.testing.expectEqual(runtime.ResourceStatus.requested, controller.resourceStatus(lds.type_url, "frontend").?);
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    try controller.pollResourceTimers(&client);
    try std.testing.expectEqual(runtime.ResourceStatus.does_not_exist, controller.resourceStatus(lds.type_url, "frontend").?);

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var update = try adsUpdate(&client, lds.type_url, "l1", &.{.{ .type_url = lds.type_url, .value = listener }});
    defer update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(&client, update, channel, deadline(io)));
    try controller.pollResourceTimers(&client);
    try std.testing.expectEqual(runtime.ResourceStatus.acked, controller.resourceStatus(lds.type_url, "frontend").?);
}

test "gRPC delta xDS real EDS delivery replaces a timed-out placeholder" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try delta.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
        .resource_timer_timeout = .fromMilliseconds(5),
    });
    defer controller.deinit();
    _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var listener_update = try deltaUpdate(&client, lds.type_url, "l1", &.{deltaPayload(lds.type_url, "frontend", "v1", listener)});
    defer listener_update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, listener_update, channel, deadline(io)));

    const cluster = try cds_fixture.cluster(gpa, "a", "eds-a", "");
    defer gpa.free(cluster);
    var cluster_update = try deltaUpdate(&client, cds.type_url, "c1", &.{deltaPayload(cds.type_url, "a", "v1", cluster)});
    defer cluster_update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, cluster_update, channel, deadline(io)));

    try controller.pollResourceTimers(&client);
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    try std.testing.expectError(error.AdsNotConnected, controller.expireResourceTimersWithDeadline(&client, channel, deadline(io)));
    try std.testing.expectEqual(runtime.ResourceStatus.does_not_exist, controller.resourceStatus(eds.type_url, "eds-a").?);

    const assignment = try cds_fixture.assignment(gpa, "eds-a", "127.0.0.1", 1001);
    defer gpa.free(assignment);
    var assignment_update = try deltaUpdate(&client, eds.type_url, "e1", &.{deltaPayload(eds.type_url, "eds-a", "v1", assignment)});
    defer assignment_update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, assignment_update, channel, deadline(io)));
    try controller.pollResourceTimers(&client);
    try std.testing.expectEqual(runtime.ResourceStatus.acked, controller.resourceStatus(eds.type_url, "eds-a").?);
}
