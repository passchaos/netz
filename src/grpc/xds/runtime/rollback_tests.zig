//! One failed discovery transaction cannot partially commit names or caches.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const ads = @import("../ads.zig");
const lds = @import("../lds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const gpa = std.testing.allocator;
fn update(client: *ads.Client, url: []const u8, version: []const u8, resources: []const ads.codec.Any) !ads.Update {
    const encoded = try ads.codec.encodeResponse(gpa, .{ .type_url = url, .version = version, .nonce = version, .resources = resources }, 65536);
    defer gpa.free(encoded);
    var response = try ads.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}
test "gRPC xDS runtime transaction rollback preserves cluster snapshots subscriptions and versions" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    var channel = try grpc.SharedChannel.init(failing.allocator(), io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    const routes = try @import("../rds/testing.zig").encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try @import("../lds/testing.zig").encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var initial = try update(&client, lds.type_url, "l1", &.{.{ .type_url = lds.type_url, .value = listener }});
    defer initial.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(&client, initial, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
    const a = try @import("../cds/testing.zig").cluster(gpa, "a", "service-a", "");
    defer gpa.free(a);
    var first = try update(&client, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = a }});
    defer first.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(&client, first, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
    const before = channel.configurationRevision();
    const old_cluster = controller.entries.items[0].cluster.?;
    const old_snapshot = controller.entries.items[0].snapshot.?;
    const b = try @import("../cds/testing.zig").cluster(gpa, "a", "service-b", "");
    defer gpa.free(b);
    var candidate = try update(&client, cds.type_url, "c2", &.{.{ .type_url = cds.type_url, .value = b }});
    defer candidate.deinit();
    failing.fail_index = failing.alloc_index;
    const result = controller.applyWithDeadline(&client, candidate, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expectEqual(before, channel.configurationRevision());
    try std.testing.expect(controller.entries.items[0].cluster.? == old_cluster and controller.entries.items[0].snapshot.? == old_snapshot);
    try std.testing.expectEqualStrings("service-a", client.subscriptions.find(eds.type_url).?.names[0]);
    try std.testing.expectEqualStrings("c1", client.acceptedVersion(cds.type_url).?);
    try client.validateUpdate(candidate);
    try std.testing.expectError(error.Timeout, controller.applyWithDeadline(&client, candidate, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) })));
    try std.testing.expectEqual(before, channel.configurationRevision());
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(&client, candidate, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
    try std.testing.expectEqualStrings("service-b", client.subscriptions.find(eds.type_url).?.names[0]);
    try std.testing.expectEqualStrings("c2", client.acceptedVersion(cds.type_url).?);
}

test "gRPC xDS federated serving inventory storage budget rejects before cache and revision commit" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "budget" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" }, .disable_automatic_lrs = true });
    defer controller.deinit();
    controller.retain_valid_routes = true;
    _ = try controller.startWithDeadline(&client, channel, budgetDeadline(io));
    const routes = try @import("../rds/testing.zig").encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try @import("../lds/testing.zig").encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var initial = try update(&client, lds.type_url, "l1", &.{.{ .type_url = lds.type_url, .value = listener }});
    defer initial.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(&client, initial, channel, budgetDeadline(io)));
    const a = try @import("../cds/testing.zig").cluster(gpa, "a", "service-a", "");
    defer gpa.free(a);
    var first = try update(&client, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = a }});
    defer first.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(&client, first, channel, budgetDeadline(io)));
    const assignment = try @import("../cds/testing.zig").assignment(gpa, "service-a", "127.0.0.1", 1001);
    defer gpa.free(assignment);
    var endpoints = try update(&client, eds.type_url, "e1", &.{.{ .type_url = eds.type_url, .value = assignment }});
    defer endpoints.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(&client, endpoints, channel, budgetDeadline(io)));
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    const b = try @import("../cds/testing.zig").cluster(gpa, "a", "service-b", "");
    defer gpa.free(b);
    // Bound this candidate one byte below its simultaneous target/route/cache
    // arenas and candidate plus retained inventory backing allocations.
    const candidate_budget = blk: {
        var plan = try @import("plan.zig").Plan.create(controller, null);
        defer plan.deinit();
        var owned = try cds.decode(gpa, b, .{});
        const cluster = @import("entry.zig").Cluster.create(gpa, owned) catch |err| {
            owned.deinit();
            return err;
        };
        var installed = false;
        defer if (!installed) cluster.release();
        const empty = try controller.emptyEds(io, cluster);
        const item = &plan.entries.items[0];
        item.cluster.?.release();
        item.snapshot.?.release();
        item.cluster = cluster;
        item.snapshot = empty;
        item.eds_seen = false;
        installed = true;
        var view = try @import("serving.zig").View.prepare(controller, &plan, controller.latest.?);
        defer view.deinit();
        const target = try @import("target.zig").Target.createWithReporting(gpa, io, view.targetEntries(&plan), controller.local_json, true);
        defer target.release();
        var storage = plan.route_storage + target.arena.queryCapacity() + cluster.resource.arena.queryCapacity() + empty.resource.arena.queryCapacity();
        if (target.lrs_selection) |selection| storage += selection.arena.queryCapacity();
        const inventory_bytes = try view.storageBytes(controller);
        try std.testing.expect(inventory_bytes != 0);
        break :blk storage + inventory_bytes - 1;
    };
    const before = channel.configurationRevision();
    const old_cluster = controller.entries.items[0].cluster.?;
    const old_snapshot = controller.entries.items[0].snapshot.?;
    const old_served = controller.served_entries.items.ptr;
    const old_published = controller.published_entries.items.ptr;
    var candidate = try update(&client, cds.type_url, "c2", &.{.{ .type_url = cds.type_url, .value = b }});
    defer candidate.deinit();
    const original_budget = controller.options.limits.max_storage_bytes;
    defer controller.options.limits.max_storage_bytes = original_budget;
    controller.options.limits.max_storage_bytes = candidate_budget;
    try std.testing.expectError(error.XdsLimitExceeded, controller.applyWithDeadline(&client, candidate, channel, budgetDeadline(io)));
    try std.testing.expectEqual(before, channel.configurationRevision());
    try std.testing.expect(controller.entries.items[0].cluster.? == old_cluster and controller.entries.items[0].snapshot.? == old_snapshot);
    try std.testing.expect(controller.served_entries.items.ptr == old_served and controller.published_entries.items.ptr == old_published);
    try expectBudgetNames(client.subscriptions.find(eds.type_url).?.names, &.{"service-a"});
    try std.testing.expectEqualStrings("c1", client.acceptedVersion(cds.type_url).?);
    try client.validateUpdate(candidate);
    controller.options.limits.max_storage_bytes = original_budget;
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(&client, candidate, channel, budgetDeadline(io)));
    try std.testing.expect(channel.configurationRevision() > before);
    try expectBudgetNames(client.subscriptions.find(eds.type_url).?.names, &.{ "service-a", "service-b" });
    try std.testing.expectEqualStrings("c2", client.acceptedVersion(cds.type_url).?);
    const replacement = try @import("../cds/testing.zig").assignment(gpa, "service-b", "127.0.0.1", 1002);
    defer gpa.free(replacement);
    var ready = try update(&client, eds.type_url, "e2", &.{.{ .type_url = eds.type_url, .value = replacement }});
    defer ready.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(&client, ready, channel, budgetDeadline(io)));
    try std.testing.expect(!controller.entries.items[0].pending());
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    const ready_revision = channel.configurationRevision();
    try std.testing.expectError(error.AdsNotConnected, controller.synchronizeWithDeadline(&client, channel, budgetDeadline(io)));
    try std.testing.expectEqual(ready_revision, channel.configurationRevision());
    try expectBudgetNames(client.subscriptions.find(eds.type_url).?.names, &.{"service-b"});
    try std.testing.expectEqualStrings("e2", client.acceptedVersion(eds.type_url).?);
}

test "gRPC xDS federated cluster quota counts unique dependencies across retained route projections" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "quota" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" }, .disable_automatic_lrs = true, .limits = .{ .max_clusters = 2 } });
    defer controller.deinit();
    controller.retain_valid_routes = true;
    _ = try controller.startWithDeadline(&client, channel, budgetDeadline(io));

    const clusters = [_][]const []const u8{ &.{"a"}, &.{ "a", "b" }, &.{ "a", "b", "c" } };
    for (clusters, 0..) |names, index| {
        var routes: std.ArrayList(@import("../rds/testing.zig").Route) = .empty;
        defer routes.deinit(gpa);
        for (names) |name| try routes.append(gpa, .{ .prefix = "/", .cluster = name });
        const encoded_routes = try @import("../rds/testing.zig").encode(gpa, "inline", &.{"backend.test"}, routes.items, null);
        defer gpa.free(encoded_routes);
        const listener = try @import("../lds/testing.zig").encode(gpa, .{ .inline_rds = encoded_routes });
        defer gpa.free(listener);
        const version = switch (index) {
            0 => "l1",
            1 => "l2",
            else => "l3",
        };
        var candidate = try update(&client, lds.type_url, version, &.{.{ .type_url = lds.type_url, .value = listener }});
        defer candidate.deinit();
        if (index == 2) {
            const revision = channel.configurationRevision();
            try std.testing.expectError(error.XdsLimitExceeded, controller.applyWithDeadline(&client, candidate, channel, budgetDeadline(io)));
            try std.testing.expectEqual(revision, channel.configurationRevision());
            try std.testing.expectEqualStrings("l2", client.acceptedVersion(lds.type_url).?);
            try std.testing.expectEqual(@as(usize, 2), controller.entries.items.len);
        } else {
            try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(&client, candidate, channel, budgetDeadline(io)));
            try std.testing.expectEqualStrings(version, client.acceptedVersion(lds.type_url).?);
            const watches = client.subscriptions.find(cds.type_url).?.names;
            try std.testing.expectEqual(names.len, watches.len);
            for (names, watches) |expected, actual| try std.testing.expectEqualStrings(expected, actual);
        }
    }
}

fn budgetDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

fn expectBudgetNames(actual: []const []const u8, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected) |name| {
        const found = for (actual) |value| {
            if (std.mem.eql(u8, value, name)) break true;
        } else false;
        try std.testing.expect(found);
    }
}
