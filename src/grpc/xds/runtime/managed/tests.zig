//! Federated authority peers feed one managed publisher and data channel.
const std = @import("std");
const grpc = @import("../../../mod.zig");
const managed = @import("../managed.zig");
const bootstrap = @import("../../bootstrap.zig");
const tls_testing = @import("../../../../tls/testing.zig");
const test_tmp = @import("../../../../internal/test_tmp_dir.zig");
const lds = @import("../../lds.zig");
const rds = @import("../../rds.zig");
const cds = @import("../../cds.zig");
const eds = @import("../../eds.zig");
const entry = @import("../entry.zig");
const lds_fixture = @import("../../lds/testing.zig");
const rds_fixture = @import("../../rds/testing.zig");
const cds_fixture = @import("../../cds/testing.zig");
const testing = @import("testing.zig");
const gpa = std.testing.allocator;
const Mode = managed.Mode;

fn find(facade: anytype, name: []const u8) *entry.Entry {
    for (facade.controller.entries.items) |*value| if (std.mem.eql(u8, value.identity.name, name)) return value;
    @panic("missing federated cluster");
}
fn desired(facade: anytype, url: []const u8, name: []const u8) bool {
    for (facade.registry.desired.items) |watch| if (std.mem.eql(u8, watch.type_url, url)) {
        for (watch.values) |value| if (std.mem.eql(u8, value, name)) return true;
    };
    return false;
}
fn subscribed(client: anytype, url: []const u8, name: []const u8) bool {
    const subscription = client.subscriptions.find(url) orelse return false;
    for (subscription.names) |value| if (std.mem.eql(u8, value, name)) return true;
    return false;
}
fn expectEdsDependencies(facade: anytype, cluster: []const u8, endpoint: []const u8) !void {
    try std.testing.expect(desired(facade, cds.type_url, cluster));
    try std.testing.expect(desired(facade, eds.type_url, endpoint));
    const owner = try facade.registry.forName(endpoint);
    try std.testing.expect(subscribed(&owner.client, eds.type_url, endpoint));
    for (facade.registry.sessions.items) |session| {
        if (session == owner) continue;
        try std.testing.expect(!subscribed(&session.client, eds.type_url, endpoint));
    }
}
fn applyNext(comptime mode: Mode, facade: anytype, phase: []const u8, index: usize) !void {
    var event = facade.nextWithDeadline(testing.deadline(facade.io)) catch |err| {
        testing.report(mode, facade, phase, index, "next", err, "unknown", "unknown", "unknown");
        return err;
    };
    defer event.deinit();
    const value = event.result catch |err| {
        testing.report(mode, facade, phase, index, "event", err, event.session.authority, "unknown", "unknown");
        return err;
    };
    std.testing.expect(value == .update) catch |err| {
        testing.report(mode, facade, phase, index, "event-kind", err, event.session.authority, "terminal", "none");
        return err;
    };
    const response = value.update.response.value;
    std.debug.print("federated native mode={s} phase={s} step={d} authority={s} url={s} nonce={s}\n", .{ @tagName(mode), phase, index, event.session.authority, response.type_url, response.nonce });
    const source = value.update.source.?;
    std.testing.expectEqualStrings(event.session.control_plane.serverUri(), source.server.uri) catch |err| {
        testing.report(mode, facade, phase, index, "source-uri", err, event.session.authority, response.type_url, response.nonce);
        return err;
    };
    std.testing.expectEqualSlices(u8, event.session.client.source.?.key, source.key) catch |err| {
        testing.report(mode, facade, phase, index, "source-key", err, event.session.authority, response.type_url, response.nonce);
        return err;
    };
    _ = facade.applyWithDeadline(&event, testing.deadline(facade.io)) catch |err| {
        testing.report(mode, facade, phase, index, "apply", err, event.session.authority, response.type_url, response.nonce);
        return err;
    };
    for (facade.controller.entries.items) |item| if (item.cluster) |cluster| {
        if (cluster.resource.value.isEds()) expectEdsDependencies(facade, item.identity.name, cluster.resource.value.edsName()) catch |err| {
            std.debug.print("  missing EDS watch cluster={s} endpoint={s}\n", .{ item.identity.name, cluster.resource.value.edsName() });
            testing.report(mode, facade, phase, index, "eds-watch", err, event.session.authority, response.type_url, response.nonce);
            return err;
        };
    };
}
fn acceptOffline(comptime mode: Mode, facade: *managed.Managed(mode), step: testing.Step) !void {
    var event = try testing.offline(mode, facade, step);
    defer event.deinit();
    try std.testing.expectError(error.AdsNotConnected, facade.applyWithDeadline(&event, testing.deadline(facade.io)));
}

fn native(comptime mode: Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var control_a = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer control_a.deinit();
    var control_b = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer control_b.deinit();
    var backend_a = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer backend_a.deinit();
    var backend_b = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer backend_b.deinit();
    const config = try testing.configuration(control_a.address().getPort(), control_b.address().getPort());
    defer config.deinit();
    var data = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer data.deinit();
    const facade = try managed.Managed(mode).createForTarget(gpa, io, config, data, "xds://A/frontend", .{ .resolver = .{ .default_authority = "backend.test" } });
    var live = true;
    defer if (live) facade.deinit();
    try std.testing.expectEqualStrings(testing.listener, facade.controller.options.listener_name);
    var held_entered: std.Io.Event = .unset;
    var held_release: std.Io.Event = .unset;
    var peer_hold: std.Io.Event = .unset;
    var remove_a: std.Io.Event = .unset;
    var replace_routes: std.Io.Event = .unset;
    var finish_b2: std.Io.Event = .unset;
    var initial_a_ack: std.Io.Event = .unset;
    var initial_b_ack: std.Io.Event = .unset;
    var removed_ack: std.Io.Event = .unset;
    var replacement_ack: std.Io.Event = .unset;
    const listener = try lds_fixture.encode(gpa, .{ .name = testing.listener, .route_name = testing.routes });
    defer gpa.free(listener);
    const initial = try rds_fixture.encode(gpa, testing.routes, &.{"backend.test"}, &.{ .{ .exact = "/demo.Service/Beta", .cluster = testing.cluster_b }, .{ .prefix = "/", .cluster = testing.cluster_a } }, null);
    defer gpa.free(initial);
    const replacement = try rds_fixture.encode(gpa, testing.routes, &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = testing.cluster_b2 }}, null);
    defer gpa.free(replacement);
    const a = try cds_fixture.cluster(gpa, testing.cluster_a, testing.endpoint_a, "");
    defer gpa.free(a);
    const b = try cds_fixture.cluster(gpa, testing.cluster_b, testing.endpoint_b, "");
    defer gpa.free(b);
    const b2 = try cds_fixture.cluster(gpa, testing.cluster_b2, testing.endpoint_b2, "");
    defer gpa.free(b2);
    const ea = try cds_fixture.assignment(gpa, testing.endpoint_a, "127.0.0.1", backend_a.address().getPort());
    defer gpa.free(ea);
    const eb = try cds_fixture.assignment(gpa, testing.endpoint_b, "127.0.0.1", backend_b.address().getPort());
    defer gpa.free(eb);
    const eb2 = try cds_fixture.assignment(gpa, testing.endpoint_b2, "127.0.0.1", backend_b.address().getPort());
    defer gpa.free(eb2);
    const a_steps = [_]testing.Step{
        .{ .url = lds.type_url, .name = testing.listener, .version = "l1", .bytes = listener },
        .{ .url = cds.type_url, .name = testing.cluster_a, .version = "ca1", .bytes = a },
        .{ .url = eds.type_url, .name = testing.endpoint_a, .version = "ea1", .bytes = ea, .ack = &initial_a_ack },
        .{ .url = cds.type_url, .name = testing.cluster_a, .version = "ca-empty", .bytes = null, .trigger = false, .gate = &remove_a, .ack = &removed_ack },
    };
    const b_steps = [_]testing.Step{
        .{ .url = rds.type_url, .name = testing.routes, .version = "r1", .bytes = initial },
        .{ .url = cds.type_url, .name = testing.cluster_b, .version = "cb1", .bytes = b },
        .{ .url = eds.type_url, .name = testing.endpoint_b, .version = "eb1", .bytes = eb, .ack = &initial_b_ack },
        .{ .url = rds.type_url, .name = testing.routes, .version = "r2", .bytes = replacement, .trigger = false, .gate = &replace_routes },
        .{ .url = cds.type_url, .name = testing.cluster_b2, .version = "cb2", .bytes = b2, .extra = .{ .name = testing.cluster_b, .bytes = b } },
        .{ .url = eds.type_url, .name = testing.endpoint_b2, .version = "eb2", .bytes = eb2, .gate = &finish_b2, .ack = &replacement_ack },
    };
    var a_peer = io.async(testing.Peer(mode).run, .{ io, &control_a, "A", &a_steps, &peer_hold });
    defer _ = a_peer.cancel(io) catch {};
    var b_peer = io.async(testing.Peer(mode).run, .{ io, &control_b, "B", &b_steps, &peer_hold });
    defer _ = b_peer.cancel(io) catch {};
    var a_backend = io.async(testing.Backend.run, .{ io, &backend_a, "A", &.{3}, &held_entered, &held_release });
    defer _ = a_backend.cancel(io) catch {};
    var b_backend = io.async(testing.Backend.run, .{ io, &backend_b, "B", &.{ 3, 2 }, &held_entered, &held_release });
    defer _ = b_backend.cancel(io) catch {};
    _ = try facade.startWithDeadline(testing.deadline(io));
    for (0..6) |index| try applyNext(mode, facade, "initial", index);
    try testing.wait(io, &initial_a_ack);
    try testing.wait(io, &initial_b_ack);
    try std.testing.expectEqual(@as(usize, 2), facade.registry.sessions.items.len);
    const a_session = try facade.registry.forName(testing.cluster_a);
    const b_session = try facade.registry.forName(testing.cluster_b);
    try std.testing.expectEqualSlices(u8, a_session.client.source.?.key, find(facade, testing.cluster_a).cluster.?.discovery_source.?.key);
    try std.testing.expectEqualSlices(u8, b_session.client.source.?.key, find(facade, testing.cluster_b).cluster.?.discovery_source.?.key);
    try testing.call(data, "/demo.Service/Alpha", "ok", "A");
    try testing.call(data, "/demo.Service/Beta", "ok", "B");
    const a_cluster = find(facade, testing.cluster_a).cluster;
    const b_snapshot = find(facade, testing.cluster_b).snapshot;
    remove_a.set(io);
    try applyNext(mode, facade, "remove-a", 0);
    try testing.wait(io, &removed_ack);
    try std.testing.expect(find(facade, testing.cluster_a).cluster == a_cluster);
    try std.testing.expect(find(facade, testing.cluster_b).snapshot == b_snapshot);
    try std.testing.expect(!facade.controller.options.ignore_resource_deletion);
    try std.testing.expect(!facade.controller.options.trusted_xds_server);
    try testing.call(data, "/demo.Service/Beta", "ok", "B");
    const retained_revision = data.configurationRevision();
    replace_routes.set(io);
    try applyNext(mode, facade, "replacement", 0);
    try std.testing.expectEqual(retained_revision, data.configurationRevision());
    try applyNext(mode, facade, "replacement", 1);
    try std.testing.expectEqual(retained_revision, data.configurationRevision());
    try std.testing.expect(find(facade, testing.cluster_b2).pending());
    try std.testing.expect(find(facade, testing.cluster_a).cluster == a_cluster);
    try std.testing.expectEqualSlices(u8, a_session.client.source.?.key, find(facade, testing.cluster_a).cluster.?.discovery_source.?.key);
    try std.testing.expect(desired(facade, cds.type_url, testing.cluster_a));
    try std.testing.expect(desired(facade, cds.type_url, testing.cluster_b2));
    try testing.call(data, "/demo.Service/Alpha", "ok", "A");
    try testing.call(data, "/demo.Service/Beta", "ok", "B");
    var held_call = io.async(testing.call, .{ data, "/demo.Service/Alpha", "hold", "A" });
    defer _ = held_call.cancel(io) catch {};
    try testing.wait(io, &held_entered);
    finish_b2.set(io);
    try applyNext(mode, facade, "finish-b2", 0);
    try testing.wait(io, &replacement_ack);
    try std.testing.expect(data.configurationRevision() > retained_revision);
    try std.testing.expect(!find(facade, testing.cluster_b2).pending());
    try testing.call(data, "/demo.Service/Alpha", "ok", "B");
    try testing.call(data, "/demo.Service/Beta", "ok", "B");
    try std.testing.expect(desired(facade, cds.type_url, testing.cluster_a));
    try std.testing.expect(desired(facade, eds.type_url, testing.endpoint_a));
    held_release.set(io);
    try held_call.await(io);
    _ = try facade.synchronizeWithDeadline(testing.deadline(io));
    try std.testing.expect(!desired(facade, cds.type_url, testing.cluster_a));
    try std.testing.expect(!desired(facade, eds.type_url, testing.endpoint_a));
    try std.testing.expect(desired(facade, cds.type_url, testing.cluster_b2));
    if (mode == .delta) {
        try std.testing.expectEqual(@as(usize, 0), a_session.client.subscriptions.find(cds.type_url).?.names.len);
        try std.testing.expectEqual(@as(usize, 0), a_session.client.subscriptions.find(eds.type_url).?.names.len);
    }
    try a_backend.await(io);
    try b_backend.await(io);
    facade.deinit();
    live = false;
    peer_hold.set(io);
    try a_peer.await(io);
    try b_peer.await(io);
}

fn rollback(comptime mode: Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const config = try testing.configuration(1, 2);
    defer config.deinit();
    var data = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer data.deinit();
    const facade = try managed.Managed(mode).createForTarget(gpa, io, config, data, "xds://A/frontend", .{ .resolver = .{ .default_authority = "backend.test" } });
    defer facade.deinit();
    _ = try facade.startWithDeadline(testing.deadline(io));
    const listener = try lds_fixture.encode(gpa, .{ .name = testing.listener, .route_name = testing.routes });
    defer gpa.free(listener);
    try acceptOffline(mode, facade, .{ .url = lds.type_url, .name = testing.listener, .version = "l1", .bytes = listener });
    const routes = try rds_fixture.encode(gpa, testing.routes, &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = testing.cluster_a }}, null);
    defer gpa.free(routes);
    try acceptOffline(mode, facade, .{ .url = rds.type_url, .name = testing.routes, .version = "r1", .bytes = routes });
    const pending_projection = facade.controller.latest.?;
    try std.testing.expect(pending_projection != facade.controller.served_projection.?);
    try std.testing.expectEqual(@as(usize, 1), pending_projection.refs.load(.acquire));
    try std.testing.expect(desired(facade, cds.type_url, testing.cluster_a));
    try std.testing.expect(find(facade, testing.cluster_a).cluster == null);
    const a = try cds_fixture.cluster(gpa, testing.cluster_a, testing.endpoint_a, "");
    defer gpa.free(a);
    try acceptOffline(mode, facade, .{ .url = cds.type_url, .name = testing.cluster_a, .version = "ca1", .bytes = a });
    try std.testing.expect(facade.controller.latest.? == pending_projection);
    try std.testing.expect(facade.controller.served_projection.? != pending_projection);
    try expectEdsDependencies(facade, testing.cluster_a, testing.endpoint_a);
    const ea = try cds_fixture.assignment(gpa, testing.endpoint_a, "127.0.0.1", 1001);
    defer gpa.free(ea);
    try acceptOffline(mode, facade, .{ .url = eds.type_url, .name = testing.endpoint_a, .version = "ea1", .bytes = ea });
    try std.testing.expect(facade.controller.served_projection.? == pending_projection);
    try std.testing.expectEqual(@as(usize, 1), data.configuredEndpointCount());
    const a_session = try facade.registry.forName(testing.cluster_a);
    const b_session = try facade.registry.forName(testing.cluster_b);
    const projection = facade.controller.latest;
    const snapshot = find(facade, testing.cluster_a).snapshot;
    const revision = data.configurationRevision();
    const replacement = try rds_fixture.encode(gpa, testing.routes, &.{"backend.test"}, &.{ .{ .exact = "/demo.Service/Alpha", .cluster = "xdstp://A/envoy.config.cluster.v3.Cluster/a2" }, .{ .prefix = "/", .cluster = testing.cluster_b } }, null);
    defer gpa.free(replacement);
    var event = try testing.offline(mode, facade, .{ .url = rds.type_url, .name = testing.routes, .version = "r-failed", .bytes = replacement });
    defer event.deinit();
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    b_session.client.subscriptions.allocator = failing.allocator();
    defer b_session.client.subscriptions.allocator = gpa;
    failing.fail_index = failing.alloc_index;
    const result = facade.applyWithDeadline(&event, testing.deadline(io));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expectEqual(revision, data.configurationRevision());
    try std.testing.expect(facade.controller.latest == projection);
    try std.testing.expect(find(facade, testing.cluster_a).snapshot == snapshot);
    try std.testing.expectEqualStrings(testing.cluster_a, a_session.client.subscriptions.find(cds.type_url).?.names[0]);
    try std.testing.expectEqual(@as(usize, 1), a_session.client.subscriptions.find(cds.type_url).?.names.len);
    try std.testing.expect(b_session.client.subscriptions.find(cds.type_url) == null);
    try std.testing.expect(desired(facade, cds.type_url, testing.cluster_a));
    try std.testing.expect(!desired(facade, cds.type_url, testing.cluster_b));
    const version = if (mode == .sotw) b_session.client.acceptedVersion(rds.type_url) else b_session.client.acceptedVersion(rds.type_url, testing.routes);
    try std.testing.expectEqualStrings("r1", version.?);
    try std.testing.expectEqual(@as(usize, 0), facade.registry.pending_types);
    const count = facade.registry.sessions.items.len;
    try std.testing.expectError(error.InvalidControlPlaneOptions, facade.registry.forName("xdstp://unknown/envoy.config.cluster.v3.Cluster/other"));
    try std.testing.expectEqual(count, facade.registry.sessions.items.len);
    try std.testing.expectError(error.AdsNotConnected, facade.applyWithDeadline(&event, testing.deadline(io)));
    try std.testing.expect(desired(facade, cds.type_url, testing.cluster_b));
}

fn sourceFeatures(comptime mode: Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const config = try testing.configuration(1, 2);
    defer config.deinit();
    var data = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer data.deinit();
    const facade = try managed.Managed(mode).createForTarget(gpa, io, config, data, "xds://A/frontend", .{ .resolver = .{ .default_authority = "backend.test" } });
    defer facade.deinit();
    _ = try facade.startWithDeadline(testing.deadline(io));
    const listener = try lds_fixture.encode(gpa, .{ .name = testing.listener, .route_name = testing.routes });
    defer gpa.free(listener);
    try acceptOffline(mode, facade, .{ .url = lds.type_url, .name = testing.listener, .version = "l1", .bytes = listener });
    const routes = try rds_fixture.encode(gpa, testing.routes, &.{"backend.test"}, &.{ .{ .exact = "/demo.Service/Alpha", .cluster = testing.cluster_a }, .{ .prefix = "/", .cluster = testing.cluster_b } }, null);
    defer gpa.free(routes);
    try acceptOffline(mode, facade, .{ .url = rds.type_url, .name = testing.routes, .version = "r1", .bytes = routes });
    inline for (.{ .{ testing.cluster_a, testing.endpoint_a }, .{ testing.cluster_b, testing.endpoint_b } }) |pair| {
        const cluster = try cds_fixture.cluster(gpa, pair[0], pair[1], "");
        defer gpa.free(cluster);
        try acceptOffline(mode, facade, .{ .url = cds.type_url, .name = pair[0], .version = "c1", .bytes = cluster });
        try expectEdsDependencies(facade, pair[0], pair[1]);
        const assignment = try cds_fixture.assignment(gpa, pair[1], "127.0.0.1", 1001);
        defer gpa.free(assignment);
        try acceptOffline(mode, facade, .{ .url = eds.type_url, .name = pair[1], .version = "e1", .bytes = assignment });
    }
    const a = find(facade, testing.cluster_a);
    const a_cluster = a.cluster;
    const a_snapshot = a.snapshot;
    const a_source = a.cluster.?.discovery_source;
    try acceptOffline(mode, facade, .{ .url = cds.type_url, .name = testing.cluster_b, .version = "b-removed", .bytes = null });
    try std.testing.expect(find(facade, testing.cluster_b).cluster == null);
    try std.testing.expect(find(facade, testing.cluster_a).cluster == a_cluster);
    try std.testing.expect(find(facade, testing.cluster_a).snapshot == a_snapshot);
    try std.testing.expect(find(facade, testing.cluster_a).cluster.?.discovery_source == a_source);
    try acceptOffline(mode, facade, .{ .url = cds.type_url, .name = testing.cluster_a, .version = "a-ignored", .bytes = null });
    try std.testing.expect(find(facade, testing.cluster_a).cluster == a_cluster);
    try std.testing.expect(find(facade, testing.cluster_a).snapshot == a_snapshot);
    try std.testing.expect(find(facade, testing.cluster_b).cluster == null);
    try std.testing.expect(!facade.controller.options.ignore_resource_deletion);
    try std.testing.expect(!facade.controller.options.trusted_xds_server);
    try std.testing.expect(!facade.controller.listener.?.options.ignore_resource_deletion);
    try std.testing.expect(!facade.controller.listener.?.options.trusted_xds_server);
}

test "gRPC federated managed SotW routes native authorities and retains valid targets" {
    try native(.sotw);
}
test "gRPC federated managed delta routes native authorities and retains valid targets" {
    try native(.delta);
}
test "gRPC federated managed subscriptions roll back second-authority allocation failure" {
    try rollback(.sotw);
    try rollback(.delta);
}
test "gRPC federated managed source features isolate authority caches" {
    try sourceFeatures(.sotw);
    try sourceFeatures(.delta);
}

const RefreshPeer = struct {
    listener: *grpc.runtime.TlsServer,
    io: std.Io,
    second_accepted: std.atomic.Value(bool) = .init(false),
    release: std.Io.Event = .unset,

    fn run(self: *RefreshPeer) void {
        self.runFallible() catch |err| {
            std.debug.print(
                "managed refresh peer error: {s}\n",
                .{@errorName(err)},
            );
        };
    }

    fn runFallible(self: *RefreshPeer) !void {
        var first = try self.listener.acceptWithTimeout(.fromSeconds(3));
        defer first.deinit();
        var first_duplex = try first.acceptDuplexWithTimeout(
            .fromSeconds(3),
        );
        defer first_duplex.deinit();
        try readManagedRequest(&first_duplex);
        var second = try self.listener.acceptWithTimeout(.fromSeconds(3));
        self.second_accepted.store(true, .release);
        defer second.deinit();
        var second_duplex = try second.acceptDuplexWithTimeout(
            .fromSeconds(3),
        );
        defer second_duplex.deinit();
        try readManagedRequest(&second_duplex);
        // Keep the refreshed stream open until the caller has observed the
        // reconnect; closing first would race the subscription flush.
        self.release.waitTimeout(self.io, .{ .duration = .{
            .clock = .awake,
            .raw = .fromSeconds(5),
        } }) catch {};
    }
};

fn readManagedRequest(duplex: anytype) !void {
    const Collector = struct {
        seen: bool = false,
        fn consume(self: *@This(), _: grpc.StreamingMessage) !void {
            self.seen = true;
        }
    };
    var collector: Collector = .{};
    while (!collector.seen) {
        var event = try duplex.readRequestEventWithTimeout(
            .fromSeconds(3),
            &collector,
            Collector.consume,
        );
        defer event.deinit();
        if (event == .finished or event == .reset) return error.EndedEarly;
    }
}

test "gRPC federated managed refreshes TLS material between reads" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try grpc.runtime.TlsServer.listen(
        gpa,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .transport = .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } } },
    );
    defer server.deinit();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    const pem = try std.fmt.allocPrint(
        gpa,
        "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n",
        .{tls_testing.certificate_base64},
    );
    defer gpa.free(pem);
    try tmp.dir.writeFile(io, .{ .sub_path = "ca.pem", .data = pem });
    var ca_buffer: [256]u8 = undefined;
    const ca_path = try tmp.path(&ca_buffer, "ca.pem");
    const json = try std.fmt.allocPrint(
        gpa,
        "{{\"xds_servers\":[{{\"server_uri\":\"https://localhost:{d}\",\"channel_creds\":[{{\"type\":\"tls\",\"config\":{{\"ca_certificate_file\":\"{s}\",\"refresh_interval\":\"10s\"}}}}]}}],\"node\":{{\"id\":\"node-1\"}},\"authorities\":{{\"A\":{{\"xds_servers\":[{{\"server_uri\":\"https://localhost:{d}\",\"channel_creds\":[{{\"type\":\"tls\",\"config\":{{\"ca_certificate_file\":\"{s}\",\"refresh_interval\":\"10s\"}}}}]}}]}}}}}}",
        .{
            server.address().getPort(),
            ca_path,
            server.address().getPort(),
            ca_path,
        },
    );
    defer gpa.free(json);
    const config = try bootstrap.parse(gpa, json, .{});
    defer config.deinit();
    var data = try grpc.SharedChannel.init(
        gpa,
        io,
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } },
        .{},
    );
    defer data.deinit();
    const facade = try managed.Managed(.delta).createForTarget(
        gpa,
        io,
        config,
        data,
        "xds://A/frontend",
        .{},
    );
    defer facade.deinit();
    var peer = RefreshPeer{ .listener = &server, .io = io };
    var task = io.async(RefreshPeer.run, .{&peer});
    defer task.cancel(io);
    _ = try facade.startWithDeadline(.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(3),
    }));
    // Make the authority-A session active without waiting for a resource
    // publication; the refresh schedule only covers desired authorities.
    var staged = try facade.registry.router().prepare(
        &.{.{ .type_url = cds.type_url, .names = &.{
            "xdstp://A/envoy.config.cluster.v3.Cluster/a",
        } }},
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }),
    );
    defer staged.deinit();
    staged.commit();
    const session = try facade.registry.forAuthority("A");
    try std.testing.expect(facade.registry.active(session));
    try std.testing.expect(session.control_plane.refreshInterval() != null);
    try std.testing.expect(session.control_plane.nextRefreshDeadline() != null);
    // Establish the initial stream. The peer deliberately sends no response,
    // so this read expires at the caller deadline.
    var initial = try facade.nextWithDeadline(.fromNow(io, .{
        .clock = .awake,
        .raw = .fromMilliseconds(500),
    }));
    defer initial.deinit();
    try std.testing.expectError(error.Timeout, initial.result);
    // Force the schedule due; subsequent calls must reload TLS and reconnect.
    // A stale stream cancellation from the pre-reload read may surface as the
    // first event, so keep reading until the peer observes the new connect.
    const now = std.Io.Clock.Timestamp.now(io, .awake);
    session.control_plane.last_reload_ns =
        now.raw.nanoseconds - 11 * std.time.ns_per_s;
    session.control_plane.last_refresh_attempt_ns =
        session.control_plane.last_reload_ns;
    var attempts: usize = 0;
    while (attempts < 4) : (attempts += 1) {
        var refreshed = facade.nextWithDeadline(.fromNow(io, .{
            .clock = .awake,
            .raw = .fromMilliseconds(300),
        })) catch |err| {
            std.debug.print("refresh next error: {s}\n", .{@errorName(err)});
            return err;
        };
        defer refreshed.deinit();
        if (refreshed.result) |_| {} else |err| {
            if (err != error.Timeout) {
                std.debug.print(
                    "refresh read error: {s}\n",
                    .{@errorName(err)},
                );
                return err;
            }
        }
        if (peer.second_accepted.load(.acquire)) break;
    }
    try std.testing.expect(peer.second_accepted.load(.acquire));
    peer.release.set(io);
    task.await(io);
}
