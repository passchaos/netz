//! Accepted CDS selects collection; LRS responses select the reported subset.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const lds = @import("../lds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const lrs = @import("../lrs.zig");
const stats = @import("../../channel/shared/lrs_stats.zig");
const cds_fixture = @import("../cds/testing.zig");
const gpa = std.testing.allocator;
const self_lrs = "\xd2\x02\x02\x2a\x00";
const Mode = enum { sotw, delta };
const Resource = struct { name: []const u8, bytes: []const u8 };

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

fn Harness(comptime mode: Mode) type {
    return struct {
        const Self = @This();
        const Client = if (mode == .sotw) ads.Client else delta.Client;
        const Update = if (mode == .sotw) ads.Update else delta.Update;
        io: std.Io,
        channel: grpc.SharedChannel,
        client: Client,
        controller: *runtime.Controller,

        fn init(io: std.Io, controller_allocator: std.mem.Allocator, channel_allocator: std.mem.Allocator) !Self {
            var channel = try grpc.SharedChannel.init(channel_allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{ .enable_lrs_stats = true });
            errdefer channel.deinit();
            var sender = channel.sender();
            defer sender.deinit();
            var client = try Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
            errdefer client.deinit();
            const controller = try runtime.Controller.create(controller_allocator, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
            errdefer controller.deinit();
            if (mode == .sotw) {
                _ = try controller.startWithDeadline(&client, channel, deadline(io));
            } else {
                _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));
            }
            return .{ .io = io, .channel = channel, .client = client, .controller = controller };
        }

        fn deinit(self: *Self) void {
            self.controller.deinit();
            self.client.deinit();
            self.channel.deinit();
        }

        fn update(self: *Self, url: []const u8, resource_version: []const u8, resources: []const Resource, removed: []const []const u8) !Update {
            const WireResource = if (mode == .sotw) ads.codec.Any else delta.codec.Resource;
            var wire_resources: [2]WireResource = undefined;
            for (resources, wire_resources[0..resources.len]) |resource, *wire| {
                if (mode == .sotw) {
                    wire.* = .{ .type_url = url, .value = resource.bytes };
                } else {
                    wire.* = .{ .name = resource.name, .version = resource_version, .resource = .{ .type_url = url, .value = resource.bytes } };
                }
            }
            const encoded = if (mode == .sotw)
                try ads.codec.encodeResponse(gpa, .{ .type_url = url, .version = resource_version, .nonce = resource_version, .resources = wire_resources[0..resources.len] }, 65536)
            else
                try delta.codec.encodeResponse(gpa, .{ .type_url = url, .nonce = resource_version, .resources = wire_resources[0..resources.len], .removed = removed }, .{});
            defer gpa.free(encoded);
            var response = if (mode == .sotw) try ads.codec.decodeResponse(gpa, encoded, .{}) else try delta.codec.decodeResponse(gpa, encoded, .{});
            errdefer response.deinit();
            return .{ .response = response, .token = try self.client.subscriptions.received(response.value) };
        }

        fn applyUpdate(self: *Self, value: Update) !u64 {
            return if (mode == .sotw)
                self.controller.applyWithDeadline(&self.client, value, self.channel, deadline(self.io))
            else
                self.controller.applyDeltaWithDeadline(&self.client, value, self.channel, deadline(self.io));
        }

        fn accept(self: *Self, url: []const u8, resource_version: []const u8, resources: []const Resource, removed: []const []const u8) !void {
            var value = try self.update(url, resource_version, resources, removed);
            defer value.deinit();
            try std.testing.expectError(error.AdsNotConnected, self.applyUpdate(value));
            for (resources) |resource| try std.testing.expectEqualStrings(resource_version, self.version(url, resource.name).?);
        }

        fn version(self: *Self, url: []const u8, name: []const u8) ?[]const u8 {
            return if (mode == .sotw) self.client.acceptedVersion(url) else self.client.acceptedVersion(url, name);
        }

        fn discover(self: *Self) !void {
            const routes = try @import("../rds/testing.zig").encode(gpa, "inline", &.{"backend.test"}, &.{ .{ .exact = "/demo.Service/Beta", .cluster = "b" }, .{ .prefix = "/", .cluster = "a" } }, null);
            defer gpa.free(routes);
            const listener = try @import("../lds/testing.zig").encode(gpa, .{ .inline_rds = routes });
            defer gpa.free(listener);
            try self.accept(lds.type_url, "l1", &.{.{ .name = "frontend", .bytes = listener }}, &.{});
        }

        fn begin(self: *Self, cluster_name: []const u8, service: []const u8) !stats.Registration {
            return self.channel.state.lrs_stats.begin(self.io, cluster_name, service, .{ .ip4 = .loopback(1001) }) orelse error.CollectionDisabled;
        }

        fn finish(self: *Self, registration: stats.Registration, success: bool) void {
            self.channel.state.lrs_stats.complete(self.io, registration, .{ .ip4 = .loopback(1001) }, success);
        }

        fn call(self: *Self, cluster_name: []const u8, service: []const u8) !void {
            const registration = try self.begin(cluster_name, service);
            defer registration.release();
            self.finish(registration, true);
        }

        fn disabled(self: *Self, cluster_name: []const u8, service: []const u8) !void {
            const registration = self.channel.state.lrs_stats.begin(self.io, cluster_name, service, null);
            defer if (registration) |value| value.release();
            try std.testing.expect(registration == null);
            self.channel.state.lrs_stats.recordDropped(self.io, cluster_name, service, "disabled-drop");
        }

        fn report(self: *Self, response: lrs.codec.Response) !lrs.codec.OwnedRequest {
            var sender = self.channel.sender();
            defer sender.deinit();
            var client = try lrs.Client.init(gpa, sender, .{ .node = .{ .id = "test", .client_features = &.{"envoy.lrs.supports_send_all_clusters"} } });
            defer client.deinit();
            var reporter = lrs.Reporter.init(gpa, &client, self.channel, .{});
            defer reporter.deinit();
            const response_bytes = try lrs.codec.encodeResponse(gpa, response, .{});
            defer gpa.free(response_bytes);
            var decoded_response = try lrs.codec.decodeResponse(gpa, response_bytes, .{});
            defer decoded_response.deinit();
            try reporter.onResponse(decoded_response.value);
            var snapshot = try self.channel.lrsStatsDeltaSnapshot(gpa);
            defer snapshot.deinit();
            var reports = try lrs.integration.buildWithOptions(gpa, &snapshot, .{ .region = "test" }, std.time.ns_per_s, reporter.filter, reporter.endpoint_granularity);
            defer reports.deinit();
            const encoded = try lrs.codec.encodeRequest(gpa, .{ .clusters = reports.clusters }, .{});
            defer gpa.free(encoded);
            return lrs.codec.decodeRequest(gpa, encoded, .{});
        }
    };
}

fn cluster(request: lrs.codec.Request, name: []const u8, service: []const u8) !lrs.codec.ClusterStats {
    for (request.clusters) |value| {
        if (std.mem.eql(u8, name, value.name) and std.mem.eql(u8, service, value.service_name)) return value;
    }
    return error.MissingClusterReport;
}

fn expectCall(value: lrs.codec.ClusterStats, success: bool) !void {
    try std.testing.expectEqual(std.time.ns_per_s, value.interval_ns);
    try std.testing.expectEqual(@as(usize, 1), value.localities.len);
    const locality = value.localities[0];
    try std.testing.expectEqualStrings("test", locality.locality.region);
    try std.testing.expectEqual(@as(u64, 1), locality.issued);
    try std.testing.expectEqual(@as(u64, @intFromBool(success)), locality.successful);
    try std.testing.expectEqual(@as(u64, @intFromBool(!success)), locality.error_requests);
    try std.testing.expectEqual(@as(u64, 0), locality.in_progress);
    try std.testing.expectEqual(@as(usize, 1), locality.endpoints.len);
    try std.testing.expectEqual(@as(u64, 1), locality.endpoints[0].issued);
    try std.testing.expectEqual(@as(u16, 1001), locality.endpoints[0].port);
}

fn runSelection(comptime mode: Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var h = try Harness(mode).init(threaded.io(), gpa, gpa);
    defer h.deinit();
    try h.discover();
    try h.disabled("a", "eds-a");
    try h.disabled("b", "eds-b");
    var initial = try h.report(.{ .send_all_clusters = true });
    defer initial.deinit();
    try std.testing.expectEqual(@as(usize, 0), initial.value.clusters.len);

    const a_off = try cds_fixture.cluster(gpa, "a", "eds-a", "");
    defer gpa.free(a_off);
    const b_off = try cds_fixture.cluster(gpa, "b", "eds-b", "");
    defer gpa.free(b_off);
    const a_on = try cds_fixture.cluster(gpa, "a", "eds-a", self_lrs);
    defer gpa.free(a_on);
    try h.accept(cds.type_url, "absent", &.{ .{ .name = "a", .bytes = a_off }, .{ .name = "b", .bytes = b_off } }, &.{});
    try h.disabled("a", "eds-a");
    try h.accept(cds.type_url, "enabled", &.{ .{ .name = "a", .bytes = a_on }, .{ .name = "b", .bytes = b_off } }, &.{});
    try h.call("a", "eds-a");
    try h.disabled("b", "eds-b");
    h.channel.state.lrs_stats.recordDropped(h.io, "a", "eds-a", "throttle");
    var selected = try h.report(.{ .clusters = &.{ "a", "b" }, .report_endpoint_granularity = true });
    defer selected.deinit();
    try std.testing.expectEqual(@as(usize, 1), selected.value.clusters.len);
    const a = try cluster(selected.value, "a", "eds-a");
    try expectCall(a, true);
    try std.testing.expectEqual(@as(u64, 1), a.total_dropped);
    try std.testing.expectEqual(@as(usize, 1), a.dropped.len);
    try std.testing.expectEqualStrings("throttle", a.dropped[0].category);
    try std.testing.expectEqual(@as(u64, 1), a.dropped[0].count);
    try h.call("a", "eds-a");
    var unrequested = try h.report(.{ .clusters = &.{"b"} });
    defer unrequested.deinit();
    try std.testing.expectEqual(@as(usize, 0), unrequested.value.clusters.len);
    try h.call("a", "eds-a");
    var all = try h.report(.{ .send_all_clusters = true, .report_endpoint_granularity = true });
    defer all.deinit();
    try std.testing.expectEqual(@as(usize, 1), all.value.clusters.len);
    try expectCall(try cluster(all.value, "a", "eds-a"), true);

    // A propagation-only delta must replace the accepted registration image,
    // while a call admitted before it retains its previous metric selection.
    const before_metrics = try h.begin("a", "eds-a");
    defer before_metrics.release();
    const a_metrics = try cds_fixture.cluster(gpa, "a", "eds-a", self_lrs ++ "\xca\x03\x0fcpu_utilization");
    defer gpa.free(a_metrics);
    try h.accept(cds.type_url, "metrics", &.{ .{ .name = "a", .bytes = a_metrics }, .{ .name = "b", .bytes = b_off } }, &.{});
    const accepted = for (h.controller.entries.items) |item| {
        if (!std.mem.eql(u8, item.identity.name, "a")) continue;
        const resource = item.cluster orelse return error.MissingAcceptedCds;
        break resource.resource.value;
    } else return error.MissingAcceptedCluster;
    try std.testing.expect(accepted.lrs_propagation.cpu_utilization);
    const published = h.channel.state.lrs_stats.selection orelse return error.MissingPublishedSelection;
    const identity = published.find("a", "eds-a") orelse return error.MissingPublishedIdentity;
    try std.testing.expect(identity.propagation.cpu_utilization);
    h.finish(before_metrics, true);
    h.channel.state.lrs_stats.recordRegisteredOrca(h.io, before_metrics, .{ .cpu_utilization = 0.9 });
    const with_metrics = try h.begin("a", "eds-a");
    defer with_metrics.release();
    const admitted_propagation = with_metrics.propagation orelse return error.MissingAdmittedPropagation;
    try std.testing.expect(admitted_propagation.cpu_utilization);
    h.finish(with_metrics, true);
    h.channel.state.lrs_stats.recordRegisteredOrca(h.io, with_metrics, .{ .cpu_utilization = 0.5 });
    {
        var sampled = try h.channel.lrsStatsSnapshot(gpa);
        defer sampled.deinit();
        const sample = for (sampled.entries) |entry| {
            if (std.mem.eql(u8, entry.cluster, "a") and std.mem.eql(u8, entry.service_name, "eds-a")) break entry.cpu_utilization;
        } else return error.MissingSampledIdentity;
        try std.testing.expectEqual(@as(u64, 1), sample.count);
        try std.testing.expectEqual(@as(f64, 0.5), sample.sum);
    }
    var metrics = try h.report(.{ .send_all_clusters = true });
    defer metrics.deinit();
    const locality_metrics = try cluster(metrics.value, "a", "eds-a");
    try std.testing.expectEqual(@as(usize, 1), locality_metrics.localities.len);
    const utilization = locality_metrics.localities[0].cpu_utilization orelse return error.MissingCpuMetricInEncodedReport;
    try std.testing.expectEqual(@as(u64, 1), utilization.count);
    try std.testing.expectEqual(@as(f64, 0.5), utilization.value);

    const held = try h.begin("a", "eds-a");
    defer held.release();
    try h.accept(cds.type_url, "disabled", &.{ .{ .name = "a", .bytes = a_off }, .{ .name = "b", .bytes = b_off } }, &.{});
    try h.disabled("a", "eds-a");
    h.finish(held, true);
    var completed = try h.report(.{ .send_all_clusters = true, .report_endpoint_granularity = true });
    defer completed.deinit();
    try std.testing.expectEqual(@as(usize, 1), completed.value.clusters.len);
    try expectCall(try cluster(completed.value, "a", "eds-a"), true);
    try std.testing.expectEqual(@as(u64, 0), completed.value.clusters[0].total_dropped);

    try h.accept(cds.type_url, "reenabled", &.{ .{ .name = "a", .bytes = a_on }, .{ .name = "b", .bytes = b_off } }, &.{});
    const old_identity = try h.begin("a", "eds-a");
    defer old_identity.release();
    const moved = try cds_fixture.cluster(gpa, "a", "eds-a2", self_lrs);
    defer gpa.free(moved);
    try h.accept(cds.type_url, "moved", &.{ .{ .name = "a", .bytes = moved }, .{ .name = "b", .bytes = b_off } }, &.{});
    const assignment = try cds_fixture.assignment(gpa, "eds-a2", "127.0.0.1", 1001);
    defer gpa.free(assignment);
    try h.accept(eds.type_url, "e2", &.{.{ .name = "eds-a2", .bytes = assignment }}, &.{});
    try h.disabled("a", "eds-a");
    h.finish(old_identity, true);
    try h.call("a", "eds-a2");
    var identities = try h.report(.{ .send_all_clusters = true, .report_endpoint_granularity = true });
    defer identities.deinit();
    try std.testing.expectEqual(@as(usize, 2), identities.value.clusters.len);
    try expectCall(try cluster(identities.value, "a", "eds-a"), true);
    try expectCall(try cluster(identities.value, "a", "eds-a2"), true);

    const deleted = try h.begin("a", "eds-a2");
    defer deleted.release();
    try h.accept(cds.type_url, "deleted", &.{.{ .name = "b", .bytes = b_off }}, &.{"a"});
    try h.disabled("a", "eds-a2");
    h.finish(deleted, false);
    var final = try h.report(.{ .send_all_clusters = true, .report_endpoint_granularity = true });
    defer final.deinit();
    try expectCall(try cluster(final.value, "a", "eds-a2"), false);
}

fn runRollback(comptime mode: Mode, comptime fail_controller: bool) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    var h = try Harness(mode).init(threaded.io(), if (fail_controller) failing.allocator() else gpa, if (fail_controller) gpa else failing.allocator());
    defer h.deinit();
    try h.discover();
    const a_on = try cds_fixture.cluster(gpa, "a", "eds-a", self_lrs);
    defer gpa.free(a_on);
    const b_off = try cds_fixture.cluster(gpa, "b", "eds-b", "");
    defer gpa.free(b_off);
    try h.accept(cds.type_url, "valid", &.{ .{ .name = "a", .bytes = a_on }, .{ .name = "b", .bytes = b_off } }, &.{});
    const revision = h.channel.configurationRevision();
    const selection = h.channel.state.lrs_stats.selection;
    const a_off = try cds_fixture.cluster(gpa, "a", "eds-a", "");
    defer gpa.free(a_off);
    const bad_b = try cds_fixture.cluster(gpa, "b", "eds-b", "\xd2\x02\x02\x1a\x00");
    defer gpa.free(bad_b);
    var bad = try h.update(cds.type_url, "nack", &.{ .{ .name = "a", .bytes = a_off }, .{ .name = "b", .bytes = bad_b } }, &.{});
    defer bad.deinit();
    try std.testing.expectError(error.UnsupportedCdsFeature, h.applyUpdate(bad));
    try std.testing.expect(selection == h.channel.state.lrs_stats.selection);
    try std.testing.expectEqual(revision, h.channel.configurationRevision());
    try std.testing.expectEqualStrings("valid", h.version(cds.type_url, "a").?);
    try h.call("a", "eds-a");
    try h.disabled("b", "eds-b");
    var nacked = try h.report(.{ .send_all_clusters = true, .report_endpoint_granularity = true });
    defer nacked.deinit();
    try std.testing.expectEqual(@as(usize, 1), nacked.value.clusters.len);
    try expectCall(try cluster(nacked.value, "a", "eds-a"), true);
    const b_on = try cds_fixture.cluster(gpa, "b", "eds-b", self_lrs);
    defer gpa.free(b_on);
    var candidate = try h.update(cds.type_url, "oom", &.{ .{ .name = "a", .bytes = a_off }, .{ .name = "b", .bytes = b_on } }, &.{});
    defer candidate.deinit();
    failing.fail_index = failing.alloc_index;
    const result = h.applyUpdate(candidate);
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expect(selection == h.channel.state.lrs_stats.selection);
    try std.testing.expectEqual(revision, h.channel.configurationRevision());
    try std.testing.expectEqualStrings("valid", h.version(cds.type_url, "a").?);
    try h.call("a", "eds-a");
    try h.disabled("b", "eds-b");
    var preserved = try h.report(.{ .send_all_clusters = true, .report_endpoint_granularity = true });
    defer preserved.deinit();
    try std.testing.expectEqual(@as(usize, 1), preserved.value.clusters.len);
    try expectCall(try cluster(preserved.value, "a", "eds-a"), true);
    try std.testing.expectError(error.AdsNotConnected, h.applyUpdate(candidate));
    try h.disabled("a", "eds-a");
    try h.call("b", "eds-b");
    var retried = try h.report(.{ .clusters = &.{"b"}, .report_endpoint_granularity = true });
    defer retried.deinit();
    try std.testing.expectEqual(@as(usize, 1), retried.value.clusters.len);
    try expectCall(try cluster(retried.value, "b", "eds-b"), true);
}

test "gRPC SotW CDS LRS selection controls encoded reports and retains admitted identities" {
    try runSelection(.sotw);
}
test "gRPC delta CDS LRS selection controls encoded reports and retains admitted identities" {
    try runSelection(.delta);
}
test "gRPC CDS LRS selection rolls back NACKs and controller or channel allocation failures" {
    inline for (.{ Mode.sotw, Mode.delta }) |mode| {
        try runRollback(mode, true);
        try runRollback(mode, false);
    }
}
