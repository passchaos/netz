//! Accepted delta subsets must describe the cache after a response-level NACK.
const std = @import("std");
const support = @import("partial_versions_testing.zig");
const gpa = support.gpa;

fn run(comptime kind: support.Kind) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var h = try support.Fixture.init(io, null);
    defer h.deinit();
    try h.seed(kind);
    h.controller.response_authority = "A";
    const old_a = h.find(0).cluster;
    const old_b = h.find(1).cluster;
    const old_a_snapshot = h.find(0).snapshot;
    const old_b_snapshot = h.find(1).snapshot;
    const foreign = h.find(2).clone();
    var foreign_owned = foreign;
    defer foreign_owned.deinit();
    const old_time = h.acceptedTime(kind, 2);
    const before = h.channel.configurationRevision();
    const generation = h.controller.resource_commit_generation;
    var payloads = try support.Payloads.init(kind, true);
    defer payloads.deinit();
    var mixed = try h.update(support.url(kind), "mixed", &payloads.resources, &.{});
    defer mixed.deinit();
    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    h.client.subscriptions.allocator = failing.allocator();
    defer h.client.subscriptions.allocator = gpa;
    const failed = h.apply(mixed);
    failing.fail_index = std.math.maxInt(usize);
    h.client.subscriptions.allocator = gpa;
    try std.testing.expectError(error.OutOfMemory, failed);
    try std.testing.expectEqual(before, h.channel.configurationRevision());
    try std.testing.expectEqual(generation, h.controller.resource_commit_generation);
    try std.testing.expect(h.find(0).cluster == old_a and h.find(1).cluster == old_b);
    try std.testing.expect(h.find(0).snapshot == old_a_snapshot and h.find(1).snapshot == old_b_snapshot);
    for (0..3) |index| try std.testing.expectEqualStrings("v1", h.client.acceptedVersion(support.url(kind), support.name(kind, index)).?);
    try std.testing.expectEqual(old_time, h.acceptedTime(kind, 2));
    try h.client.validateUpdate(mixed);
    const expected = if (kind == .cds) error.UnsupportedCdsPolicy else error.TruncatedMessage;
    try std.testing.expectError(expected, h.apply(mixed));
    try std.testing.expect(h.channel.configurationRevision() > before);
    try std.testing.expect(h.controller.resource_commit_generation > generation);
    try std.testing.expectEqualStrings("v2", h.client.acceptedVersion(support.url(kind), support.name(kind, 0)).?);
    try std.testing.expect(h.client.acceptedVersion(support.url(kind), support.name(kind, 1)) == null);
    try std.testing.expectEqualStrings("v1", h.client.acceptedVersion(support.url(kind), support.name(kind, 2)).?);
    try std.testing.expectEqual(old_time, h.acceptedTime(kind, 2));
    try std.testing.expect(h.find(2).cluster == foreign.cluster and h.find(2).snapshot == foreign.snapshot);
    switch (kind) {
        .cds => try std.testing.expect(h.find(1).cluster == null),
        .eds => try std.testing.expect(h.find(1).eds_seen),
        .sds => {
            try std.testing.expect(h.controller.sds_secrets.get(support.name(kind, 1)) == null);
            try std.testing.expect(h.find(1).cluster.?.sdsPending());
        },
    }
    try std.testing.expectEqual(@as(usize, 2), h.channel.configuredEndpointCount());
    try h.client.validateUpdate(mixed);
    try std.testing.expectError(error.AdsNotConnected, h.client.rejectWithDeadline(mixed, .{ .message = "invalid sibling" }, support.deadline(io)));
    const rejected = h.client.subscriptions.find(support.url(kind)).?;
    try std.testing.expectEqualStrings("mixed", rejected.nonce);
    try std.testing.expectEqualStrings("invalid sibling", rejected.error_detail.?.message);
    try std.testing.expect(rejected.pending_sequence == null and rejected.applied_sequence == null);
    try std.testing.expectEqualStrings("v2", h.client.acceptedVersion(support.url(kind), support.name(kind, 0)).?);
    try std.testing.expect(h.client.acceptedVersion(support.url(kind), support.name(kind, 1)) == null);
    {
        const kept = h.find(0).clone();
        var kept_owned = kept;
        defer kept_owned.deinit();
        const accepted_time = h.acceptedTime(kind, 0);
        var ignored = try h.update(support.url(kind), "foreign-and-policy", &.{payloads.resources[2]}, if (kind == .sds) &.{} else &.{support.name(kind, 0)});
        defer ignored.deinit();
        try std.testing.expectError(error.AdsNotConnected, h.apply(ignored));
        try std.testing.expect(h.find(0).cluster == kept.cluster and h.find(0).snapshot == kept.snapshot);
        try std.testing.expectEqualStrings("v2", h.client.acceptedVersion(support.url(kind), support.name(kind, 0)).?);
        try std.testing.expectEqual(accepted_time, h.acceptedTime(kind, 0));
        try std.testing.expectEqualStrings("v1", h.client.acceptedVersion(support.url(kind), support.name(kind, 2)).?);
        try std.testing.expectEqual(old_time, h.acceptedTime(kind, 2));
    }
}

test "gRPC delta partial CDS acceptance preserves scoped versions through NACK and version OOM" {
    try run(.cds);
}
test "gRPC delta partial EDS acceptance preserves scoped versions through NACK and version OOM" {
    try run(.eds);
}
test "gRPC delta partial SDS acceptance preserves scoped versions through NACK and version OOM" {
    try run(.sds);
}

test "gRPC delta partial payload acceptance time follows publication and heartbeat preserves it" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var h = try support.Fixture.init(io, null);
    defer h.deinit();
    try h.seed(.cds);
    h.controller.response_authority = "A";
    const foreign_time = h.acceptedTime(.cds, 2);
    var payloads = try support.Payloads.init(.cds, true);
    defer payloads.deinit();
    var mixed = try h.update(support.cds.type_url, "timed-mixed", &payloads.resources, &.{});
    defer mixed.deinit();
    const Probe = struct {
        controller: *support.runtime.Controller,
        before_generation: u64,
        before_ns: i96,
        after_ns: i96,
        stamp_generation: u64 = 0,
        published_reads: usize = 0,
        var active: ?*@This() = null;
        var fallback: ?*const fn (?*anyopaque, std.Io.Clock) std.Io.Timestamp = null;
        fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            const self = active orelse return fallback.?(userdata, clock);
            if (clock != .real) return fallback.?(userdata, clock);
            const generation = self.controller.resource_commit_generation;
            if (generation > self.before_generation) {
                self.stamp_generation = generation;
                self.published_reads += 1;
                return .fromNanoseconds(self.after_ns);
            }
            return .fromNanoseconds(self.before_ns);
        }
    };
    const before_ns = std.Io.Timestamp.now(io, .real).nanoseconds;
    var probe = Probe{ .controller = h.controller, .before_generation = h.controller.resource_commit_generation, .before_ns = before_ns, .after_ns = before_ns + 1000 };
    var table = io.vtable.*;
    table.now = Probe.now;
    Probe.fallback = io.vtable.now;
    Probe.active = &probe;
    h.channel.state.io = .{ .userdata = io.userdata, .vtable = &table };
    defer {
        h.channel.state.io = io;
        Probe.active = null;
    }
    // The clock reports distinct values across the actual cache-publication
    // boundary. Capturing a timestamp during preparation cannot pass this.
    try std.testing.expectError(error.UnsupportedCdsPolicy, h.apply(mixed));
    try std.testing.expect(probe.published_reads != 0);
    try std.testing.expectEqual(h.controller.resource_commit_generation, probe.stamp_generation);
    const committed_ns = h.acceptedTime(.cds, 0);
    try std.testing.expectEqual(@as(i128, probe.after_ns), committed_ns);
    try std.testing.expectEqual(foreign_time, h.acceptedTime(.cds, 2));
    try std.testing.expectError(error.AdsNotConnected, h.client.rejectWithDeadline(mixed, .{ .message = "invalid sibling" }, support.deadline(io)));
    probe.after_ns += 1000;
    var heartbeat = try h.update(support.cds.type_url, "timed-heartbeat", &.{.{ .name = support.name(.cds, 0), .version = "v2", .ttl = .{ .seconds = 1 } }}, &.{});
    defer heartbeat.deinit();
    try std.testing.expectError(error.AdsNotConnected, h.apply(heartbeat));
    try std.testing.expect(h.find(0).cds_deadline != null);
    try std.testing.expectEqualStrings("v2", h.client.acceptedVersion(support.cds.type_url, support.name(.cds, 0)).?);
    try std.testing.expectEqual(committed_ns, h.acceptedTime(.cds, 0));
    try std.testing.expectEqual(foreign_time, h.acceptedTime(.cds, 2));
}

test "gRPC SotW fail_on_data_errors overrides ignore deletion only for failed CDS names" {
    const ads = @import("../ads.zig");
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var data = try support.grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer data.deinit();
    var sender = data.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "precedence" } });
    defer client.deinit();
    const controller = try support.runtime.Controller.create(gpa, .{ .listener_name = "frontend", .authority = "A", .additional_authorities = &.{"B"}, .target = .{ .authority = "backend.test" }, .ignore_resource_deletion = true, .fail_on_data_errors = true, .disable_automatic_lrs = true });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, data, support.deadline(io));
    const listener = try support.listener();
    defer gpa.free(listener);
    try std.testing.expectError(error.AdsNotConnected, sotw(controller, &client, data, support.lds.type_url, "l1", &.{.{ .type_url = support.lds.type_url, .value = listener }}, io));
    var initial = try support.Payloads.init(.cds, false);
    defer initial.deinit();
    var initial_any: [3]ads.codec.Any = undefined;
    for (initial.resources, &initial_any) |resource, *any| any.* = resource.resource.?;
    try std.testing.expectError(error.AdsNotConnected, sotw(controller, &client, data, support.cds.type_url, "c1", &initial_any, io));
    try std.testing.expectEqual(@as(usize, 3), controller.entries.items.len);
    controller.response_authority = "A";
    const old_b = controller.entries.items[1].cluster;
    const foreign = controller.entries.items[2].cluster;
    // A genuine omission still honors ignore_resource_deletion.
    try std.testing.expectError(error.AdsNotConnected, sotw(controller, &client, data, support.cds.type_url, "omission", initial_any[0..1], io));
    try std.testing.expect(controller.entries.items[1].cluster == old_b);
    var mixed = try support.Payloads.init(.cds, true);
    defer mixed.deinit();
    var mixed_any: [3]ads.codec.Any = undefined;
    for (mixed.resources, &mixed_any) |resource, *any| any.* = resource.resource.?;
    const revision = data.configurationRevision();
    try std.testing.expectError(error.DuplicateCdsResource, sotw(controller, &client, data, support.cds.type_url, "duplicate", &.{ mixed_any[1], initial_any[1] }, io));
    try std.testing.expectEqual(revision, data.configurationRevision());
    try std.testing.expect(controller.entries.items[1].cluster == old_b);
    try std.testing.expectError(error.UnsupportedCdsPolicy, sotw(controller, &client, data, support.cds.type_url, "mixed", &mixed_any, io));
    try std.testing.expect(controller.entries.items[1].cluster == null);
    try std.testing.expect(controller.entries.items[2].cluster == foreign);
    try std.testing.expectEqual(@as(usize, 2), data.configuredEndpointCount());
}

fn sotw(controller: *support.runtime.Controller, client: *@import("../ads.zig").Client, data: support.grpc.SharedChannel, url: []const u8, nonce: []const u8, resources: []const @import("../ads.zig").codec.Any, io: std.Io) !u64 {
    const ads = @import("../ads.zig");
    const wire = try ads.codec.encodeResponse(gpa, .{ .type_url = url, .version = nonce, .nonce = nonce, .resources = resources }, 65536);
    defer gpa.free(wire);
    var response = try ads.codec.decodeResponse(gpa, wire, .{});
    defer response.deinit();
    return controller.applyWithDeadline(client, .{ .response = response, .token = try client.subscriptions.received(response.value) }, data, support.deadline(io));
}
