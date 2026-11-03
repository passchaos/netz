const std = @import("std");
const codec = @import("delta_codec.zig");
const sotw = @import("codec.zig");
const subscriptions = @import("delta_subscriptions.zig");
const allocator = std.testing.allocator;

pub const cds = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
pub const eds = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";

fn cluster(name: []const u8, version: []const u8, payload: []const u8) codec.Resource {
    return .{ .name = name, .version = version, .resource = .{ .type_url = cds, .value = payload } };
}

test "delta xDS envelopes round-trip request diffs, initial versions and resources" {
    const node = try sotw.encodeNode(allocator, .{ .id = "node-1", .cluster = "client" });
    defer allocator.free(node);
    const request = try codec.encodeRequest(allocator, .{
        .node = node,
        .type_url = cds,
        .subscribe = &.{ "a", "b" },
        .unsubscribe = &.{"c"},
        .initial_versions = &.{ .{ .name = "a", .version = "v1" }, .{ .name = "b", .version = "v2" } },
        .nonce = "n1",
        .nack = .{ .message = "bad \xe2\x9c\x93" },
    }, .{});
    defer allocator.free(request);
    var decoded = try codec.decodeRequest(allocator, request, .{});
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u8, node, decoded.value.node.?);
    try std.testing.expectEqualStrings(cds, decoded.value.type_url);
    try std.testing.expectEqual(@as(usize, 2), decoded.value.subscribe.len);
    try std.testing.expectEqualStrings("c", decoded.value.unsubscribe[0]);
    try std.testing.expectEqual(@as(usize, 2), decoded.value.initial_versions.len);
    try std.testing.expectEqualStrings("v1", decoded.value.initial_versions[0].version);
    try std.testing.expectEqualStrings("n1", decoded.value.nonce);
    try std.testing.expectEqualStrings("bad \xe2\x9c\x93", decoded.value.nack.?.message);

    const response = try codec.encodeResponse(allocator, .{
        .system_version = "s1",
        .type_url = cds,
        .nonce = "n2",
        .resources = &.{
            cluster("a", "v1", "\x00\xff"),
            .{ .name = "b", .version = "v2", .ttl = .{ .seconds = 3, .nanos = 500 }, .aliases = &.{"alias"} },
        },
        .removed = &.{"c"},
    }, .{});
    defer allocator.free(response);
    var owned = try codec.decodeResponse(allocator, response, .{});
    defer owned.deinit();
    try std.testing.expectEqualStrings("s1", owned.value.system_version);
    try std.testing.expectEqual(@as(usize, 2), owned.value.resources.len);
    try std.testing.expectEqualSlices(u8, "\x00\xff", owned.value.resources[0].resource.?.value);
    try std.testing.expect(owned.value.resources[1].resource == null);
    try std.testing.expectEqual(@as(u64, 3_000_000_500), try owned.value.resources[1].ttl.?.nanoseconds());
    try std.testing.expectEqualStrings("alias", owned.value.resources[1].aliases[0]);
    try std.testing.expectEqualStrings("c", owned.value.removed[0]);
}

fn putVarint(out: *std.ArrayList(u8), value: u64) !void {
    var remaining = value;
    while (remaining >= 128) : (remaining >>= 7) try out.append(allocator, @as(u8, @truncate(remaining)) | 0x80);
    try out.append(allocator, @intCast(remaining));
}

fn putBytes(out: *std.ArrayList(u8), field: u32, bytes: []const u8) !void {
    try putVarint(out, @as(u64, field) * 8 + 2);
    try putVarint(out, bytes.len);
    try out.appendSlice(allocator, bytes);
}

test "delta xDS codecs reject unsupported variants, duplicates and malformed bounds" {
    const response = try codec.encodeResponse(allocator, .{
        .type_url = cds,
        .resources = &.{ cluster("a", "v1", "1234"), cluster("a", "v2", "x") },
    }, .{});
    defer allocator.free(response);
    try std.testing.expectError(error.InvalidDiscoveryMessage, codec.decodeResponse(allocator, response, .{}));
    try std.testing.expectError(error.DiscoveryLimitExceeded, codec.decodeResponse(allocator, response, .{ .max_resources = 1 }));

    const single = try codec.encodeResponse(allocator, .{ .type_url = cds, .resources = &.{cluster("a", "v1", "1234")} }, .{});
    defer allocator.free(single);
    try std.testing.expectError(error.DiscoveryLimitExceeded, codec.decodeResponse(allocator, single, .{ .max_resource_bytes = 3 }));
    try std.testing.expectError(error.DiscoveryLimitExceeded, codec.decodeResponse(allocator, single, .{ .max_message_bytes = single.len - 1 }));
    try std.testing.expectError(error.InvalidDiscoveryMessage, codec.decodeResponse(allocator, "", .{}));
    try std.testing.expectError(error.TruncatedMessage, codec.decodeResponse(allocator, "\x22\x03a", .{}));

    const overlap = try codec.encodeResponse(allocator, .{ .type_url = cds, .resources = &.{cluster("a", "v1", "x")}, .removed = &.{"a"} }, .{});
    defer allocator.free(overlap);
    try std.testing.expectError(error.InvalidDiscoveryMessage, codec.decodeResponse(allocator, overlap, .{}));

    // A negative protobuf int64 encodes as a huge varint. The decoder rejects
    // it without letting the encoder produce an unrepresentable TTL.
    var duration: std.ArrayList(u8) = .empty;
    defer duration.deinit(allocator);
    try putVarint(&duration, 8);
    try putVarint(&duration, std.math.maxInt(u64));
    var resource: std.ArrayList(u8) = .empty;
    defer resource.deinit(allocator);
    try putBytes(&resource, 3, "a");
    try putBytes(&resource, 6, duration.items);
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    try putBytes(&raw, 4, cds);
    try putBytes(&raw, 2, resource.items);
    try std.testing.expectError(error.InvalidResourceTtl, codec.decodeResponse(allocator, raw.items, .{}));
    try std.testing.expectError(error.InvalidResourceTtl, (codec.Duration{ .seconds = std.math.maxInt(u64) }).nanoseconds());

    // removed_resource_names (field 8) and resource_errors (field 9) are
    // unsupported resource variants, not ignorable unknown fields.
    const variant = "\x22\x01x\x42\x05\x0a\x03bad";
    try std.testing.expectError(error.InvalidDiscoveryMessage, codec.decodeResponse(allocator, variant, .{}));
    const errors = "\x22\x01x\x4a\x02\x00\x00";
    try std.testing.expectError(error.InvalidDiscoveryMessage, codec.decodeResponse(allocator, errors, .{}));
}

test "delta xDS state applies per-resource versions, removals and heartbeats" {
    var state = subscriptions.State{ .allocator = allocator, .options = .{} };
    defer state.deinit();
    try state.set(cds, &.{ "b", "a" });
    try std.testing.expectEqualStrings("a", state.find(cds).?.names[0]);
    try std.testing.expectEqualStrings("b", state.find(cds).?.names[1]);
    const first = try state.received(.{ .type_url = cds, .nonce = "n1" });
    _ = try state.decide(cds, first, null, .{ .type_url = cds, .resources = &.{ cluster("a", "v1", "one"), cluster("b", "v2", "two") } });
    const entry = state.find(cds).?;
    try std.testing.expectEqual(@as(usize, 2), entry.versions.len);
    try std.testing.expectEqualStrings("v1", entry.versions[0].version);
    try std.testing.expectEqualStrings("v2", entry.versions[1].version);
    try std.testing.expectEqualStrings("n1", entry.nonce);

    // A heartbeat refreshes only the version; a removal deletes it.
    const second = try state.received(.{ .type_url = cds, .nonce = "n2" });
    _ = try state.decide(cds, second, null, .{ .type_url = cds, .resources = &.{.{ .name = "a", .version = "v3", .ttl = .{ .seconds = 1 } }}, .removed = &.{"b"} });
    const after = state.find(cds).?;
    try std.testing.expectEqual(@as(usize, 1), after.versions.len);
    try std.testing.expectEqualStrings("a", after.versions[0].name);
    try std.testing.expectEqualStrings("v3", after.versions[0].version);
    try std.testing.expectEqualStrings("n2", after.nonce);

    // Unsolicited resources are applied by the caller but are not reconnect
    // state for a name that is no longer desired.
    try state.set(cds, &.{"a"});
    const third = try state.received(.{ .type_url = cds, .nonce = "n3" });
    _ = try state.decide(cds, third, null, .{ .type_url = cds, .resources = &.{cluster("zz", "v9", "x")} });
    try std.testing.expectEqual(@as(usize, 1), state.find(cds).?.versions.len);

    // A NACK retains every accepted version and keeps the response nonce.
    const failed = try state.received(.{ .type_url = cds, .nonce = "n4" });
    _ = try state.decide(cds, failed, .{ .message = "invalid resource" }, .{ .type_url = cds });
    const rejected = state.find(cds).?;
    try std.testing.expectEqualStrings("v3", rejected.versions[0].version);
    try std.testing.expectEqualStrings("n4", rejected.nonce);
    try std.testing.expectEqualStrings("invalid resource", rejected.error_detail.?.message);
    try std.testing.expectError(error.StaleDiscoveryResponse, state.decide(cds, failed, null, .{ .type_url = cds }));
}

test "delta xDS reconnect retains accepted versions and invalidates pending decisions" {
    var state = subscriptions.State{ .allocator = allocator, .options = .{} };
    defer state.deinit();
    try state.set(cds, &.{"a"});
    const token = try state.received(.{ .type_url = cds, .nonce = "n1" });
    _ = try state.decide(cds, token, null, .{ .type_url = cds, .resources = &.{cluster("a", "v1", "one")} });
    try std.testing.expectEqualStrings("v1", state.find(cds).?.versions[0].version);
    state.resetStream();
    const entry = state.find(cds).?;
    try std.testing.expectEqualStrings("", entry.nonce);
    try std.testing.expect(!entry.stream_started);
    try std.testing.expectEqualStrings("v1", entry.versions[0].version);
    try std.testing.expect(entry.subscribe.items.len == 0);
    try std.testing.expectError(error.StaleDiscoveryResponse, state.decide(cds, token, null, .{ .type_url = cds }));
}

test "delta xDS allocation failure leaves desired and accepted state intact" {
    const Harness = struct {
        fn run(gpa: std.mem.Allocator) !void {
            var state = subscriptions.State{ .allocator = gpa, .options = .{} };
            defer state.deinit();
            try state.set(cds, &.{"a"});
            const first = try state.received(.{ .type_url = cds, .nonce = "n1" });
            _ = try state.decide(cds, first, null, .{ .type_url = cds, .resources = &.{cluster("a", "v1", "one")} });
            try state.set(cds, &.{ "a", "b" });
            const second = try state.received(.{ .type_url = cds, .nonce = "n2" });
            _ = try state.decide(cds, second, .{ .message = "invalid resource" }, .{ .type_url = cds });
            const encoded = try codec.encodeResponse(gpa, .{ .type_url = cds, .nonce = "n3", .resources = &.{cluster("b", "v2", "\x00")} }, .{});
            defer gpa.free(encoded);
            var response = try codec.decodeResponse(gpa, encoded, .{});
            defer response.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{});

    var state = subscriptions.State{ .allocator = allocator, .options = .{ .max_types = 1, .max_names_per_type = 2, .max_name_bytes = 128 } };
    defer state.deinit();
    try state.set(cds, &.{"a"});
    try std.testing.expectError(error.InvalidDiscoveryMessage, state.set(cds, &.{ "b", "b" }));
    try std.testing.expectEqualStrings("a", state.find(cds).?.names[0]);
    try std.testing.expectError(error.DiscoveryTypeLimit, state.set(eds, &.{}));
    try std.testing.expectError(error.DiscoveryLimitExceeded, state.set(cds, &.{ "a", "b", "c" }));
}

test "delta xDS response tokens cannot acknowledge another client" {
    var first = subscriptions.State{ .allocator = allocator, .options = .{} };
    defer first.deinit();
    var second = subscriptions.State{ .allocator = allocator, .options = .{} };
    defer second.deinit();
    try first.set(cds, &.{"a"});
    try second.set(cds, &.{"a"});
    const token_a = try first.received(.{ .type_url = cds, .nonce = "n1" });
    const token_b = try second.received(.{ .type_url = cds, .nonce = "n2" });
    try std.testing.expectEqual(token_a.epoch, token_b.epoch);
    try std.testing.expectEqual(token_a.sequence, token_b.sequence);
    try std.testing.expectError(error.StaleDiscoveryResponse, second.decide(cds, token_a, null, .{ .type_url = cds }));
    _ = try second.decide(cds, token_b, null, .{ .type_url = cds, .resources = &.{cluster("a", "v2", "two")} });
    try std.testing.expectEqualStrings("v2", second.find(cds).?.versions[0].version);
}
