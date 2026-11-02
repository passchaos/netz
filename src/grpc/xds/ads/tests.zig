const std = @import("std");
const codec = @import("codec.zig");
const subscriptions = @import("subscriptions.zig");
const allocator = std.testing.allocator;

pub const cds = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
pub const eds = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";

test "gRPC ADS envelopes retain opaque resources and independent error metadata" {
    const node = try codec.encodeNode(allocator, .{ .id = "node-1", .cluster = "client", .locality = .{ .region = "r", .zone = "z", .sub_zone = "s" }, .client_features = &.{"envoy.lb.does_not_support_overprovisioning"} });
    defer allocator.free(node);
    const encoded = try codec.encodeRequest(allocator, .{ .type_url = cds, .node = node, .version = "v1", .nonce = "nonce", .names = &.{ "a", "b" }, .nack = .{ .message = "bad \xe2\x9c\x93" } }, 4096);
    defer allocator.free(encoded);
    var decoded = try codec.decodeRequest(allocator, encoded, 4096, 2);
    defer decoded.deinit();
    try std.testing.expectEqualStrings(cds, decoded.value.type_url);
    try std.testing.expectEqualSlices(u8, node, decoded.value.node.?);
    try std.testing.expectEqualStrings("v1", decoded.value.version);
    try std.testing.expectEqualStrings("nonce", decoded.value.nonce);
    try std.testing.expectEqual(@as(usize, 2), decoded.value.names.len);
    try std.testing.expectEqualStrings("bad \xe2\x9c\x93", decoded.value.nack.?.message);
    try std.testing.expectEqual(@import("../../wire.zig").Status.invalid_argument, decoded.value.nack.?.code);
    const response = try codec.encodeResponse(allocator, .{ .type_url = cds, .version = "v2", .nonce = "n2", .canary = true, .resources = &.{ .{ .type_url = cds, .value = "\x00\xff" }, .{ .type_url = eds, .value = "opaque" } } }, 4096);
    defer allocator.free(response);
    var owned = try codec.decodeResponse(allocator, response, .{});
    defer owned.deinit();
    try std.testing.expect(owned.value.canary);
    try std.testing.expectEqual(@as(usize, 2), owned.value.resources.len);
    try std.testing.expectEqualSlices(u8, "\x00\xff", owned.value.resources[0].value);
    try std.testing.expectEqualStrings(eds, owned.value.resources[1].type_url);
}

test "gRPC ADS codecs bound resource count bytes and malformed protobuf" {
    const encoded = try codec.encodeResponse(allocator, .{ .type_url = cds, .resources = &.{.{ .type_url = cds, .value = "1234" }} }, 4096);
    defer allocator.free(encoded);
    try std.testing.expectError(error.DiscoveryLimitExceeded, codec.decodeResponse(allocator, encoded, .{ .max_resources = 0 }));
    try std.testing.expectError(error.DiscoveryLimitExceeded, codec.decodeResponse(allocator, encoded, .{ .max_resource_bytes = 3 }));
    try std.testing.expectError(error.DiscoveryLimitExceeded, codec.decodeResponse(allocator, encoded, .{ .max_message_bytes = encoded.len - 1 }));
    try std.testing.expectError(error.InvalidDiscoveryMessage, codec.decodeResponse(allocator, "", .{}));
    try std.testing.expectError(error.TruncatedMessage, codec.decodeResponse(allocator, "\x22\x03a", .{}));
    try std.testing.expectError(error.InvalidUtf8, codec.decodeResponse(allocator, "\x22\x01\xff", .{}));
    // Unknown fields and explicit-last scalar strings follow protobuf rules.
    const final = "\x22\x01a\x22\x01b\x48\x01";
    var accepted = try codec.decodeResponse(allocator, final, .{});
    defer accepted.deinit();
    try std.testing.expectEqualStrings("b", accepted.value.type_url);
}

test "gRPC ADS state ACK NACK latest nonce and reconnect preserve the applied version" {
    var state = subscriptions.State{ .allocator = allocator, .options = .{} };
    defer state.deinit();
    var name = [_]u8{'b'};
    try state.set(cds, &.{ &name, "a" });
    name[0] = 'x';
    try std.testing.expectEqualStrings("a", state.find(cds).?.names[0]);
    try std.testing.expectEqualStrings("b", state.find(cds).?.names[1]);
    try state.set(eds, &.{}); // explicit wildcard subscription
    const first = try state.received(.{ .type_url = cds, .version = "v1", .nonce = "c1" });
    const endpoint = try state.received(.{ .type_url = eds, .version = "e1", .nonce = "e-n1" });
    _ = try state.decide(cds, first, null);
    _ = try state.decide(eds, endpoint, null);
    const failed = try state.received(.{ .type_url = cds, .version = "bad", .nonce = "c2" });
    _ = try state.decide(cds, failed, .{ .message = "invalid resource" });
    try std.testing.expectEqualStrings("v1", state.find(cds).?.version);
    try std.testing.expectEqualStrings("c2", state.find(cds).?.nonce);
    try std.testing.expectEqualStrings("invalid resource", state.find(cds).?.nack.?.message);
    const superseded = try state.received(.{ .type_url = cds, .version = "v2", .nonce = "c3" });
    const latest = try state.received(.{ .type_url = cds, .version = "v3", .nonce = "c4" });
    try std.testing.expectError(error.StaleDiscoveryResponse, state.decide(cds, superseded, null));
    _ = try state.decide(cds, latest, null);
    state.resetStream();
    try std.testing.expectEqualStrings("v3", state.find(cds).?.version);
    try std.testing.expectEqualStrings("e1", state.find(eds).?.version);
    try std.testing.expectEqualStrings("", state.find(cds).?.nonce);
    try std.testing.expect(state.find(cds).?.nack == null);
    try std.testing.expectError(error.StaleDiscoveryResponse, state.decide(cds, latest, null));
}

test "gRPC ADS allocation failure leaves desired and accepted state intact" {
    const Harness = struct {
        fn run(gpa: std.mem.Allocator) !void {
            var state = subscriptions.State{ .allocator = gpa, .options = .{} };
            defer state.deinit();
            try state.set(cds, &.{"a"});
            const token = try state.received(.{ .type_url = cds, .version = "v1", .nonce = "n1" });
            _ = try state.decide(cds, token, null);
            try state.set(cds, &.{ "a", "b" });
            const next = try state.received(.{ .type_url = cds, .version = "v2", .nonce = "n2" });
            _ = try state.decide(cds, next, .{ .message = "invalid resource" });
            const encoded = try codec.encodeResponse(gpa, .{ .type_url = cds, .version = "v3", .resources = &.{.{ .type_url = cds, .value = "\x00" }} }, 4096);
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

test "gRPC ADS response tokens cannot acknowledge another client with equal stream counters" {
    var first = subscriptions.State{ .allocator = allocator, .options = .{} };
    defer first.deinit();
    var second = subscriptions.State{ .allocator = allocator, .options = .{} };
    defer second.deinit();
    try first.set(cds, &.{"a"});
    try second.set(cds, &.{"a"});
    const token_a = try first.received(.{ .type_url = cds, .version = "a", .nonce = "n1" });
    const token_b = try second.received(.{ .type_url = cds, .version = "b", .nonce = "n2" });
    try std.testing.expectEqual(token_a.epoch, token_b.epoch);
    try std.testing.expectEqual(token_a.sequence, token_b.sequence);
    try std.testing.expectError(error.StaleDiscoveryResponse, second.decide(cds, token_a, null));
    try std.testing.expectEqualStrings("", second.find(cds).?.version);
    _ = try second.decide(cds, token_b, null);
    try std.testing.expectEqualStrings("b", second.find(cds).?.version);
}

test "gRPC ADS prepared subscriptions can roll back without changing pending response state" {
    var state = subscriptions.State{ .allocator = allocator, .options = .{} };
    defer state.deinit();
    try state.set(cds, &.{"original"});
    const token = try state.received(.{ .type_url = cds, .version = "c1", .nonce = "n1" });
    var aborted = try state.prepare(cds, &.{"discard"});
    aborted.deinit();
    try std.testing.expectEqualStrings("original", state.find(cds).?.names[0]);
    try state.validateToken(cds, token);
    var staged = try state.prepare(eds, &.{"endpoint"});
    defer staged.deinit();
    try std.testing.expect(state.find(eds) == null);
    staged.commit();
    try std.testing.expectEqualStrings("endpoint", state.find(eds).?.names[0]);
    _ = try state.decide(cds, token, null);
    var changed = try state.prepare(cds, &.{"changed"});
    defer changed.deinit();
    changed.commit();
    try std.testing.expectEqualStrings("c1", state.find(cds).?.version);
    try std.testing.expectEqualStrings("n1", state.find(cds).?.nonce);
}
