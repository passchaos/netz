//! Prepared maps survive subscription relocation and retain response decisions.
const std = @import("std");
const state_module = @import("delta_subscriptions.zig");
const codec = @import("delta_codec.zig");
const gpa = std.testing.allocator;
const cds = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
fn resource(name: []const u8, version: []const u8) codec.Resource {
    return .{ .name = name, .version = version, .resource = .{ .type_url = cds, .value = "payload" } };
}

test "delta prepared accepted versions survive subscription relocation without deciding NACK" {
    var state = state_module.State{ .allocator = gpa, .options = .{} };
    defer state.deinit();
    try state.set(cds, &.{ "a", "b", "c" });
    const initial = codec.Response{ .type_url = cds, .nonce = "first", .resources = &.{ resource("a", "v1"), resource("b", "v1"), resource("c", "v1") } };
    const first = try state.received(initial);
    const accepted = try state.decide(cds, first, null, initial);
    state_module.State.markAccepted(accepted, initial, 11);
    const response = codec.Response{ .type_url = cds, .nonce = "mixed", .resources = &.{ resource("a", "v2"), resource("b", "bad"), resource("c", "foreign") } };
    const token = try state.received(response);
    var prepared = try state.prepareAppliedVersions(cds, token, response, &.{"a"}, &.{"b"}, &.{ "a", "b", "c" }, 22);
    defer prepared.deinit();
    // A publication's subscription batches replace entries and can relocate
    // their containing array. The version commit must re-find by owned type.
    try state.set(cds, &.{ "a", "b", "c" });
    for (0..8) |index| {
        const url = try std.fmt.allocPrint(gpa, "type.googleapis.com/test.Type{d}", .{index});
        defer gpa.free(url);
        try state.set(url, &.{"other"});
    }
    prepared.commit();
    try state.validateToken(cds, token);
    try std.testing.expect(state.versionsApplied(cds, token));
    const current = state.find(cds).?;
    try std.testing.expectEqualStrings("mixed", current.nonce);
    try std.testing.expectEqual(@as(usize, 2), current.versions.len);
    try std.testing.expectEqualStrings("a", current.versions[0].name);
    try std.testing.expectEqualStrings("v2", current.versions[0].version);
    try std.testing.expectEqual(@as(i128, 22), current.versions[0].accepted_ns);
    try std.testing.expectEqualStrings("c", current.versions[1].name);
    try std.testing.expectEqualStrings("v1", current.versions[1].version);
    try std.testing.expectEqual(@as(i128, 11), current.versions[1].accepted_ns);
    _ = try state.decide(cds, token, .{ .message = "invalid b" }, response);
    try std.testing.expectEqualStrings("v2", state.find(cds).?.versions[0].version);
    try std.testing.expectEqualStrings("v1", state.find(cds).?.versions[1].version);
    try std.testing.expectEqualStrings("invalid b", state.find(cds).?.error_detail.?.message);
    state.resetStream();
    try std.testing.expectEqual(@as(usize, 2), state.find(cds).?.versions.len);
}

test "delta prepared accepted version allocation failures preserve the current map and token" {
    const Scenario = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var state = state_module.State{ .allocator = allocator, .options = .{} };
            defer state.deinit();
            try state.set(cds, &.{ "a", "b" });
            const initial = codec.Response{ .type_url = cds, .nonce = "first", .resources = &.{ resource("a", "v1"), resource("b", "v1") } };
            const first = try state.received(initial);
            _ = try state.decide(cds, first, null, initial);
            const response = codec.Response{ .type_url = cds, .nonce = "mixed", .resources = &.{ resource("a", "v2"), resource("b", "bad") } };
            const token = try state.received(response);
            var patch = state.prepareAppliedVersions(cds, token, response, &.{"a"}, &.{"b"}, &.{ "a", "b" }, 22) catch |err| {
                try std.testing.expectEqual(@as(usize, 2), state.find(cds).?.versions.len);
                try std.testing.expectEqualStrings("v1", state.find(cds).?.versions[0].version);
                try std.testing.expectEqualStrings("v1", state.find(cds).?.versions[1].version);
                try state.validateToken(cds, token);
                return err;
            };
            defer patch.deinit();
            patch.commit();
            try state.validateToken(cds, token);
            try std.testing.expectEqual(@as(usize, 1), state.find(cds).?.versions.len);
            try std.testing.expectEqualStrings("v2", state.find(cds).?.versions[0].version);
        }
    };
    try std.testing.checkAllAllocationFailures(gpa, Scenario.run, .{});
}

test "delta prepared heartbeat preserves payload acceptance time at commit" {
    var state = state_module.State{ .allocator = gpa, .options = .{} };
    defer state.deinit();
    try state.set(cds, &.{"a"});
    const initial = codec.Response{ .type_url = cds, .nonce = "first", .resources = &.{resource("a", "v1")} };
    const first = try state.received(initial);
    state_module.State.markAccepted(try state.decide(cds, first, null, initial), initial, 11);
    const heartbeat = codec.Response{ .type_url = cds, .nonce = "heartbeat", .resources = &.{.{ .name = "a", .version = "v1", .ttl = .{ .seconds = 1 } }} };
    const token = try state.received(heartbeat);
    var prepared = try state.prepareAppliedVersions(cds, token, heartbeat, &.{"a"}, &.{}, &.{"a"}, 22);
    defer prepared.deinit();
    prepared.commitAt(heartbeat, &.{"a"}, 33);
    try state.validateToken(cds, token);
    try std.testing.expectEqualStrings("v1", state.find(cds).?.versions[0].version);
    try std.testing.expectEqual(@as(i128, 11), state.find(cds).?.versions[0].accepted_ns);
    _ = try state.decide(cds, token, null, heartbeat);
    try std.testing.expectEqual(@as(i128, 11), state.find(cds).?.versions[0].accepted_ns);
}
