//! Full discovery chain starts with no application endpoint or manual child map.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const ads = @import("../ads.zig");
const lds = @import("../lds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const lds_fixture = @import("../lds/testing.zig");
const rds_fixture = @import("../rds/testing.zig");
const cds_fixture = @import("../cds/testing.zig");
const eds_fixture = @import("../eds/testing.zig");
const gpa = std.testing.allocator;
fn update(client: *ads.Client, url: []const u8, version: []const u8, resources: []const ads.codec.Any) !ads.Update {
    const encoded = try ads.codec.encodeResponse(gpa, .{ .type_url = url, .version = version, .nonce = version, .resources = resources }, 65536);
    defer gpa.free(encoded);
    var response = try ads.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}
fn accept(controller: *runtime.Controller, client: *ads.Client, channel: grpc.SharedChannel, io: std.Io, url: []const u8, version: []const u8, resources: []const ads.codec.Any) !void {
    var value = try update(client, url, version, resources);
    defer value.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(client, value, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
    try std.testing.expectEqualStrings(version, client.acceptedVersion(url).?);
}
test "gRPC xDS runtime discovers cluster children endpoints and service-name transitions atomically" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{ .{ .exact = "/demo.Service/Beta", .cluster = "b" }, .{ .prefix = "/", .cluster = "a" } }, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    try accept(controller, &client, channel, io, lds.type_url, "l1", &.{.{ .type_url = lds.type_url, .value = listener }});
    try std.testing.expectEqual(@as(usize, 2), controller.entries.items.len);
    try std.testing.expectEqualStrings("a", client.subscriptions.find(cds.type_url).?.names[0]);
    try std.testing.expectEqualStrings("b", client.subscriptions.find(cds.type_url).?.names[1]);
    try std.testing.expect(controller.entries.items[0].pending());
    const a = try cds_fixture.cluster(gpa, "a", "eds-a", "");
    defer gpa.free(a);
    const b = try cds_fixture.cluster(gpa, "b", "eds-b", "");
    defer gpa.free(b);
    try accept(controller, &client, channel, io, cds.type_url, "c1", &.{ .{ .type_url = cds.type_url, .value = a }, .{ .type_url = cds.type_url, .value = b } });
    try std.testing.expectEqualStrings("eds-a", client.subscriptions.find(eds.type_url).?.names[0]);
    try std.testing.expectEqualStrings("eds-b", client.subscriptions.find(eds.type_url).?.names[1]);
    const ea = try eds_fixture.encode(gpa, "eds-a", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }}, null);
    defer gpa.free(ea);
    const eb = try eds_fixture.encode(gpa, "eds-b", &.{.{ .region = "b", .endpoints = &.{.{ .port = 1002 }} }}, null);
    defer gpa.free(eb);
    try accept(controller, &client, channel, io, eds.type_url, "e1", &.{ .{ .type_url = eds.type_url, .value = ea }, .{ .type_url = eds.type_url, .value = eb } });
    try std.testing.expectEqual(@as(usize, 2), channel.configuredEndpointCount());
    try std.testing.expect(!controller.entries.items[0].pending() and !controller.entries.items[1].pending());
    const revision = channel.configurationRevision();
    var duplicate = try update(&client, cds.type_url, "bad", &.{ .{ .type_url = cds.type_url, .value = a }, .{ .type_url = cds.type_url, .value = a } });
    defer duplicate.deinit();
    try std.testing.expectError(error.DuplicateCdsResource, controller.applyWithDeadline(&client, duplicate, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
    try std.testing.expectEqual(revision, channel.configurationRevision());
    try std.testing.expectEqualStrings("c1", client.acceptedVersion(cds.type_url).?);
    const changed = try cds_fixture.cluster(gpa, "b", "eds-b2", "");
    defer gpa.free(changed);
    try accept(controller, &client, channel, io, cds.type_url, "c2", &.{ .{ .type_url = cds.type_url, .value = a }, .{ .type_url = cds.type_url, .value = changed } });
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expectEqualStrings("eds-b2", client.subscriptions.find(eds.type_url).?.names[1]);
    try std.testing.expect(controller.entries.items[1].pending());
    try accept(controller, &client, channel, io, eds.type_url, "e2", &.{ .{ .type_url = eds.type_url, .value = ea }, .{ .type_url = eds.type_url, .value = eb } });
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expect(!controller.entries.items[1].pending());
}
