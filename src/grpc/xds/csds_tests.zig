//! CSDS response encoding from the runtime controller.
const std = @import("std");
const grpc = @import("../mod.zig");
const runtime = @import("runtime.zig");
const ads = @import("ads.zig");
const delta = @import("ads/delta.zig");
const lds = @import("lds.zig");
const rds = @import("rds.zig");
const cds = @import("cds.zig");
const eds = @import("eds.zig");
const lds_fixture = @import("lds/testing.zig");
const rds_fixture = @import("rds/testing.zig");
const cds_fixture = @import("cds/testing.zig");
const pb = @import("lds/protobuf.zig");
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

const Info = struct {
    type_url: []const u8 = "",
    name: []const u8 = "",
    version: []const u8 = "",
    status: u64 = 0,
    has_config: bool = false,
};

fn collect(allocator: std.mem.Allocator, encoded: []const u8) ![]Info {
    var list: std.ArrayList(Info) = .empty;
    errdefer list.deinit(allocator);
    var reader = pb.Reader{ .bytes = encoded };
    while (try reader.next()) |field| {
        if (field.number != 1 or field.wire_type != 2) {
            try reader.skip(field);
            continue;
        }
        var client = pb.Reader{ .bytes = try reader.bytesValue() };
        while (try client.next()) |client_field| {
            if (client_field.number != 3 or client_field.wire_type != 2) {
                try client.skip(client_field);
                continue;
            }
            var generic = pb.Reader{ .bytes = try client.bytesValue() };
            var info: Info = .{};
            while (try generic.next()) |generic_field| {
                switch (generic_field.number) {
                    1 => info.type_url = try generic.string(),
                    2 => info.name = try generic.string(),
                    3 => info.version = try generic.string(),
                    4 => {
                        info.has_config = true;
                        try generic.skip(generic_field);
                    },
                    7 => info.status = try generic.varint(),
                    else => try generic.skip(generic_field),
                }
            }
            try list.append(allocator, info);
        }
    }
    return list.toOwnedSlice(allocator);
}

fn find(list: []const Info, type_url: []const u8, name: []const u8) ?Info {
    for (list) |info| {
        if (std.mem.eql(u8, info.type_url, type_url) and std.mem.eql(u8, info.name, name)) return info;
    }
    return null;
}

test "gRPC delta xDS CSDS dump reports accepted LDS RDS CDS and EDS resources" {
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
    });
    defer controller.deinit();
    _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));

    const listener = try lds_fixture.encode(gpa, .{ .route_name = "routes" });
    defer gpa.free(listener);
    var listener_update = try deltaUpdate(&client, lds.type_url, "l1", &.{deltaPayload(lds.type_url, "frontend", "v1", listener)});
    defer listener_update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, listener_update, channel, deadline(io)));

    const routes = try rds_fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    var routes_update = try deltaUpdate(&client, rds.type_url, "r1", &.{deltaPayload(rds.type_url, "routes", "v1", routes)});
    defer routes_update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, routes_update, channel, deadline(io)));

    const cluster = try cds_fixture.cluster(gpa, "a", "eds-a", "");
    defer gpa.free(cluster);
    var cluster_update = try deltaUpdate(&client, cds.type_url, "c1", &.{deltaPayload(cds.type_url, "a", "v1", cluster)});
    defer cluster_update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, cluster_update, channel, deadline(io)));

    const assignment = try cds_fixture.assignment(gpa, "eds-a", "127.0.0.1", 1001);
    defer gpa.free(assignment);
    var assignment_update = try deltaUpdate(&client, eds.type_url, "e1", &.{deltaPayload(eds.type_url, "eds-a", "v1", assignment)});
    defer assignment_update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, assignment_update, channel, deadline(io)));

    const encoded = try controller.encodeClientStatus(&client, gpa, .{ .node = "\x0a\x06node-1" });
    defer gpa.free(encoded);
    const configs = try collect(gpa, encoded);
    defer gpa.free(configs);
    try std.testing.expectEqual(@as(usize, 4), configs.len);
    inline for (.{
        .{ lds.type_url, "frontend" },
        .{ rds.type_url, "routes" },
        .{ cds.type_url, "a" },
        .{ eds.type_url, "eds-a" },
    }) |expected| {
        const info = find(configs, expected[0], expected[1]) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("v1", info.version);
        try std.testing.expectEqual(@as(u64, 3), info.status); // ACKED
    }
}

test "gRPC SotW xDS CSDS dump reports the accepted type version" {
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
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var update = try adsUpdate(&client, lds.type_url, "v1", &.{.{ .type_url = lds.type_url, .value = listener }});
    defer update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(&client, update, channel, deadline(io)));

    const encoded = try controller.encodeClientStatus(&client, gpa, .{});
    defer gpa.free(encoded);
    const configs = try collect(gpa, encoded);
    defer gpa.free(configs);
    // The listener is accepted; publishing its inline routes subscribed CDS
    // "a", which has not been delivered yet and therefore reports REQUESTED.
    try std.testing.expectEqual(@as(usize, 2), configs.len);
    const listener_info = find(configs, lds.type_url, "frontend") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("v1", listener_info.version);
    try std.testing.expectEqual(@as(u64, 3), listener_info.status); // ACKED
    const pending = find(configs, cds.type_url, "a") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("", pending.version);
    try std.testing.expectEqual(@as(u64, 1), pending.status); // REQUESTED
    try std.testing.expect(listener_info.has_config);
    try std.testing.expect(!pending.has_config);

    // exclude_resource_contents (ClientStatusRequest field 3) removes wire
    // bytes but keeps the accepted type, name, version and status.
    const excluded = try controller.fetchClientStatus(&client, gpa, "\x18\x01", .{});
    defer gpa.free(excluded);
    const excluded_configs = try collect(gpa, excluded);
    defer gpa.free(excluded_configs);
    const excluded_listener = find(excluded_configs, lds.type_url, "frontend") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("v1", excluded_listener.version);
    try std.testing.expectEqual(@as(u64, 3), excluded_listener.status);
    try std.testing.expect(!excluded_listener.has_config);

    // Node matchers are ignored, and malformed request bytes are rejected.
    const with_matcher = try controller.fetchClientStatus(&client, gpa, "\x0a\x02\x08\x01", .{});
    defer gpa.free(with_matcher);
    try std.testing.expectError(error.InvalidRequest, controller.fetchClientStatus(&client, gpa, "\x0f", .{}));
}
