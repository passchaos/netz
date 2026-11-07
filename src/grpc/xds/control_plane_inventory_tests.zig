const std = @import("std");
const grpc = @import("../mod.zig");
const bootstrap = @import("bootstrap.zig");
const control = @import("control_plane.zig");
const delta = @import("ads/delta.zig");
const lrs = @import("lrs.zig");
const gpa = std.testing.allocator;
const cds = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

fn Peer(comptime is_lrs: bool) type {
    return struct {
        const Request = if (is_lrs) lrs.codec.OwnedRequest else delta.codec.OwnedRequest;
        const Collector = struct {
            request: ?Request = null,
            fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                self.request = if (is_lrs)
                    try lrs.codec.decodeRequest(gpa, message.payload, .{})
                else
                    try delta.codec.decodeRequest(gpa, message.payload, .{});
            }
        };
        fn run(listener: *grpc.runtime.Server) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var duplex = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer duplex.deinit();
            try std.testing.expectEqualStrings(if (is_lrs) lrs.path else delta.path, duplex.transport.path);
            var collector: Collector = .{};
            defer if (collector.request) |*value| value.deinit();
            while (collector.request == null) {
                var event = try duplex.readRequestEventWithTimeout(.fromSeconds(3), &collector, Collector.consume);
                defer event.deinit();
                if (event == .finished or event == .reset) return error.EndedEarly;
            }
            try std.testing.expect(collector.request.?.value.node != null);
            try duplex.startResponse(.{});
            try duplex.finishOk();
        }
    };
}

fn authorityInventory(comptime is_lrs: bool, top_level_usable: bool) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const json = try std.fmt.allocPrint(
        gpa,
        "{{\"xds_servers\":[{{\"server_uri\":\"http://127.0.0.1:1\",\"channel_creds\":[{{\"type\":\"{s}\"}}]}}],\"node\":{{\"id\":\"node\"}},\"authorities\":{{\"auth\":{{\"xds_servers\":[{{\"server_uri\":\"http://127.0.0.1:1\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}},{{\"server_uri\":\"http://127.0.0.1:2\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}},{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}]}}}}}}",
        .{ if (top_level_usable) @as([]const u8, "insecure") else "google_default", server.address().getPort() },
    );
    defer gpa.free(json);
    const configuration = try bootstrap.parse(gpa, json, .{});
    defer configuration.deinit();
    const plane = try control.ControlPlane.init(gpa, io, configuration, .{ .authority = "auth", .server_open_timeout = .fromMilliseconds(100) });
    defer plane.deinit();
    try std.testing.expectEqual(@as(usize, 3), plane.servers.len);
    var task = io.async(Peer(is_lrs).run, .{&server});
    defer _ = task.cancel(io) catch {};
    if (is_lrs) {
        var sender = plane.sender();
        defer sender.deinit();
        var client = try lrs.Client.init(gpa, sender, .{ .node = .{ .id = "node" } });
        defer client.deinit();
        try plane.failoverLrsWithTimeout(&client, .{ .path = lrs.path }, .fromSeconds(3));
        var terminal = try client.nextWithTimeout(.fromSeconds(3));
        defer terminal.deinit();
        try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);
    } else {
        try plane.discovery().setSubscription(cds, &.{"a"});
        try plane.connectWithTimeout(.fromSeconds(3));
        var terminal = try plane.discovery().nextWithTimeout(.fromSeconds(3));
        defer terminal.deinit();
        try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);
    }
    try std.testing.expectEqual(server.address().getPort(), plane.server().target.port);
    try std.testing.expectEqual(@as(usize, 2), plane.server_index);
    try std.testing.expectEqual(server.address().getPort(), plane.source.server.target.port);
    var factory = try plane.newSotwClient(.{ .node = .{ .id = "factory-node" } });
    defer factory.deinit();
    try std.testing.expectEqual(server.address().getPort(), factory.source.?.server.target.port);
    try std.testing.expectEqualStrings("factory-node", factory.source.?.node.id);
    try std.testing.expect(factory.stream == null);
    try task.await(io);
}

test "control plane ADS attempts every authority server despite unusable or refused top-level inventory" {
    try authorityInventory(false, false);
    try authorityInventory(false, true);
}

test "control plane LRS failover checks and bounds attempts by authority inventory" {
    try authorityInventory(true, false);
    try authorityInventory(true, true);
}

test "private pinned control plane owns one destination and leaves the ADS plane untouched" {
    const configuration = try bootstrap.parse(gpa, "{\"xds_servers\":[{\"server_uri\":\"http://127.0.0.1:1\",\"channel_creds\":[{\"type\":\"insecure\"}]},{\"server_uri\":\"http://127.0.0.1:2\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"node\":{\"id\":\"node\"}}", .{});
    defer configuration.deinit();
    const ads_plane = try control.ControlPlane.init(gpa, std.testing.io, configuration, .{});
    defer ads_plane.deinit();
    const ads_source = ads_plane.source;
    const ads_transport = ads_plane.channel.state;
    var caller = std.heap.ArenaAllocator.init(gpa);
    var caller_owned = true;
    defer if (caller_owned) caller.deinit();
    const arena = caller.allocator();
    const creds = try arena.alloc(bootstrap.Creds, 1);
    creds[0] = .{ .type = try arena.dupe(u8, "insecure"), .config_json = try arena.dupe(u8, "{\"pinned\":true}") };
    const server: bootstrap.Server = .{
        .uri = try arena.dupe(u8, "http://pinned.example:80"),
        .target = .{ .scheme = .http, .host = try arena.dupe(u8, "pinned.example"), .port = 80 },
        .channel_creds = creds,
        .server_features = &.{try arena.dupe(u8, "trusted_xds_server")},
    };
    const plane = try control.ControlPlane.init(gpa, std.testing.io, configuration, .{ .pinned_server = server });
    defer plane.deinit();
    caller.deinit();
    caller_owned = false;
    try std.testing.expect(plane.servers_owned);
    try std.testing.expectEqual(@as(usize, 1), plane.servers.len);
    try std.testing.expectEqualStrings("http://pinned.example:80", plane.serverUri());
    try std.testing.expectEqualStrings("pinned.example", plane.source.server.target.host);
    try std.testing.expectEqualStrings("{\"pinned\":true}", plane.source.server.channel_creds[0].config_json.?);
    try std.testing.expect(plane.discovery().stream == null);
    try std.testing.expectEqual(@as(usize, 0), plane.channel.state.queued);
    try plane.moveToNextServerWithTimeout(.fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 0), plane.server_index);
    try std.testing.expectEqualStrings("pinned.example", plane.server().target.host);
    try std.testing.expectEqualStrings("trusted_xds_server", plane.server().server_features[0]);
    try std.testing.expect(plane.discovery().stream == null);
    try std.testing.expect(ads_plane.source == ads_source and ads_plane.channel.state == ads_transport);
    try std.testing.expectEqual(@as(usize, 0), ads_plane.server_index);
}
