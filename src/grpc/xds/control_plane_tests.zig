const std = @import("std");
const grpc = @import("../mod.zig");
const bootstrap = @import("bootstrap.zig");
const control = @import("control_plane.zig");
const delta = @import("ads/delta.zig");
const gpa = std.testing.allocator;
const cds = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

const Collector = struct {
    request: ?delta.codec.OwnedRequest = null,
    fn consume(self: *Collector, message: grpc.StreamingMessage) !void {
        if (self.request != null) return error.UnexpectedRequest;
        self.request = try delta.codec.decodeRequest(gpa, message.payload, .{});
    }
};

fn request(stream: anytype) !delta.codec.OwnedRequest {
    var collector: Collector = .{};
    errdefer if (collector.request) |*value| value.deinit();
    while (collector.request == null) {
        var event = try stream.readRequestEventWithTimeout(.fromSeconds(3), &collector, Collector.consume);
        defer event.deinit();
        if (event == .finished or event == .reset) return error.EndedEarly;
    }
    return collector.request.?;
}

fn expectReplay(duplex: anytype, node: []const u8) !void {
    var value = try request(duplex);
    defer value.deinit();
    try std.testing.expectEqualStrings(delta.path, duplex.transport.path);
    try std.testing.expect(value.value.node != null);
    try std.testing.expect(std.mem.indexOf(u8, value.value.node.?, node) != null);
    try std.testing.expectEqual(@as(usize, 1), value.value.subscribe.len);
    try std.testing.expectEqualStrings("a", value.value.subscribe[0]);
    try std.testing.expectEqual(@as(usize, 1), value.value.initial_versions.len);
    try std.testing.expectEqualStrings("a", value.value.initial_versions[0].name);
    try std.testing.expectEqualStrings("v1", value.value.initial_versions[0].version);
    try std.testing.expectEqualStrings("", value.value.nonce);
    try std.testing.expect(value.value.nack == null);
}

const Peer = struct {
    fn run(listener: *grpc.runtime.Server, node: []const u8, terminal: grpc.Status) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(3));
        defer connection.deinit();
        var duplex = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
        defer duplex.deinit();
        try expectReplay(&duplex, node);
        try duplex.startResponse(.{});
        if (terminal == .ok) try duplex.finishOk() else try duplex.finishWithOptions(.{ .status = terminal, .status_message = "restart" });
    }
};

fn seed(client: *delta.Client) !void {
    try client.setSubscription(cds, &.{"a"});
    const token = try client.subscriptions.received(.{ .type_url = cds, .nonce = "n1" });
    _ = try client.subscriptions.decide(cds, token, null, .{ .type_url = cds, .resources = &.{.{ .name = "a", .version = "v1", .resource = .{ .type_url = cds, .value = "one" } }} });
    client.disconnect();
}

test "gRPC xDS control plane fails over across a refused server" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const json = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"http://127.0.0.1:1\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}},{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"node\":{{\"id\":\"node-1\"}}}}", .{server.address().getPort()});
    defer gpa.free(json);
    const configuration = try bootstrap.parse(gpa, json, .{});
    defer configuration.deinit();
    const plane = try control.ControlPlane.init(gpa, io, configuration, .{});
    defer plane.deinit();
    try seed(plane.discovery());
    var task = io.async(Peer.run, .{ &server, "node-1", grpc.Status.ok });
    defer _ = task.cancel(io) catch {};
    try plane.connectWithDeadline(deadline(io));
    try std.testing.expectEqual(@as(u16, server.address().getPort()), plane.server().target.port);
    var event = try plane.discovery().nextWithDeadline(deadline(io));
    defer event.deinit();
    try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
    try task.await(io);
}

test "gRPC xDS control plane failover replays versions on the next server" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var first = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer first.deinit();
    var second = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer second.deinit();
    const json = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}},{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"node\":{{\"id\":\"node-1\"}}}}", .{ first.address().getPort(), second.address().getPort() });
    defer gpa.free(json);
    const configuration = try bootstrap.parse(gpa, json, .{});
    defer configuration.deinit();
    const plane = try control.ControlPlane.init(gpa, io, configuration, .{});
    defer plane.deinit();
    try seed(plane.discovery());
    var first_task = io.async(Peer.run, .{ &first, "node-1", grpc.Status.unavailable });
    defer _ = first_task.cancel(io) catch {};
    var second_task = io.async(Peer.run, .{ &second, "node-1", grpc.Status.ok });
    defer _ = second_task.cancel(io) catch {};
    try plane.connectWithDeadline(deadline(io));
    try std.testing.expectEqual(first.address().getPort(), plane.server().target.port);
    var terminal = try plane.discovery().nextWithDeadline(deadline(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, terminal.terminal.status);
    try plane.failoverWithDeadline(deadline(io));
    try std.testing.expectEqual(second.address().getPort(), plane.server().target.port);
    var recovered = try plane.discovery().nextWithDeadline(deadline(io));
    defer recovered.deinit();
    try std.testing.expectEqual(grpc.Status.ok, recovered.terminal.status);
    try first_task.await(io);
    try second_task.await(io);
}

test "gRPC xDS control plane requires a usable server and node" {
    const tls_only =
        \\{"xds_servers":[{"server_uri":"https://host","channel_creds":[{"type":"tls"}]}],"node":{"id":"node"}}
    ;
    const configuration = try bootstrap.parse(gpa, tls_only, .{});
    defer configuration.deinit();
    try std.testing.expectError(error.NoUsableXdsServer, control.ControlPlane.init(gpa, std.testing.io, configuration, .{}));

    const no_node =
        \\{"xds_servers":[{"server_uri":"http://127.0.0.1:1","channel_creds":[{"type":"insecure"}]}]}
    ;
    const no_node_config = try bootstrap.parse(gpa, no_node, .{});
    defer no_node_config.deinit();
    try std.testing.expectError(error.InvalidBootstrapNode, control.ControlPlane.init(gpa, std.testing.io, no_node_config, .{}));
}
