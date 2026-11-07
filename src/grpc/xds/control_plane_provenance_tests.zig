const std = @import("std");
const grpc = @import("../mod.zig");
const bootstrap = @import("bootstrap.zig");
const control = @import("control_plane.zig");
const ads = @import("ads.zig");
const delta = ads.delta;
const Source = @import("discovery_source.zig").Source;
const tls_testing = @import("../../tls/testing.zig");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const gpa = std.testing.allocator;
const cds = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

fn Peer(comptime is_delta: bool) type {
    return struct {
        const Request = if (is_delta) delta.codec.OwnedRequest else ads.codec.OwnedRequest;
        const Collector = struct {
            request: ?Request = null,
            fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                self.request = if (is_delta)
                    try delta.codec.decodeRequest(gpa, message.payload, .{})
                else
                    try ads.codec.decodeRequest(gpa, message.payload, 4096, 8);
            }
        };
        fn run(listener: *grpc.runtime.Server, expected_node: []const u8) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var duplex = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer duplex.deinit();
            try std.testing.expectEqualStrings(if (is_delta) delta.path else ads.path, duplex.transport.path);
            var collector: Collector = .{};
            defer if (collector.request) |*value| value.deinit();
            while (collector.request == null) {
                var event = try duplex.readRequestEventWithTimeout(.fromSeconds(3), &collector, Collector.consume);
                defer event.deinit();
                if (event == .finished or event == .reset) return error.EndedEarly;
            }
            try std.testing.expectEqualSlices(u8, expected_node, collector.request.?.value.node.?);
            try duplex.startResponse(.{});
            const bytes = if (is_delta)
                try delta.codec.encodeResponse(gpa, .{ .type_url = cds, .nonce = "n1", .resources = &.{.{ .name = "a", .version = "v1", .resource = .{ .type_url = cds, .value = "cluster" } }} }, .{})
            else
                try ads.codec.encodeResponse(gpa, .{ .type_url = cds, .nonce = "n1", .version = "v1", .resources = &.{.{ .type_url = cds, .value = "cluster" }} }, 4096);
            defer gpa.free(bytes);
            try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try duplex.writeMessage(bytes));
            try duplex.finishOk();
        }
    };
}

fn retainedUpdate(comptime is_delta: bool) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const json = try std.fmt.allocPrint(
        gpa,
        "{{\"xds_servers\":[{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\",\"config\":{{\"tag\":\"credential\"}}}}]}},{{\"server_uri\":\"http://127.0.0.1:1\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"node\":{{\"id\":\"bootstrap-node\"}},\"certificate_providers\":{{\"roots\":{{\"plugin_name\":\"file_watcher\",\"config\":{{\"ca_certificate_file\":\"retained-roots.pem\"}}}}}}}}",
        .{server.address().getPort()},
    );
    defer gpa.free(json);
    const configuration = try bootstrap.parse(gpa, json, .{});
    var configuration_owned = true;
    defer if (configuration_owned) configuration.deinit();
    var caller = std.heap.ArenaAllocator.init(gpa);
    var caller_owned = true;
    defer if (caller_owned) caller.deinit();
    const arena = caller.allocator();
    const node: ads.codec.Node = .{
        .id = try arena.dupe(u8, "actual-node"),
        .cluster = try arena.dupe(u8, "actual-cluster"),
        .metadata = try arena.dupe(u8, ""),
        .locality = .{ .region = try arena.dupe(u8, "region"), .zone = try arena.dupe(u8, "zone"), .sub_zone = try arena.dupe(u8, "sub-zone") },
        .user_agent_name = try arena.dupe(u8, "agent"),
        .user_agent_version = try arena.dupe(u8, "version"),
        .client_features = &.{try arena.dupe(u8, "custom-feature")},
    };
    const request: grpc.StreamingRequestOptions = .{ .path = "/caller", .metadata = &.{.{ .name = try arena.dupe(u8, "x-origin"), .value = try arena.dupe(u8, "original") }} };
    const plane = try control.ControlPlane.init(gpa, io, configuration, .{ .node = node, .request = request });
    var plane_owned = true;
    defer if (plane_owned) plane.deinit();
    var client = if (is_delta)
        try plane.newDeltaClient(.{ .node = node, .request = request })
    else
        try plane.newSotwClient(.{ .node = node, .request = request });
    var client_owned = true;
    defer if (client_owned) client.deinit();
    configuration.deinit();
    configuration_owned = false;
    caller.deinit();
    caller_owned = false;
    try std.testing.expectEqualSlices(u8, plane.source.node_bytes, client.node);
    const original = client.source.?;
    try std.testing.expectEqualSlices(u8, original.node_bytes, client.node);
    var task = io.async(Peer(is_delta).run, .{ &server, original.node_bytes });
    defer _ = task.cancel(io) catch {};
    try client.setSubscription(cds, &.{"a"});
    try client.connectWithDeadline(deadline(io));
    var event = try client.nextWithDeadline(deadline(io));
    defer event.deinit();
    try std.testing.expect(event == .update);
    try std.testing.expect(event.update.source.? == original);
    try client.acceptAppliedUpdate(event.update);
    try task.await(io);
    try plane.moveToNextServerWithTimeout(.fromSeconds(1));
    try std.testing.expectEqualStrings("actual-node", plane.source.node.id);
    try std.testing.expectEqualStrings("original", plane.source.request.metadata[0].value);
    if (is_delta)
        try plane.rebindDelta(&client, .{ .path = "/new", .metadata = &.{.{ .name = "x-origin", .value = "rebound" }} })
    else
        try plane.rebindSotw(&client, .{ .path = "/new", .metadata = &.{.{ .name = "x-origin", .value = "rebound" }} });
    try std.testing.expect(client.source.? != original);
    try std.testing.expectEqual(@as(u16, 1), client.source.?.server.target.port);
    try std.testing.expectEqualSlices(u8, original.node_bytes, client.source.?.node_bytes);
    try std.testing.expectEqualStrings("rebound", client.source.?.request.metadata[0].value);
    try std.testing.expectEqualStrings("v1", if (is_delta) client.acceptedVersion(cds, "a").? else client.acceptedVersion(cds).?);
    plane.deinit();
    plane_owned = false;
    try std.testing.expectEqualStrings("actual-node", client.source.?.node.id);
    client.deinit();
    client_owned = false;
    try std.testing.expectEqual(server.address().getPort(), event.update.source.?.server.target.port);
    try std.testing.expectEqualStrings("original", event.update.source.?.request.metadata[0].value);
    try std.testing.expectEqualStrings("zone", event.update.source.?.node.locality.?.zone);
    try std.testing.expectEqualStrings("agent", event.update.source.?.node.user_agent_name);
    try std.testing.expectEqualStrings("version", event.update.source.?.node.user_agent_version);
    try std.testing.expectEqualStrings("custom-feature", event.update.source.?.node.client_features[0]);
    try std.testing.expectEqualStrings("{\"tag\":\"credential\"}", event.update.source.?.server.channel_creds[0].config_json.?);
    try std.testing.expectEqualStrings("retained-roots.pem", event.update.source.?.bootstrap.certificateProvider("roots").?.ca_certificate_file);
}

test "SotW received update retains the encoded node and source after control plane rebind and destruction" {
    try retainedUpdate(false);
}

test "delta received update retains the encoded node and source after control plane rebind and destruction" {
    try retainedUpdate(true);
}

fn validateSource(comptime is_delta: bool) !void {
    const configuration = try bootstrap.parse(gpa, "{\"xds_servers\":[{\"server_uri\":\"http://127.0.0.1:1\",\"channel_creds\":[{\"type\":\"insecure\"}]}]}", .{});
    defer configuration.deinit();
    var channel = try grpc.SharedChannel.init(gpa, std.testing.io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    const source = try Source.create(gpa, configuration, configuration.servers[0], .{ .id = "node" }, .{ .path = if (is_delta) delta.path else ads.path });
    defer source.release();
    const other = try Source.create(gpa, configuration, configuration.servers[0], .{ .id = "other" }, .{ .path = if (is_delta) delta.path else ads.path });
    defer other.release();
    const Client = if (is_delta) delta.Client else ads.Client;
    const source_refs = source.refs.load(.acquire);
    const sender_refs = channel.state.refs.load(.acquire);
    try std.testing.expectError(error.InvalidAdsOptions, Client.init(gpa, sender, .{ .node = .{ .id = "different" }, .source = source }));
    try std.testing.expectEqual(source_refs, source.refs.load(.acquire));
    try std.testing.expectEqual(sender_refs, channel.state.refs.load(.acquire));
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    var client = try Client.init(failing.allocator(), sender, .{ .node = .{ .id = "node" }, .source = source });
    defer client.deinit();
    const retained_refs = source.refs.load(.acquire);
    const transport = client.sender.state;
    var new_sender = channel.sender();
    var sender_owned = true;
    defer if (sender_owned) new_sender.deinit();
    const rebind_refs = channel.state.refs.load(.acquire);
    try std.testing.expectError(error.InvalidAdsOptions, client.rebindWithSource(new_sender, .{ .path = "/wrong" }, other));
    try std.testing.expectEqual(rebind_refs, channel.state.refs.load(.acquire));
    try std.testing.expectEqual(retained_refs, source.refs.load(.acquire));
    try std.testing.expect(client.source.? == source and client.sender.state == transport);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, client.rebindWithSource(new_sender, .{ .path = "/new" }, source));
    try std.testing.expect(client.source.? == source and client.sender.state == transport);
    try std.testing.expectEqual(retained_refs, source.refs.load(.acquire));
    try std.testing.expectEqual(rebind_refs, channel.state.refs.load(.acquire));
    failing.fail_index = std.math.maxInt(usize);
    try client.rebind(new_sender, .{ .path = "/manual" });
    sender_owned = false;
    try std.testing.expect(client.source == null);
    try std.testing.expectEqual(source_refs, source.refs.load(.acquire));
}

test "ADS source validation and failed rebinding preserve ownership in both modes" {
    try validateSource(false);
    try validateSource(true);
}

test "control plane source allocation failure leaves the selected source and channel untouched" {
    const configuration = try bootstrap.parse(gpa, "{\"xds_servers\":[{\"server_uri\":\"http://127.0.0.1:1\",\"channel_creds\":[{\"type\":\"insecure\"}]},{\"server_uri\":\"http://127.0.0.1:2\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"node\":{\"id\":\"node\"}}", .{});
    defer configuration.deinit();
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    const plane = try control.ControlPlane.init(failing.allocator(), std.testing.io, configuration, .{});
    defer plane.deinit();
    const source = plane.source;
    const transport = plane.channel.state;
    const refs = source.refs.load(.acquire);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, plane.moveToNextServerWithTimeout(.fromSeconds(1)));
    try std.testing.expect(plane.source == source and plane.channel.state == transport);
    try std.testing.expect(plane.discovery().source.? == source);
    try std.testing.expectEqual(@as(usize, 0), plane.server_index);
    try std.testing.expectEqual(refs, source.refs.load(.acquire));
    failing.fail_index = std.math.maxInt(usize);
    try plane.moveToNextServerWithTimeout(.fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 1), plane.server_index);
}

test "control plane TLS target material and provider inventory survive through an external sender" {
    const io = std.testing.io;
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    const pem = try std.fmt.allocPrint(gpa, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{tls_testing.certificate_base64});
    defer gpa.free(pem);
    try tmp.dir.writeFile(io, .{ .sub_path = "ca.pem", .data = pem });
    var buffer: [256]u8 = undefined;
    const ca_path = try tmp.path(&buffer, "ca.pem");
    const json = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"https://localhost:1\",\"channel_creds\":[{{\"type\":\"tls\",\"config\":{{\"root_certificate_provider\":\"roots\"}}}}]}}],\"node\":{{\"id\":\"node\"}},\"certificate_providers\":{{\"roots\":{{\"plugin_name\":\"file_watcher\",\"config\":{{\"ca_certificate_file\":\"{s}\"}}}}}}}}", .{ca_path});
    defer gpa.free(json);
    const configuration = try bootstrap.parse(gpa, json, .{});
    var configuration_owned = true;
    defer if (configuration_owned) configuration.deinit();
    const plane = try control.ControlPlane.init(gpa, io, configuration, .{});
    var plane_owned = true;
    defer if (plane_owned) plane.deinit();
    var sender = plane.sender();
    defer sender.deinit();
    const material = plane.material;
    try std.testing.expect(material.bundle_loaded);
    try std.testing.expect(material.bundle.map.count() != 0);
    configuration.deinit();
    configuration_owned = false;
    plane.deinit();
    plane_owned = false;
    try std.testing.expect(material.refs.load(.acquire) != 0);
    try std.testing.expect(material.bundle.map.count() != 0);
    try std.testing.expectEqualStrings("localhost", material.host);
    try std.testing.expectEqualStrings(ca_path, material.bootstrap.certificateProvider("roots").?.ca_certificate_file);
    const bundle = sender.state.canonical_endpoints[0].tls_host.tls.ca_bundle.?;
    try std.testing.expect(bundle.bundle == &material.bundle);
    try std.testing.expect(bundle.lock == &material.lock);
}
