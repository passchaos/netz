const std = @import("std");
const bootstrap = @import("bootstrap.zig");
const ads = @import("ads.zig");
const gpa = std.testing.allocator;

const valid =
    \\{
    \\  "xds_servers": [
    \\    {"server_uri": "http://127.0.0.1:8080", "channel_creds": [{"type": "insecure"}]},
    \\    {"server_uri": "https://control.example", "channel_creds": [{"type": "tls", "config": {"ca_certificate_file": "/ca.pem"}}],
    \\     "server_features": ["ignore_resource_deletion", "fail_on_data_errors", "unknown_feature"]}
    \\  ],
    \\  "node": {"id": "node-1", "cluster": "cluster-1",
    \\    "locality": {"region": "r", "zone": "z", "sub_zone": "s"},
    \\    "metadata": {"a": 1, "b": "x", "c": true, "d": null, "e": [1, 2]}},
    \\  "authorities": {
    \\    "auth-1": {"xds_servers": [{"server_uri": "http://127.0.0.1:8081", "channel_creds": [{"type": "insecure"}]}],
    \\      "client_listener_resource_name_template": "xdstp://auth-1/listener"}
    \\  },
    \\  "client_default_listener_resource_name_template": "xdstp://auth-1/listener",
    \\  "server_listener_resource_name_template": "xdstp://auth-1/server"
    \\}
;

test "gRPC xDS bootstrap parses servers node authorities and metadata" {
    const parsed = try bootstrap.parse(gpa, valid, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.servers.len);
    try std.testing.expectEqual(bootstrap.Scheme.http, parsed.servers[0].target.scheme);
    try std.testing.expectEqualStrings("127.0.0.1", parsed.servers[0].target.host);
    try std.testing.expectEqual(@as(u16, 8080), parsed.servers[0].target.port);
    try std.testing.expect(parsed.servers[0].hasInsecureCreds());
    try std.testing.expectEqual(bootstrap.Scheme.https, parsed.servers[1].target.scheme);
    try std.testing.expectEqual(@as(u16, 443), parsed.servers[1].target.port);
    try std.testing.expect(parsed.servers[1].hasTlsCreds());
    try std.testing.expect(parsed.servers[1].ignore_resource_deletion);
    try std.testing.expect(parsed.servers[1].fail_on_data_errors);
    try std.testing.expect(!parsed.servers[1].resource_timer_is_transient_error);
    try std.testing.expectEqualStrings("{\"ca_certificate_file\":\"/ca.pem\"}", parsed.servers[1].channel_creds[0].config_json.?);
    const first = parsed.firstInsecureServer().?;
    try std.testing.expectEqualStrings("http://127.0.0.1:8080", first.uri);

    const node = parsed.node.?;
    try std.testing.expectEqualStrings("node-1", node.id);
    try std.testing.expectEqualStrings("cluster-1", node.cluster);
    try std.testing.expectEqualStrings("r", node.locality.?.region);
    try std.testing.expectEqualStrings("s", node.locality.?.sub_zone);
    try std.testing.expect(node.metadata != null and node.metadata.?.len != 0);
    try std.testing.expect(node.metadata_json != null);
    const ads_node = parsed.adsNode().?;
    try std.testing.expectEqualStrings("node-1", ads_node.id);
    const encoded = try ads.codec.encodeNode(gpa, ads_node);
    defer gpa.free(encoded);
    try std.testing.expect(encoded.len > node.metadata.?.len);

    try std.testing.expectEqual(@as(usize, 1), parsed.authorities.len);
    const authority = parsed.authority("auth-1").?;
    try std.testing.expectEqualStrings("xdstp://auth-1/listener", authority.client_listener_resource_name_template);
    try std.testing.expectEqual(@as(usize, 1), authority.servers.len);
    try std.testing.expectEqualStrings("xdstp://auth-1/listener", parsed.client_default_listener_resource_name_template);
    try std.testing.expectEqualStrings("xdstp://auth-1/server", parsed.server_listener_resource_name_template);
}

test "gRPC xDS bootstrap server URI defaults and IPv6" {
    const parsed = try bootstrap.parse(gpa,
        \\{"xds_servers": [
        \\ {"server_uri": "http://host", "channel_creds": [{"type": "insecure"}]},
        \\ {"server_uri": "https://host", "channel_creds": [{"type": "tls"}]},
        \\ {"server_uri": "http://[::1]:9000", "channel_creds": [{"type": "insecure"}]}
        \\]}
    , .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 80), parsed.servers[0].target.port);
    try std.testing.expectEqual(@as(u16, 443), parsed.servers[1].target.port);
    try std.testing.expectEqualStrings("::1", parsed.servers[2].target.host);
    try std.testing.expectEqual(@as(u16, 9000), parsed.servers[2].target.port);
}

test "gRPC xDS bootstrap rejects invalid and unsupported shapes" {
    const cases = [_]struct { json: []const u8, want: anyerror }{
        .{ .json = "{}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"channel_creds\":[{\"type\":\"insecure\"}]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"ftp://host\",\"channel_creds\":[{\"type\":\"insecure\"}]}]}", .want = error.InvalidServerUri },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host/path\",\"channel_creds\":[{\"type\":\"insecure\"}]}]}", .want = error.InvalidServerUri },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host:0\",\"channel_creds\":[{\"type\":\"insecure\"}]}]}", .want = error.InvalidServerUri },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\"}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"unknown\"}]}]}", .want = error.UnsupportedBootstrapCreds },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"insecure\",\"config\":[]}]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"node\":{}}", .want = error.InvalidBootstrapNode },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"node\":{\"id\":\"n\",\"metadata\":[]}}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"authorities\":{\"a\":{\"client_listener_resource_name_template\":\"wrong\"}}}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"certificate_providers\":{\"p\":{}}}", .want = error.UnsupportedBootstrapFeature },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"xds_servers\":[]}", .want = error.InvalidBootstrap },
        .{ .json = "{", .want = error.InvalidBootstrap },
    };
    for (cases) |case| {
        if (bootstrap.parse(gpa, case.json, .{})) |parsed| {
            parsed.deinit();
            return error.TestUnexpectedResult;
        } else |err| {
            try std.testing.expectEqual(case.want, err);
        }
    }
}

test "gRPC xDS bootstrap bounds and allocation failures" {
    try std.testing.expectError(error.BootstrapLimitExceeded, bootstrap.parse(gpa, valid, .{ .max_bytes = valid.len - 1 }));
    const many =
        \\{"xds_servers":[
        \\ {"server_uri":"http://h1","channel_creds":[{"type":"insecure"}]},
        \\ {"server_uri":"http://h2","channel_creds":[{"type":"insecure"}]},
        \\ {"server_uri":"http://h3","channel_creds":[{"type":"insecure"}]},
        \\ {"server_uri":"http://h4","channel_creds":[{"type":"insecure"}]}
        \\]}
    ;
    try std.testing.expectError(error.InvalidBootstrap, bootstrap.parse(gpa, many, .{ .max_servers = 2 }));

    const Harness = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const parsed = try bootstrap.parse(allocator, valid, .{});
            defer parsed.deinit();
            try std.testing.expect(parsed.node != null);
        }
    };
    try std.testing.checkAllAllocationFailures(gpa, Harness.run, .{});
}
