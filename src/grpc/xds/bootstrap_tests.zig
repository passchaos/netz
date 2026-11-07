const std = @import("std");
const bootstrap = @import("bootstrap.zig");
const ads = @import("ads.zig");
const gpa = std.testing.allocator;

const valid =
    \\{
    \\  "xds_servers": [
    \\    {"server_uri": "http://127.0.0.1:8080", "channel_creds": [{"type": "insecure"}]},
    \\    {"server_uri": "https://control.example", "channel_creds": [{"type": "tls", "config": {"ca_certificate_file": "/ca.pem"}}],
    \\     "server_features": ["ignore_resource_deletion", "fail_on_data_errors", "trusted_xds_server", "unknown_feature"]}
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
    try std.testing.expect(parsed.servers[1].trusted_xds_server);
    try std.testing.expect(!parsed.servers[1].resource_timer_is_transient_error);
    try std.testing.expectEqualStrings("{\"ca_certificate_file\":\"/ca.pem\"}", parsed.servers[1].channel_creds[0].config_json.?);
    try std.testing.expectEqualStrings("/ca.pem", parsed.servers[1].tlsConfig().?.ca_certificate_file);
    try std.testing.expectEqual(@as(i96, 600 * std.time.ns_per_s), parsed.servers[1].tlsConfig().?.refresh_interval.nanoseconds);
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

test "gRPC xDS bootstrap parses standard DNS IP targets and alias defaults" {
    const cases = [_]struct { uri: []const u8, host: []const u8, port: u16, scheme: bootstrap.Scheme }{
        .{ .uri = "http://host", .host = "host", .port = 80, .scheme = .http },
        .{ .uri = "https://host", .host = "host", .port = 443, .scheme = .https },
        .{ .uri = "http://[::1]:9000", .host = "::1", .port = 9000, .scheme = .http },
        .{ .uri = "control.example:8443", .host = "control.example", .port = 8443, .scheme = .dns },
        .{ .uri = "control.example", .host = "control.example", .port = 443, .scheme = .dns },
        .{ .uri = "127.0.0.1:9001", .host = "127.0.0.1", .port = 9001, .scheme = .dns },
        .{ .uri = "[::1]:9002", .host = "::1", .port = 9002, .scheme = .dns },
        .{ .uri = "[2001:db8::1]", .host = "2001:db8::1", .port = 443, .scheme = .dns },
        .{ .uri = "dns:///control.example:8443", .host = "control.example", .port = 8443, .scheme = .dns },
        .{ .uri = "dns:///localhost", .host = "localhost", .port = 443, .scheme = .dns },
        .{ .uri = "dns:///127.0.0.1:9003", .host = "127.0.0.1", .port = 9003, .scheme = .dns },
        .{ .uri = "dns:///[::1]:9004", .host = "::1", .port = 9004, .scheme = .dns },
        .{ .uri = "dns:///[::1]", .host = "::1", .port = 443, .scheme = .dns },
    };
    for (cases) |case| {
        const json = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"{s}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}]}}", .{case.uri});
        defer gpa.free(json);
        const parsed = try bootstrap.parse(gpa, json, .{});
        defer parsed.deinit();
        const server = parsed.servers[0];
        try std.testing.expectEqualStrings(case.uri, server.uri);
        try std.testing.expectEqualStrings(case.host, server.target.host);
        try std.testing.expectEqual(case.port, server.target.port);
        try std.testing.expectEqual(case.scheme, server.target.scheme);
        try std.testing.expect(!server.usesTls());
        try std.testing.expect(parsed.firstInsecureServer() != null);
    }
}

test "gRPC xDS bootstrap selects first supported credential and ignores later TLS providers" {
    const parsed = try bootstrap.parse(gpa,
        \\{"xds_servers":[
        \\ {"server_uri":"https://host","channel_creds":[{"type":"future","config":{"value":"retained"}},{"type":"insecure"},{"type":"tls","config":{"root_certificate_provider":"missing"}}]},
        \\ {"server_uri":"http://host","channel_creds":[{"type":"future"},{"type":"tls","config":{"ca_certificate_file":"/first-ca.pem"}},{"type":"insecure"}]},
        \\ {"server_uri":"dns:///host","channel_creds":[{"type":"tls"},{"type":"tls","config":{"ca_certificate_file":"/later-ca.pem"}}]},
        \\ {"server_uri":"host:443","channel_creds":[{"type":"google_default"}]}
        \\]}
    , .{});
    defer parsed.deinit();
    const insecure = parsed.servers[0];
    try std.testing.expectEqual(@as(usize, 3), insecure.channel_creds.len);
    try std.testing.expectEqualStrings("future", insecure.channel_creds[0].type);
    try std.testing.expectEqualStrings("{\"value\":\"retained\"}", insecure.channel_creds[0].config_json.?);
    try std.testing.expect(insecure.selectedCredential().? == &insecure.channel_creds[1]);
    try std.testing.expect(!insecure.usesTls());
    try std.testing.expect(insecure.hasTlsCreds());
    try std.testing.expect(insecure.tlsConfig() == null);
    try std.testing.expectEqualStrings("missing", insecure.channel_creds[2].tls.?.root_certificate_provider);
    try std.testing.expect(parsed.firstInsecureServer().? == &parsed.servers[0]);
    const tls = parsed.servers[1];
    try std.testing.expect(tls.selectedCredential().? == &tls.channel_creds[1]);
    try std.testing.expect(tls.usesTls());
    try std.testing.expectEqualStrings("/first-ca.pem", tls.tlsConfig().?.ca_certificate_file);
    try std.testing.expectEqualStrings("", parsed.servers[2].tlsConfig().?.ca_certificate_file);
    try std.testing.expect(parsed.servers[3].selectedCredential() == null);
    try std.testing.expect(!parsed.servers[3].usesTls());
    try std.testing.expect(parsed.servers[3].tlsConfig() == null);
    try std.testing.expectError(error.InvalidBootstrap, bootstrap.parse(gpa,
        \\{"xds_servers":[{"server_uri":"host:443","channel_creds":[{"type":"future"},{"type":"tls","config":{"root_certificate_provider":"missing"}},{"type":"insecure"}]}]}
    , .{}));
}

test "gRPC xDS bootstrap rejects unsupported and malformed standard targets" {
    for ([_][]const u8{
        "",                   "dns:///",        "dns://resolver/host:443", "dns:/host",  "unix:///tmp/xds.sock",
        "ipv4:127.0.0.1:443", "ipv6:[::1]:443", "xds:///control",          "ftp://host", "host:0",
        "host:65536",         "host:",          "host:+443",               "[::1]:",     "::1:443",
        "[not-ip]:443",       "[::1",           "host/path",               "host?query", "host#fragment",
        "user@host",
    }) |uri| {
        const json = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"{s}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}]}}", .{uri});
        defer gpa.free(json);
        try std.testing.expectError(error.InvalidServerUri, bootstrap.parse(gpa, json, .{}));
    }
}

test "gRPC xDS bootstrap supplied authority templates require literal raw prefix" {
    for ([_]struct { raw: []const u8, encoded: []const u8 }{
        .{ .raw = "a/b", .encoded = "a%2Fb" },
        .{ .raw = "%名", .encoded = "%25%E5%90%8D" },
        .{ .raw = "Auth", .encoded = "%41uth" },
    }) |case| {
        const literal = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"host:443\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"authorities\":{{\"{s}\":{{\"client_listener_resource_name_template\":\"xdstp://{s}/listener\"}}}}}}", .{ case.raw, case.raw });
        defer gpa.free(literal);
        const configuration = try bootstrap.parse(gpa, literal, .{});
        defer configuration.deinit();
        try std.testing.expect(configuration.authority(case.raw) != null);
        const encoded = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"host:443\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"authorities\":{{\"{s}\":{{\"client_listener_resource_name_template\":\"xdstp://{s}/listener\"}}}}}}", .{ case.raw, case.encoded });
        defer gpa.free(encoded);
        try std.testing.expectError(error.InvalidBootstrap, bootstrap.parse(gpa, encoded, .{}));
    }
}

test "gRPC xDS bootstrap target credential and provider strings outlive input and owner" {
    const configuration = blk: {
        var caller = std.heap.ArenaAllocator.init(gpa);
        defer caller.deinit();
        const input = try caller.allocator().dupe(u8,
            \\{"xds_servers":[{"server_uri":"dns:///control.example:8443","channel_creds":[{"type":"future","config":{"value":"retained"}},{"type":"tls","config":{"root_certificate_provider":"roots"}}]}],
            \\ "certificate_providers":{"roots":{"plugin_name":"file_watcher","config":{"ca_certificate_file":"/retained-ca.pem"}}}}
        );
        break :blk try bootstrap.parse(gpa, input, .{});
    };
    const retained = configuration.retain();
    configuration.deinit();
    defer retained.deinit();
    try std.testing.expectEqual(@as(usize, 1), retained.refs.load(.acquire));
    const server = retained.servers[0];
    try std.testing.expectEqualStrings("dns:///control.example:8443", server.uri);
    try std.testing.expectEqualStrings("control.example", server.target.host);
    try std.testing.expectEqualStrings("{\"value\":\"retained\"}", server.channel_creds[0].config_json.?);
    try std.testing.expect(server.usesTls());
    const provider = retained.certificateProvider(server.tlsConfig().?.root_certificate_provider).?;
    try std.testing.expectEqualStrings("/retained-ca.pem", provider.ca_certificate_file);
}

test "gRPC xDS bootstrap parses TLS refresh intervals" {
    const parsed = try bootstrap.parse(gpa,
        \\{"xds_servers": [
        \\ {"server_uri": "https://host", "channel_creds": [{"type": "tls", "config": {"ca_certificate_file": "/ca.pem", "refresh_interval": "1.25s"}}]},
        \\ {"server_uri": "https://host", "channel_creds": [{"type": "tls", "config": {"ca_certificate_file": "/ca.pem", "refresh_interval": "0s"}}]},
        \\ {"server_uri": "https://host", "channel_creds": [{"type": "tls", "config": {"ca_certificate_file": "/ca.pem", "refresh_interval": "315576000000s"}}]}
        \\]}
    , .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(i96, std.time.ns_per_s + 250 * std.time.ns_per_ms), parsed.servers[0].tlsConfig().?.refresh_interval.nanoseconds);
    try std.testing.expectEqual(@as(i96, 0), parsed.servers[1].tlsConfig().?.refresh_interval.nanoseconds);
    try std.testing.expectEqual(@as(i96, 315576000000 * std.time.ns_per_s), parsed.servers[2].tlsConfig().?.refresh_interval.nanoseconds);
}

test "gRPC xDS bootstrap parses file_watcher certificate providers" {
    const parsed = try bootstrap.parse(gpa,
        \\{"xds_servers":[{"server_uri":"https://host","channel_creds":[{"type":"tls","config":{"root_certificate_provider":"roots","identity_certificate_provider":"identity"}}]}],
        \\ "certificate_providers":{
        \\  "roots":{"plugin_name":"file_watcher","config":{"ca_certificate_file":"/ca.pem","refresh_interval":"5s"}},
        \\  "identity":{"plugin_name":"file_watcher","config":{"certificate_file":"/cert.pem","private_key_file":"/key.pem","refresh_interval":"2s"}}}}
    , .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.certificate_providers.len);
    const roots = parsed.certificateProvider("roots").?;
    try std.testing.expectEqualStrings("/ca.pem", roots.ca_certificate_file);
    try std.testing.expectEqual(@as(i96, 5 * std.time.ns_per_s), roots.refresh_interval.nanoseconds);
    const tls = parsed.servers[0].tlsConfig().?;
    try std.testing.expectEqualStrings("roots", tls.root_certificate_provider);
    try std.testing.expectEqualStrings("identity", tls.identity_certificate_provider);
    try std.testing.expectError(error.InvalidBootstrap, bootstrap.parse(gpa, "{\"xds_servers\":[{\"server_uri\":\"https://host\",\"channel_creds\":[{\"type\":\"tls\",\"config\":{\"root_certificate_provider\":\"missing\"}}]}]}", .{}));
    try std.testing.expectError(error.UnsupportedBootstrapFeature, bootstrap.parse(gpa, "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"certificate_providers\":{\"p\":{\"plugin_name\":\"static_file\",\"config\":{}}}}", .{}));
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
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"https://host\",\"channel_creds\":[{\"type\":\"tls\",\"config\":{\"certificate_file\":\"/c.pem\"}}]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"host:443\",\"channel_creds\":[{\"type\":\"insecure\"},{\"type\":\"tls\",\"config\":{\"certificate_file\":\"/c.pem\"}}]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"https://host\",\"channel_creds\":[{\"type\":\"tls\",\"config\":{\"root_certificate_provider\":{\"instance_name\":\"p\"}}}]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"https://host\",\"channel_creds\":[{\"type\":\"tls\",\"config\":{\"ca_certificate_file\":\"/ca.pem\",\"refresh_interval\":\"1\"}}]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"https://host\",\"channel_creds\":[{\"type\":\"tls\",\"config\":{\"ca_certificate_file\":\"/ca.pem\",\"refresh_interval\":\"-1s\"}}]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"https://host\",\"channel_creds\":[{\"type\":\"tls\",\"config\":{\"ca_certificate_file\":\"/ca.pem\",\"refresh_interval\":\"1.s\"}}]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"https://host\",\"channel_creds\":[{\"type\":\"tls\",\"config\":{\"ca_certificate_file\":\"/ca.pem\",\"refresh_interval\":\"1.1234567890s\"}}]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"https://host\",\"channel_creds\":[{\"type\":\"tls\",\"config\":{\"ca_certificate_file\":\"/ca.pem\",\"refresh_interval\":\"315576000001s\"}}]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"https://host\",\"channel_creds\":[{\"type\":\"tls\",\"config\":{\"ca_certificate_file\":\"/ca.pem\",\"refresh_interval\":1}}]}]}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"node\":{}}", .want = error.InvalidBootstrapNode },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"node\":{\"id\":\"n\",\"metadata\":[]}}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"authorities\":{\"a\":{\"client_listener_resource_name_template\":\"wrong\"}}}", .want = error.InvalidBootstrap },
        .{ .json = "{\"xds_servers\":[{\"server_uri\":\"http://host\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"certificate_providers\":{\"p\":{}}}", .want = error.InvalidBootstrap },
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
