const std = @import("std");
const http1 = @import("../../http1/mod.zig");
const proxy_policy = @import("proxy_policy.zig");

const Environment = proxy_policy.Environment;
const Policy = proxy_policy.Policy;
const ProxySource = proxy_policy.ProxySource;
const BypassSource = proxy_policy.BypassSource;
const DirectReason = proxy_policy.DirectReason;

test "gRPC proxy policy follows grpc-core precedence and empty disable" {
    const allocator = std.testing.allocator;
    const environment: Environment = .{
        .grpc_proxy = "http://grpc.proxy:8001",
        .https_proxy = "http://https.proxy:8002",
        .http_proxy = "http://http.proxy:8003",
    };

    var explicit = try (Policy{ .explicit_uri = "http://explicit.proxy:8000" })
        .resolve(allocator, environment, "example.com", 443);
    defer explicit.deinit();
    try std.testing.expect(explicit == .proxy);
    try std.testing.expectEqual(ProxySource.explicit_override, explicit.proxy.source);
    try std.testing.expectEqualStrings("http://explicit.proxy:8000", explicit.proxy.uri);

    var grpc = try (Policy{}).resolve(
        allocator,
        environment,
        "example.com",
        443,
    );
    defer grpc.deinit();
    try std.testing.expectEqual(ProxySource.grpc_proxy, grpc.proxy.source);

    var https = try (Policy{}).resolve(allocator, .{
        .https_proxy = environment.https_proxy,
        .http_proxy = environment.http_proxy,
    }, "example.com", 443);
    defer https.deinit();
    try std.testing.expectEqual(ProxySource.https_proxy, https.proxy.source);

    var http = try (Policy{}).resolve(allocator, .{
        .http_proxy = environment.http_proxy,
    }, "example.com", 443);
    defer http.deinit();
    try std.testing.expectEqual(ProxySource.http_proxy, http.proxy.source);

    var explicit_empty = try (Policy{ .explicit_uri = "" }).resolve(
        allocator,
        environment,
        "example.com",
        443,
    );
    defer explicit_empty.deinit();
    try std.testing.expectEqual(DirectReason.empty_proxy, explicit_empty.direct.reason);
    try std.testing.expectEqual(
        ProxySource.explicit_override,
        explicit_empty.direct.proxy_source.?,
    );

    var grpc_empty = try (Policy{}).resolve(allocator, .{
        .grpc_proxy = "",
        .https_proxy = environment.https_proxy,
    }, "example.com", 443);
    defer grpc_empty.deinit();
    try std.testing.expectEqual(DirectReason.empty_proxy, grpc_empty.direct.reason);

    var disabled = try (Policy{ .enabled = false }).resolve(
        allocator,
        environment,
        "example.com",
        443,
    );
    defer disabled.deinit();
    try std.testing.expectEqual(DirectReason.disabled, disabled.direct.reason);
}

test "gRPC proxy policy sanitizes URI and scopes decoded Basic credentials" {
    const allocator = std.testing.allocator;
    const existing = [_]http1.Header{
        .{ .name = "X-Proxy-Tenant", .value = "blue" },
        .{ .name = "proxy-authorization", .value = "Basic c3RhbGU=" },
    };
    var decision = try (Policy{ .options = .{ .headers = &existing } }).resolve(
        allocator,
        .{ .grpc_proxy = "http://usern%40me:pass%3Aword@proxy.example/path" },
        "origin.example",
        443,
    );
    defer decision.deinit();
    try std.testing.expect(decision == .proxy);
    try std.testing.expectEqualStrings("http://proxy.example:80", decision.proxy.uri);
    const proxy = decision.proxy.httpConnectProxy();
    try std.testing.expectEqual(@as(usize, 2), proxy.options.headers.len);
    try std.testing.expectEqualStrings("X-Proxy-Tenant", proxy.options.headers[0].name);
    try std.testing.expectEqualStrings(
        "Basic dXNlcm5AbWU6cGFzczp3b3Jk",
        proxy.options.headers[1].value,
    );
    try std.testing.expect(std.mem.find(u8, proxy.uri, "user") == null);

    try std.testing.expectError(
        error.InvalidProxyCredentials,
        (Policy{}).resolve(
            allocator,
            .{ .grpc_proxy = "http://bad%ZZ@proxy.example" },
            "origin.example",
            443,
        ),
    );
    try std.testing.expectError(
        error.UnsupportedProxyScheme,
        (Policy{}).resolve(
            allocator,
            .{ .grpc_proxy = "https://proxy.example" },
            "origin.example",
            443,
        ),
    );
    try std.testing.expectError(
        error.InvalidProxyUri,
        (Policy{}).resolve(
            allocator,
            .{ .grpc_proxy = "not a uri" },
            "origin.example",
            443,
        ),
    );
}

test "gRPC proxy bypass matches domains with grpc-core boundaries" {
    const allocator = std.testing.allocator;
    const environment: Environment = .{
        .grpc_proxy = "http://proxy.example",
        .no_proxy = " ignored.example ",
        .no_grpc_proxy = " , Example.COM, .internal.test ,, ",
    };
    for ([_][]const u8{
        "example.com",
        "API.Example.com",
        "internal.test",
        "deep.internal.test",
    }) |host| {
        var decision = try (Policy{}).resolve(allocator, environment, host, 443);
        defer decision.deinit();
        try std.testing.expectEqual(DirectReason.bypassed, decision.direct.reason);
        try std.testing.expectEqual(
            BypassSource.no_grpc_proxy,
            decision.direct.bypass_source.?,
        );
    }
    for ([_][]const u8{ "notexample.com", "ignored.example" }) |host| {
        var decision = try (Policy{}).resolve(allocator, environment, host, 443);
        defer decision.deinit();
        try std.testing.expect(decision == .proxy);
    }

    var fallback = try (Policy{}).resolve(allocator, .{
        .grpc_proxy = "http://proxy.example",
        .no_proxy = "ignored.example",
    }, "ignored.example", 443);
    defer fallback.deinit();
    try std.testing.expectEqual(BypassSource.no_proxy, fallback.direct.bypass_source.?);
}

test "gRPC proxy bypass matches IPv4 and IPv6 CIDR without DNS" {
    const allocator = std.testing.allocator;
    const environment: Environment = .{
        .grpc_proxy = "http://proxy.example",
        .no_grpc_proxy = " 192.168.0.255/24,2002:db8:a::45/64,192.168.1.1/33,broken/8 ",
    };
    for ([_][]const u8{
        "192.168.0.5",
        "2002:0db8:000a:0000:0000:0000:0000:0001",
    }) |host| {
        var decision = try (Policy{}).resolve(allocator, environment, host, 443);
        defer decision.deinit();
        try std.testing.expectEqual(DirectReason.bypassed, decision.direct.reason);
    }
    for ([_][]const u8{ "192.168.1.1", "2003:db8:a::1" }) |host| {
        var decision = try (Policy{}).resolve(allocator, environment, host, 443);
        defer decision.deinit();
        try std.testing.expect(decision == .proxy);
    }

    var zero = try (Policy{}).resolve(allocator, .{
        .grpc_proxy = "http://proxy.example",
        .no_proxy = "0.0.0.0/0",
    }, "203.0.113.8", 443);
    defer zero.deinit();
    try std.testing.expectEqual(DirectReason.bypassed, zero.direct.reason);
}

test "gRPC proxy environment map remains injectable" {
    const allocator = std.testing.allocator;
    var map = std.process.Environ.Map.init(allocator);
    defer map.deinit();
    try map.put("https_proxy", "http://map.proxy:8181");
    try map.put("no_proxy", "direct.example");

    var proxied = try (Policy{}).resolveMap(
        allocator,
        &map,
        "origin.example",
        443,
    );
    defer proxied.deinit();
    try std.testing.expectEqual(ProxySource.https_proxy, proxied.proxy.source);

    var direct = try (Policy{}).resolveMap(
        allocator,
        &map,
        "direct.example",
        443,
    );
    defer direct.deinit();
    try std.testing.expectEqual(DirectReason.bypassed, direct.direct.reason);
}

test "gRPC proxy policy snapshots the Zig process environment explicitly" {
    var decision = try (Policy{ .enabled = false }).resolveEnviron(
        std.testing.allocator,
        std.testing.environ,
        "origin.example",
        443,
    );
    defer decision.deinit();
    try std.testing.expectEqual(DirectReason.disabled, decision.direct.reason);
}
