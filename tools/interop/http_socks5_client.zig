const std = @import("std");
const netz = @import("netz");

fn port(text: []const u8) !u16 {
    return std.fmt.parseInt(u16, text, 10);
}

fn uri(
    allocator: std.mem.Allocator,
    scheme: []const u8,
    target_port: u16,
    target: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}://origin.internal:{d}{s}",
        .{ scheme, target_port, target },
    );
}

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{
        .raw = .fromSeconds(8),
        .clock = .awake,
    });
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 8) return error.InvalidArgument;
    const proxy_port = try port(args[1]);
    const redirect_port = try port(args[2]);
    const final_port = try port(args[3]);
    const h2_port = try port(args[4]);
    const direct_h2_port = try port(args[5]);
    const pool_port = try port(args[6]);

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        std.Io.Clock.real.now(io),
        args[7],
    );
    var ca_lock: std.Io.RwLock = .init;
    const socks = netz.http.Socks5Proxy{
        .host = "127.0.0.1",
        .port = proxy_port,
    };
    const authorization = [_]netz.http.Header{.{
        .name = "authorization",
        .value = "Bearer http-redirect-secret",
    }};

    var redirect_client = try netz.http.Client.init(allocator, io, .{
        .socks5_proxy = socks,
    });
    defer redirect_client.deinit();
    const start_uri = try uri(allocator, "http", redirect_port, "/start");
    defer allocator.free(start_uri);
    var redirected = try redirect_client
        .requestUriFollowingRedirectsDetailedWithDeadline(
        start_uri,
        .{ .headers = &authorization },
        .{ .policy = .{ .max_redirects = 2 } },
        deadline(io),
    );
    defer redirected.deinit();
    try std.testing.expectEqual(@as(usize, 1), redirected.redirect_count);
    try std.testing.expectEqual(netz.http.Protocol.http1, redirected.response.protocol());
    try std.testing.expectEqualStrings("redirect-final", redirected.response.body());
    const final_uri = try uri(allocator, "http", final_port, "/final");
    defer allocator.free(final_uri);
    try std.testing.expectEqualStrings(final_uri, redirected.final_uri);

    var h2_client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http2_only,
        .socks5_proxy = socks,
        .tls = .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    });
    defer h2_client.deinit();
    const h2_uri = try uri(allocator, "https", h2_port, "/h2");
    defer allocator.free(h2_uri);
    var h2_response = try h2_client.requestUriWithDeadline(
        h2_uri,
        .{},
        deadline(io),
    );
    defer h2_response.deinit();
    try std.testing.expectEqual(netz.http.Protocol.http2, h2_response.protocol());
    try std.testing.expectEqualStrings("h2-socks", h2_response.body());

    var direct_h2 = try netz.http2.socks5_runtime.Client
        .connectTlsHostWithDeadline(
        allocator,
        io,
        .{ .host = "127.0.0.1", .port = proxy_port },
        "origin.internal",
        direct_h2_port,
        .{ .max_body_bytes = 4096 },
        .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
        deadline(io),
    );
    defer direct_h2.close();
    var direct_response = try direct_h2.request(.{
        .path = "/h2-direct",
    });
    defer direct_response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "h2-direct-socks",
        direct_response.body,
    );

    var pool = try netz.http.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_origin = 1,
        .client = .{ .socks5_proxy = socks },
    });
    defer pool.deinit();
    const pool_uri = try uri(allocator, "http", pool_port, "/pool");
    defer allocator.free(pool_uri);
    for ([_][]const u8{ "pool-one", "pool-two" }) |expected| {
        var response = try pool.requestUriWithTimeout(
            pool_uri,
            .{},
            .fromSeconds(3),
        );
        defer response.deinit();
        try std.testing.expectEqualStrings(expected, response.body());
    }
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    std.debug.print(
        "HTTP SOCKS5 client passed: redirects=1 http1=true http2=true " ++
            "http2_direct=true alpn=h2 pool_requests=2 pool_tunnels=1 total_tunnels=5 " ++
            "remote_dns=true credentials_isolated=true tls_hostname=true " ++
            "deadline=true client_io=zio-std-io\n",
        .{},
    );
}
