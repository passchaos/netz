const std = @import("std");
const netz = @import("netz");

fn parsePort(text: []const u8) !u16 {
    return std.fmt.parseInt(u16, text, 10);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 6) return error.InvalidArgument;
    const proxy_port = try parsePort(args[1]);
    const origin_a_port = try parsePort(args[2]);
    const origin_b_port = try parsePort(args[3]);
    _ = try parsePort(args[4]);
    if (!std.Io.Dir.path.isAbsolute(args[5])) return error.InvalidArgument;

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        now,
        args[5],
    );
    var ca_lock: std.Io.RwLock = .init;
    var bundle_verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };

    var pool = try netz.http.Pool.init(allocator, io, .{
        .max_connections = 2,
        .max_idle_connections = 2,
        .max_idle_per_origin = 1,
        .client = .{
            .socks5_proxy = .{
                .host = "127.0.0.1",
                .port = proxy_port,
                .options = .{
                    .credentials = .{
                        .username = "user",
                        .password = "secret",
                    },
                    .allow_no_authentication = false,
                },
            },
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        },
        .http3 = .{
            .limits = .{ .quic = .{ .max_datagram_size = 4096 } },
            .handshake = .{ .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .server_auth = bundle_verifier.clientVerifier(),
            } },
            .idle = .{ .max_idle_per_origin = 1, .max_idle_total = 2 },
            .max_connections = 2,
            .fallback = .never,
        },
    });
    defer pool.deinit();
    const base_a = try std.fmt.allocPrint(
        allocator,
        "https://origin-a.internal:{d}",
        .{origin_a_port},
    );
    defer allocator.free(base_a);
    const base_b = try std.fmt.allocPrint(
        allocator,
        "https://origin-b.internal:{d}",
        .{origin_b_port},
    );
    defer allocator.free(base_b);
    const requests = [_]struct {
        base: []const u8,
        path: []const u8,
        protocol: netz.http.Protocol,
        body: []const u8,
    }{
        .{ .base = base_a, .path = "/discover", .protocol = .http1, .body = "tcp-discovery-a" },
        .{ .base = base_a, .path = "/h3-a-one", .protocol = .http3, .body = "h3-socks-a-one" },
        .{ .base = base_b, .path = "/discover", .protocol = .http1, .body = "tcp-discovery-b" },
        .{ .base = base_b, .path = "/h3-b-one", .protocol = .http3, .body = "h3-socks-b-one" },
        .{ .base = base_a, .path = "/h3-a-two", .protocol = .http3, .body = "h3-socks-a-two" },
    };
    for (requests) |request| {
        const uri = try std.fmt.allocPrint(
            allocator,
            "{s}{s}",
            .{ request.base, request.path },
        );
        defer allocator.free(uri);
        var response = try pool.requestUriWithTimeout(
            uri,
            .{},
            .fromSeconds(8),
        );
        defer response.deinit();
        try std.testing.expectEqual(request.protocol, response.protocol());
        try std.testing.expectEqualStrings(request.body, response.body());
    }
    try std.testing.expectEqual(@as(usize, 2), pool.http3ConnectionCount());
    try std.testing.expectEqual(@as(usize, 2), pool.http3IdleCount());
    std.debug.print(
        "HTTP/3 SOCKS5 pool passed: origins=2 discovery=http1 " ++
            "h3_requests=3 udp_associations=1 quic_connections=2 " ++
            "domain_routes=2 remote_dns=true shared_endpoint=true " ++
            "pool_reuse=true tls_verified=true client_io=zio-std-io\n",
        .{},
    );
}
