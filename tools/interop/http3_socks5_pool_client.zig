const std = @import("std");
const netz = @import("netz");

fn parsePort(text: []const u8) !u16 {
    return std.fmt.parseInt(u16, text, 10);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 5) return error.InvalidArgument;
    const proxy_port = try parsePort(args[1]);
    const origin_port = try parsePort(args[2]);
    _ = try parsePort(args[3]);
    if (!std.Io.Dir.path.isAbsolute(args[4])) return error.InvalidArgument;

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
        args[4],
    );
    var ca_lock: std.Io.RwLock = .init;
    var bundle_verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };

    var pool = try netz.http.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
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
            .idle = .{ .max_idle_per_origin = 1, .max_idle_total = 1 },
            .max_connections = 1,
            .fallback = .never,
        },
    });
    defer pool.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "https://origin.internal:{d}",
        .{origin_port},
    );
    defer allocator.free(base);
    const paths = [_][]const u8{ "/discover", "/h3-one", "/h3-two" };
    const protocols = [_]netz.http.Protocol{ .http1, .http3, .http3 };
    const bodies = [_][]const u8{
        "tcp-discovery",
        "h3-socks-one",
        "h3-socks-two",
    };
    for (paths, protocols, bodies) |path, expected_protocol, expected_body| {
        const uri = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base, path });
        defer allocator.free(uri);
        var response = try pool.requestUriWithTimeout(
            uri,
            .{},
            .fromSeconds(8),
        );
        defer response.deinit();
        try std.testing.expectEqual(expected_protocol, response.protocol());
        try std.testing.expectEqualStrings(expected_body, response.body());
    }
    try std.testing.expectEqual(@as(usize, 1), pool.http3ConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.http3IdleCount());
    std.debug.print(
        "HTTP/3 SOCKS5 pool passed: discovery=http1 h3_requests=2 " ++
            "udp_associations=1 quic_connections=1 remote_dns=true " ++
            "pool_reuse=true tls_verified=true client_io=zio-std-io\n",
        .{},
    );
}
