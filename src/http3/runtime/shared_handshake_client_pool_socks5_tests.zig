const std = @import("std");
const runtime = @import("../runtime.zig");
const proxy_socks5 = @import("../../proxy/socks5.zig");
const quic = @import("../../quic/mod.zig");

const net = std.Io.net;

test "shared HTTP3 SOCKS5 releases failed pending domain routes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var control_listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer control_listener.deinit(io);
    const control_client = try control_listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    const control_server = try control_listener.accept(io);
    defer control_server.close(io);
    const bind_address = net.IpAddress{ .ip4 = .loopback(0) };
    const client_socket = try bind_address.bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    const relay = try bind_address.bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer relay.close(io);
    var association = proxy_socks5.UdpAssociation.init(
        io,
        .{ .io = io, .stream = control_client, .deadline = null },
        client_socket,
        relay.address,
    );
    const endpoint = try allocator.create(quic.runtime.Endpoint);
    endpoint.* = try .fromSocks5AssociationForDomains(
        allocator,
        &association,
        .{ .max_routes = 1, .max_sources_per_route = 1 },
        .{ .max_datagram_size = 1200 },
    );
    var pool = try runtime.SharedHandshakeClientPool.initWithOwnedEndpoint(
        allocator,
        io,
        .{
            .local_address = .{ .ip4 = .loopback(0) },
            .limits = .{ .quic = .{ .max_datagram_size = 1200 } },
            .client = .{ .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
            } },
            .proxy_domain_routing = true,
            .max_connections = 1,
        },
        endpoint,
    );
    defer pool.deinit();

    for ([_][]const u8{
        "https://first.proxy.invalid/",
        "https://second.proxy.invalid/",
    }) |uri| {
        try std.testing.expectError(
            error.HandshakeTimeout,
            pool.acquireUriWithTimeout(uri, .fromMilliseconds(20)),
        );
        try std.testing.expectEqual(
            @as(usize, 0),
            pool.endpoint.socks5DomainRouteCount(),
        );
    }
}
