//! Authenticated HTTP/3 clients over RFC 1928 UDP ASSOCIATE.

const std = @import("std");
const deadline_policy = @import("../internal/deadline.zig");
const proxy_socks5 = @import("../proxy/socks5.zig");
const quic = @import("../quic/mod.zig");
const runtime = @import("runtime.zig");

const net = std.Io.net;

pub const Proxy = struct {
    host: []const u8,
    port: u16 = 1080,
    options: proxy_socks5.Options = .{},
};

pub fn connectHost(
    allocator: std.mem.Allocator,
    io: std.Io,
    local_address: net.IpAddress,
    proxy: Proxy,
    target_host: []const u8,
    target_port: u16,
    limits: runtime.Limits,
    options: runtime.HandshakeClientOptions,
) runtime.Error!runtime.HandshakeClient {
    return connectHostBefore(
        allocator,
        io,
        local_address,
        proxy,
        target_host,
        target_port,
        limits,
        options,
        try deadline_policy.fromTimeout(io, options.connect_timeout),
    );
}

pub fn connectHostWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    local_address: net.IpAddress,
    proxy: Proxy,
    target_host: []const u8,
    target_port: u16,
    limits: runtime.Limits,
    options: runtime.HandshakeClientOptions,
    deadline: std.Io.Clock.Timestamp,
) runtime.Error!runtime.HandshakeClient {
    return connectHostBefore(
        allocator,
        io,
        local_address,
        proxy,
        target_host,
        target_port,
        limits,
        options,
        try deadline_policy.capTimeout(
            io,
            deadline,
            options.connect_timeout,
        ),
    );
}

pub fn connectHostWithTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    local_address: net.IpAddress,
    proxy: Proxy,
    target_host: []const u8,
    target_port: u16,
    limits: runtime.Limits,
    options: runtime.HandshakeClientOptions,
    timeout: std.Io.Duration,
) runtime.Error!runtime.HandshakeClient {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return connectHostWithDeadline(
        allocator,
        io,
        local_address,
        proxy,
        target_host,
        target_port,
        limits,
        options,
        .fromNow(io, .{ .raw = timeout, .clock = .awake }),
    );
}

fn connectHostBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    local_address: net.IpAddress,
    proxy: Proxy,
    target_host: []const u8,
    target_port: u16,
    limits: runtime.Limits,
    options: runtime.HandshakeClientOptions,
    deadline: ?std.Io.Clock.Timestamp,
) runtime.Error!runtime.HandshakeClient {
    var association = if (deadline) |absolute|
        try proxy_socks5.associateUdpHostWithDeadline(
            allocator,
            io,
            proxy.host,
            proxy.port,
            .{
                .socks5 = proxy.options,
                .bind_address = local_address,
            },
            absolute,
        )
    else
        try proxy_socks5.associateUdpHost(
            allocator,
            io,
            proxy.host,
            proxy.port,
            .{
                .socks5 = proxy.options,
                .bind_address = local_address,
            },
        );
    var association_owned = true;
    defer if (association_owned) association.deinit();

    const parsed_target = net.IpAddress.parse(target_host, target_port);
    const logical_peer = parsed_target catch net.IpAddress{ .ip4 = .{
        .bytes = .{ 0, 0, 0, 1 },
        .port = target_port,
    } };
    const endpoint = try allocator.create(quic.runtime.Endpoint);
    endpoint.* = (if (parsed_target) |_| quic.runtime.Endpoint
        .fromSocks5Association(
        allocator,
        &association,
        limits.quic,
    ) else |_| quic.runtime.Endpoint.fromSocks5AssociationForDomain(
        allocator,
        &association,
        target_host,
        target_port,
        logical_peer,
        limits.quic,
    )) catch |err| {
        allocator.destroy(endpoint);
        return err;
    };
    association_owned = false;

    var connect_options = options;
    connect_options.connect_timeout = null;
    return if (deadline) |absolute|
        runtime.HandshakeClient.connectOwningEndpointWithDeadline(
            endpoint,
            logical_peer,
            connect_options,
            absolute,
        )
    else
        runtime.HandshakeClient.connectOwningEndpoint(
            endpoint,
            logical_peer,
            connect_options,
        );
}

test {
    _ = Proxy;
}

test "HTTP3 SOCKS5 connect timeout rejects non-positive budgets before association" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        connectHostWithTimeout(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            .{ .host = "proxy.invalid" },
            "origin.test",
            443,
            .{},
            .{
                .handshake = .{
                    .original_destination_connection_id = &.{1},
                    .local_connection_id = &.{2},
                },
            },
            .fromNanoseconds(0),
        ),
    );
}
