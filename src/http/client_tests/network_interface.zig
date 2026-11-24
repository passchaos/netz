const std = @import("std");
const http = @import("../mod.zig");
const http1 = @import("../../http1/runtime.zig");
const http2 = @import("../../http2/runtime.zig");
const ws = @import("../../websocket/runtime.zig");
const checks = @import("../../internal/network_interface_test_support.zig");
const zio = @import("zio");
const net = std.Io.net;

test "unified HTTP network interface binds direct proxy and pool TCP connections" {
    if (!checks.supportedTcp()) return error.SkipZigTest;
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    var uri_storage: [80]u8 = undefined;
    const uri = try std.fmt.bufPrint(&uri_storage, "http://127.0.0.1:{d}/", .{listener.socket.address.getPort()});
    const options: http.ClientOptions = .{ .local_address = .{ .ip4 = .loopback(0) }, .network_interface = checks.loopback(), .connect_timeout = .fromSeconds(2) };
    // Connecting H1 requires no server HTTP handshake. Forward-proxy setup
    // follows the same owning Client option rather than resolving the origin.
    for ([_]?http.HttpProxy{ null, .{ .uri = uri } }) |proxy| {
        var configured = options;
        configured.http_proxy = proxy;
        var client = try http.Client.init(std.testing.allocator, io, configured);
        defer client.deinit();
        var connection = try client.connectUri(if (proxy != null) "http://unresolved.invalid/" else uri);
        defer connection.close();
        const accepted = try listener.accept(io);
        defer accepted.close(io);
        try checks.expectBound(io, connection.value.http1.stream.socket);
        try std.testing.expectEqual(connection.value.http1.stream.socket.address.getPort(), accepted.socket.address.getPort());
    }
    // Pool H3 configuration inherits the same bind, including its QUIC
    // endpoints. A fixed-family bind disables alternate-family candidates.
    var pool = try http.Pool.init(std.testing.allocator, io, .{ .client = options, .http3 = .{ .migration_local_address = .{ .ip6 = .unspecified(0) } } });
    defer pool.deinit();
    try std.testing.expect(pool.http3.?.options.local_address.eql(&options.local_address.?));
    try std.testing.expect(pool.http3.?.options.migration_local_address == null);
    try checks.expectBound(io, pool.http3.?.shared_pool.?.endpoint.socket);
    try std.testing.expectEqualStrings(checks.loopback().name, pool.http3.?.options.limits.quic.network_interface.?.name);
}

test "HTTP and WebSocket network interface options reach direct and proxy connectors" {
    if (!checks.supportedTcp()) return error.SkipZigTest;
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const invalid = @import("../../runtime.zig").NetworkInterface{ .name = "" };
    const address = net.IpAddress{ .ip4 = .loopback(1) };
    try std.testing.expectError(error.InvalidNetworkInterface, http1.Client.connect(std.testing.allocator, io, address, .{ .network_interface = invalid }));
    try std.testing.expectError(error.InvalidNetworkInterface, http2.Client.connect(std.testing.allocator, io, address, .{ .network_interface = invalid }));
    try std.testing.expectError(error.InvalidNetworkInterface, http2.Client.connectTlsHostViaProxy(std.testing.allocator, io, "origin.test", 443, .{ .uri = "http://127.0.0.1:1/" }, .{ .network_interface = invalid }, .{}));
    try std.testing.expectError(error.InvalidNetworkInterface, ws.Client.connectUri(std.testing.allocator, io, "ws://127.0.0.1:1/", .{ .network_interface = invalid }));
    try std.testing.expectError(error.InvalidNetworkInterface, ws.Client.connectUriViaProxyWithTimeout(std.testing.allocator, io, "http://127.0.0.1:1/", "ws://origin.test/", .{ .network_interface = invalid }, .{}, .{}, .fromSeconds(2)));
}

test "WebSocket network interface reaches literal and hostname socket setup" {
    if (!checks.supportedTcp()) return error.SkipZigTest;
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const options: ws.ConnectOptions = .{ .local_address = .{ .ip4 = .loopback(0) }, .network_interface = checks.loopback(), .connect_timeout = .fromSeconds(2) };
    for ([_][]const u8{ "127.0.0.1", "localhost" }) |host| {
        const stream = try ws.connectNamedEndpointBefore(std.testing.allocator, io, host, listener.socket.address.getPort(), options, null);
        defer stream.close(io);
        const accepted = try listener.accept(io);
        defer accepted.close(io);
        try checks.expectBound(io, stream.socket);
        try std.testing.expectEqual(stream.socket.address.getPort(), accepted.socket.address.getPort());
    }
}

test "HTTP network interface TCP listeners constrain accepted sockets" {
    if (!checks.supportedTcp()) return error.SkipZigTest;
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var h1 = try http1.Server.listen(std.testing.allocator, io, .{ .ip4 = .loopback(0) }, .{ .network_interface = checks.loopback() });
    defer h1.deinit();
    var h2 = try http2.Server.listen(std.testing.allocator, io, .{ .ip6 = .loopback(0) }, .{ .network_interface = checks.loopback() });
    defer h2.deinit();
    for ([_]*net.Server{ &h1.listener, &h2.listener }) |listener| {
        try checks.expectBound(io, listener.socket);
        const client = try listener.socket.address.connect(io, .{ .mode = .stream });
        defer client.close(io);
        const accepted = try listener.accept(io);
        defer accepted.close(io);
        try checks.expectBound(io, accepted.socket);
    }
}
