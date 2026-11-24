//! Shared native H1/H2 resolver, authority and admission exercises.
const std = @import("std");
const net = std.Io.net;

const Resolver = struct {
    peers: [2]net.IpAddress = undefined,
    calls: std.atomic.Value(usize) = .init(0),
    expected_deadline: ?std.Io.Clock.Timestamp = null,

    fn resolve(context: *anyopaque, resolve_allocator: std.mem.Allocator, _: std.Io, host: []const u8, port: u16, deadline: ?std.Io.Clock.Timestamp) @import("../address_resolver.zig").Error![]net.IpAddress {
        const state: *@This() = @ptrCast(@alignCast(context));
        _ = state.calls.fetchAdd(1, .acq_rel);
        if (!std.mem.eql(u8, host, "native.endpoint.test") or port != 8443) return error.UnknownHostName;
        if (state.expected_deadline) |expected| {
            if (deadline == null or !std.meta.eql(expected, deadline.?)) return error.Timeout;
        }
        return resolve_allocator.dupe(net.IpAddress, &state.peers);
    }
};

fn requireOptions(comptime Runtime: type) bool {
    return @hasField(Runtime.Limits, "address_resolver") and @hasField(Runtime.Limits, "address_connect_policy");
}

pub fn exercise(comptime Runtime: type, comptime h2: bool) !void {
    if (comptime !requireOptions(Runtime)) {
        return error.MissingNativeResolverOptions;
    } else {
        const allocator = std.testing.allocator;
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var server = try Runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
        defer server.deinit();
        var refused = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
        const refused_address = refused.socket.address;
        refused.deinit(io);
        var resolver: Resolver = .{ .peers = .{ refused_address, server.address() } };
        const Worker = struct {
            server: *Runtime.Server,
            fn run(state: *@This()) !void {
                var peer_connection = try state.server.acceptWithTimeout(.fromSeconds(3));
                defer peer_connection.close();
                if (h2) {
                    var received = try peer_connection.readRequestWithTimeout(.fromSeconds(3));
                    defer received.deinit(state.server.allocator);
                    const authority = for (received.headers) |field| {
                        if (std.mem.eql(u8, field.name, ":authority")) break field.value;
                    } else return error.MissingAuthority;
                    try std.testing.expectEqualStrings("native.endpoint.test:8443", authority);
                    try peer_connection.writeResponse(received.stream_id, .{ .body = "resolved" });
                } else {
                    var received = try peer_connection.readRequestWithTimeout(.{}, .fromSeconds(3));
                    defer received.deinit(state.server.allocator);
                    try std.testing.expectEqualStrings("native.endpoint.test:8443", received.request.header("host").?);
                    try peer_connection.writeResponse(.{ .body = "resolved" });
                }
            }
        };
        for (0..6) |mode| {
            const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
            resolver.expected_deadline = if (mode == 1) deadline else null;
            const limits: Runtime.Limits = .{
                .address_resolver = .{ .context = &resolver, .resolve = Resolver.resolve },
                .address_connect_policy = if (mode < 4) .ordered else .{ .happy_eyeballs = .{ .attempt_delay = .fromMilliseconds(1), .max_in_flight = 2 } },
            };
            var worker: Worker = .{ .server = &server };
            var serving = try std.Io.concurrent(io, Worker.run, .{&worker});
            var active = true;
            defer if (active) serving.cancel(io) catch {};
            if (mode == 3 or mode == 5) {
                var response = try Runtime.Client.requestUri(allocator, io, "http://native.endpoint.test:8443/native", .{}, limits);
                defer response.deinit(allocator);
                const body = if (h2) response.body else response.response.body;
                try std.testing.expectEqualStrings("resolved", body);
            } else {
                var client_connection = switch (mode) {
                    0 => try Runtime.Client.connectHost(allocator, io, "native.endpoint.test", 8443, limits),
                    1 => try Runtime.Client.connectHostWithDeadline(allocator, io, "native.endpoint.test", 8443, limits, deadline),
                    else => try Runtime.Client.connectHostWithTimeout(allocator, io, "native.endpoint.test", 8443, limits, .fromSeconds(2)),
                };
                defer client_connection.close();
                const authority = if (h2) client_connection.default_authority.? else client_connection.default_host.?;
                try std.testing.expectEqualStrings("native.endpoint.test:8443", authority);
                const request: Runtime.RequestOptions = if (h2) .{ .path = "/native" } else .{ .target = "/native" };
                var response = try client_connection.requestWithTimeout(request, .fromSeconds(2));
                defer response.deinit(allocator);
                const body = if (h2) response.body else response.response.body;
                try std.testing.expectEqualStrings("resolved", body);
            }
            try serving.await(io);
            active = false;
            try std.testing.expectEqual(mode + 1, resolver.calls.load(.acquire));
        }
        const calls = resolver.calls.load(.acquire);
        const LiteralPeer = struct {
            fn run(server_ptr: *Runtime.Server, release_event: *std.Io.Event, io_value: std.Io) !void {
                var peer_connection = try server_ptr.acceptWithTimeout(.fromSeconds(2));
                defer peer_connection.close();
                try release_event.wait(io_value);
            }
        };
        var release: std.Io.Event = .unset;
        var accepting = try std.Io.concurrent(io, LiteralPeer.run, .{ &server, &release, io });
        var accepting_active = true;
        defer if (accepting_active) {
            release.set(io);
            accepting.cancel(io) catch {};
        };
        var literal = try Runtime.Client.connectHostWithTimeout(allocator, io, "127.0.0.1", server.address().getPort(), .{
            .address_resolver = .{ .context = &resolver, .resolve = Resolver.resolve },
            .address_connect_policy = .ordered,
        }, .fromSeconds(2));
        defer literal.close();
        try std.testing.expectEqual(calls, resolver.calls.load(.acquire));
        release.set(io);
        try accepting.await(io);
        accepting_active = false;
    }
}

pub fn admission(comptime Runtime: type, comptime h2: bool) !void {
    if (comptime !requireOptions(Runtime)) {
        return error.MissingNativeResolverOptions;
    } else {
        const Bad = struct {
            calls: usize = 0,
            expected_host: ?[]const u8 = null,
            nameserver_failure: bool = false,
            fn resolve(context: *anyopaque, _: std.mem.Allocator, _: std.Io, query_host: []const u8, _: u16, _: ?std.Io.Clock.Timestamp) @import("../address_resolver.zig").Error![]net.IpAddress {
                const state: *@This() = @ptrCast(@alignCast(context));
                state.calls += 1;
                if (state.expected_host) |expected| {
                    if (!std.mem.eql(u8, expected, query_host)) return error.InvalidHostName;
                }
                if (state.nameserver_failure) return error.NameServerFailure;
                return error.UnknownHostName;
            }
        };
        var bad: Bad = .{};
        const configured: Runtime.Limits = .{ .address_resolver = .{ .context = &bad, .resolve = Bad.resolve } };
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        var invalid = configured;
        invalid.address_connect_policy = .{ .happy_eyeballs = .{ .max_in_flight = 0 } };
        try std.testing.expectError(error.InvalidAddressConnectPolicy, Runtime.Client.connectHost(failing.allocator(), undefined, "native.endpoint.test", 8443, invalid));
        try std.testing.expectError(error.InvalidAddressConnectPolicy, Runtime.Client.requestUri(failing.allocator(), std.Io.failing, "http://native.endpoint.test:8443/", .{}, invalid));
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectError(error.OutOfMemory, Runtime.Client.connectHost(failing.allocator(), undefined, "native.endpoint.test", 8443, configured));
        try std.testing.expectEqual(@as(usize, 0), bad.calls);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        try std.testing.expectError(error.Timeout, Runtime.Client.connectHostWithDeadline(std.testing.allocator, undefined, "native.endpoint.test", 8443, configured, .{ .clock = .real, .raw = .zero }));
        try std.testing.expectEqual(@as(usize, 0), bad.calls);
        try std.testing.expectError(error.UnknownHostName, Runtime.Client.connectTlsHost(std.testing.allocator, undefined, "native.endpoint.test", 8443, configured, .{}));
        if (!h2) try std.testing.expectError(error.UnknownHostName, Runtime.Client.connectVailTlsHost(std.testing.allocator, undefined, "native.endpoint.test", 8443, configured, .{}));
        try std.testing.expectEqual(@as(usize, if (h2) 1 else 2), bad.calls);
        const before_proxy = bad.calls;
        bad.expected_host = "proxy.native.test";
        var overridden: Bad = .{ .expected_host = "proxy.native.test", .nameserver_failure = true };
        const proxy_uri = "http://proxy.native.test:8080/";
        if (h2) {
            try std.testing.expectError(error.UnknownHostName, Runtime.Client.connectTlsHostViaProxy(std.testing.allocator, std.Io.failing, "origin.native.test", 443, .{ .uri = proxy_uri }, configured, .{}));
            try std.testing.expectError(error.NameServerFailure, Runtime.Client.connectTlsHostViaProxy(std.testing.allocator, std.Io.failing, "origin.native.test", 443, .{ .uri = proxy_uri, .options = .{ .address_resolver = .{ .context = &overridden, .resolve = Bad.resolve } } }, configured, .{}));
        } else {
            try std.testing.expectError(error.UnknownHostName, Runtime.Client.connectTunnelViaProxyUri(std.testing.allocator, std.Io.failing, proxy_uri, "origin.native.test:443", .{}, configured));
            try std.testing.expectError(error.NameServerFailure, Runtime.Client.connectTunnelViaProxyUri(std.testing.allocator, std.Io.failing, proxy_uri, "origin.native.test:443", .{ .address_resolver = .{ .context = &overridden, .resolve = Bad.resolve } }, configured));
        }
        try std.testing.expectEqual(before_proxy + 1, bad.calls);
        try std.testing.expectEqual(@as(usize, 1), overridden.calls);
    }
}

pub fn bindings(comptime Runtime: type) !void {
    if (comptime !requireOptions(Runtime)) {
        return error.MissingNativeResolverOptions;
    } else {
        const allocator = std.testing.allocator;
        var backend = try @import("zio").Runtime.init(allocator, .{});
        defer backend.deinit();
        const io = backend.io();
        const checks = @import("../network_interface_test_support.zig");
        var server = try Runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
        defer server.deinit();
        var refused = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
        const refused_address = refused.socket.address;
        refused.deinit(io);
        var resolver: Resolver = .{ .peers = .{ refused_address, server.address() } };
        const Peer = struct {
            fn run(server_ptr: *Runtime.Server, ready_event: *std.Io.Event, release_event: *std.Io.Event, address_out: *net.IpAddress, io_value: std.Io) !void {
                var peer_connection = try server_ptr.acceptWithTimeout(.fromSeconds(2));
                defer peer_connection.close();
                address_out.* = peer_connection.stream.socket.address;
                ready_event.set(io_value);
                try release_event.wait(io_value);
            }
        };
        var ready: std.Io.Event = .unset;
        var release: std.Io.Event = .unset;
        var address: net.IpAddress = undefined;
        var accepting = try std.Io.concurrent(io, Peer.run, .{ &server, &ready, &release, &address, io });
        var active = true;
        defer if (active) {
            release.set(io);
            accepting.cancel(io) catch {};
        };
        var client_connection = try Runtime.Client.connectHostWithTimeout(allocator, io, "native.endpoint.test", 8443, .{
            .local_address = .{ .ip4 = .loopback(0) },
            .network_interface = if (checks.supportedTcp()) checks.loopback() else null,
            .address_resolver = .{ .context = &resolver, .resolve = Resolver.resolve },
            .address_connect_policy = .{ .happy_eyeballs = .{ .attempt_delay = .fromMilliseconds(1), .max_in_flight = 2 } },
        }, .fromSeconds(2));
        defer client_connection.close();
        try ready.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } });
        try std.testing.expectEqual(std.meta.Tag(net.IpAddress).ip4, std.meta.activeTag(address));
        try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &address.ip4.bytes);
        try std.testing.expectEqual(client_connection.stream.socket.address.getPort(), address.getPort());
        if (checks.supportedTcp()) try checks.expectBound(io, client_connection.stream.socket);
        try std.testing.expectEqual(@as(usize, 1), resolver.calls.load(.acquire));
        release.set(io);
        try accepting.await(io);
        active = false;
    }
}
