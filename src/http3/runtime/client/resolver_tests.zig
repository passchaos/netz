const std = @import("std");
const runtime = @import("../../runtime.zig");

const net = std.Io.net;

test "HTTP3 application resolver bypasses literal URI and Alt-Svc routes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const BypassResolver = struct {
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: []const u8,
            _: u16,
            _: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            _ = self.calls.fetchAdd(1, .acq_rel);
            return error.UnknownHostName;
        }
    };
    var bypass = BypassResolver{};
    const resolver: runtime.AddressResolver = .{
        .context = &bypass,
        .resolve = BypassResolver.resolve,
    };
    const uri = try std.Uri.parse("https://127.0.0.1:8443/path");
    var endpoint = try runtime.uriEndpoint(allocator, uri);
    defer endpoint.deinit();
    const origin_addresses = try runtime.resolveEndpointWithResolverBefore(
        endpoint,
        allocator,
        io,
        resolver,
        null,
    );
    defer allocator.free(origin_addresses);
    try std.testing.expectEqual(@as(usize, 1), origin_addresses.len);
    try std.testing.expect(origin_addresses[0].eql(
        &net.IpAddress{ .ip4 = .loopback(8443) },
    ));

    const alt_addresses = try runtime.resolveHostPortWithResolverBefore(
        allocator,
        io,
        "127.0.0.1",
        9443,
        resolver,
        null,
    );
    defer allocator.free(alt_addresses);
    try std.testing.expectEqual(@as(usize, 1), alt_addresses.len);
    try std.testing.expect(alt_addresses[0].eql(
        &net.IpAddress{ .ip4 = .loopback(9443) },
    ));
    try std.testing.expectEqual(@as(u8, 0), bypass.calls.load(.acquire));
}

test "HTTP3 application resolver maps its deadline timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const TimeoutResolver = struct {
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "deadline.h3.resolver.test") or
                port != 443 or deadline == null)
            {
                return error.UnknownHostName;
            }
            _ = self.calls.fetchAdd(1, .acq_rel);
            return error.Timeout;
        }
    };
    var timeout_resolver = TimeoutResolver{};
    const uri = try std.Uri.parse("https://deadline.h3.resolver.test/");
    var endpoint = try runtime.uriEndpoint(allocator, uri);
    defer endpoint.deinit();
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.resolveEndpointWithResolverBefore(
            endpoint,
            allocator,
            io,
            .{
                .context = &timeout_resolver,
                .resolve = TimeoutResolver.resolve,
            },
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(
        @as(u8, 1),
        timeout_resolver.calls.load(.acquire),
    );
}

test "HTTP3 address attempt timeout cannot extend total deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const total = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    const capped = (try runtime.addressAttemptDeadline(
        io,
        total,
        .fromSeconds(5),
    )).?;
    try std.testing.expectEqual(total, capped);
    const shorter = (try runtime.addressAttemptDeadline(
        io,
        total,
        .fromMilliseconds(10),
    )).?;
    try std.testing.expect(std.Io.Clock.Timestamp.compare(
        shorter,
        .lt,
        total,
    ));
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.addressAttemptDeadline(io, total, .zero),
    );
}
