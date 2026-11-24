const runtime = @import("../../runtime.zig");
const shared = @import("../../../internal/testing/native_resolution.zig");

test "HTTP2 native resolver policy routes named and URI connections" {
    try shared.exercise(runtime, true);
}

test "HTTP2 native resolver policy preserves preflight and TLS propagation" {
    try shared.admission(runtime, true);
}

test "HTTP2 native resolver policy composes with source and interface binding" {
    try shared.bindings(runtime);
}

test "HTTP2 native resolver policy projection opens a constrained H1 connection" {
    if (comptime !@hasField(runtime.Limits, "address_resolver")) return error.MissingNativeResolverOptions;
    const std = @import("std");
    const h1 = @import("../../../http1/runtime.zig");
    const checks = @import("../../../internal/network_interface_test_support.zig");
    var backend = try @import("zio").Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const Resolver = struct {
        peer: std.Io.net.IpAddress,
        calls: usize = 0,
        fn resolve(context: *anyopaque, allocator: std.mem.Allocator, _: std.Io, _: []const u8, _: u16, _: ?std.Io.Clock.Timestamp) runtime.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const state: *@This() = @ptrCast(@alignCast(context));
            state.calls += 1;
            return allocator.dupe(std.Io.net.IpAddress, &.{state.peer});
        }
    };
    var resolver: Resolver = .{ .peer = listener.socket.address };
    var limits: runtime.Limits = .{
        .local_address = .{ .ip4 = .loopback(0) },
        .network_interface = if (checks.supportedTcp()) checks.loopback() else null,
        .address_resolver = .{ .context = &resolver, .resolve = Resolver.resolve },
        .address_connect_policy = .{ .happy_eyeballs = .{ .max_in_flight = 0 } },
        .connect_timeout = .fromSeconds(2),
    };
    try std.testing.expectError(error.InvalidAddressConnectPolicy, h1.Client.connectHost(std.testing.allocator, io, "projected.native.test", 8443, runtime.limitsToHttp1(limits)));
    try std.testing.expectEqual(@as(usize, 0), resolver.calls);
    limits.address_connect_policy = .{ .happy_eyeballs = .{ .max_in_flight = 2 } };
    var client = try h1.Client.connectHost(std.testing.allocator, io, "projected.native.test", 8443, runtime.limitsToHttp1(limits));
    defer client.close();
    const accepted = try listener.accept(io);
    defer accepted.close(io);
    try std.testing.expectEqualStrings("projected.native.test:8443", client.default_host.?);
    try std.testing.expectEqual(@as(usize, 1), resolver.calls);
    try std.testing.expectEqual(client.stream.socket.address.getPort(), accepted.socket.address.getPort());
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &accepted.socket.address.ip4.bytes);
    if (checks.supportedTcp()) try checks.expectBound(io, client.stream.socket);
}
