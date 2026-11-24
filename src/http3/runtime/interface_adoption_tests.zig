const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");
const checks = @import("../../internal/network_interface_test_support.zig");
const socket_binding = @import("../../internal/socket_binding.zig");
const net = std.Io.net;

test "HTTP3 network interface adoption rejects an unconstrained endpoint and preserves ownership" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos and builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var backend = try zio.Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const endpoint = try allocator.create(quic.runtime.Endpoint);
    endpoint.* = try .bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    var endpoint_owned = true;
    defer if (endpoint_owned) {
        endpoint.deinit();
        allocator.destroy(endpoint);
    };
    const result = runtime.SharedHandshakeClientPool.initWithOwnedEndpoint(allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .limits = .{ .quic = .{ .network_interface = checks.loopback() } },
        .client = .{ .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} } },
    }, endpoint);
    if (result) |value| {
        endpoint_owned = false;
        var pool = value;
        pool.deinit();
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(@as(anyerror, error.InterfaceBindingMismatch), err);
    try std.testing.expectError(error.InterfaceBindingMismatch, socket_binding.requireInterface(io, endpoint.socket, checks.loopback()));
    // The rejected endpoint remains usable by its caller.
    var peer = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer peer.deinit();
    try endpoint.sendFrames(peer.address(), &.{.{ .ping = {} }});
    var message = try peer.receiveBytesWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    defer message.deinit(allocator);
    try std.testing.expect(message.from.eql(&endpoint.address()));
}

test "HTTP3 network interface adoption accepts an already constrained endpoint" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos and builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var backend = try zio.Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const selected = checks.loopback();
    const endpoint = try allocator.create(quic.runtime.Endpoint);
    endpoint.* = try .bind(allocator, io, .{ .ip6 = .loopback(0) }, .{ .network_interface = selected });
    var endpoint_owned = true;
    defer if (endpoint_owned) {
        endpoint.deinit();
        allocator.destroy(endpoint);
    };
    const interface = @import("../../runtime.zig").NetworkInterface{ .index = (try selected.resolve(io)).index };
    var pool = try runtime.SharedHandshakeClientPool.initWithOwnedEndpoint(allocator, io, .{
        .local_address = .{ .ip6 = .loopback(0) },
        .limits = .{ .quic = .{ .network_interface = interface } },
        .client = .{ .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} } },
    }, endpoint);
    endpoint_owned = false;
    defer pool.deinit();
    try socket_binding.requireInterface(io, pool.endpoint.socket, interface);
}
