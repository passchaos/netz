//! IO provenance at the shared HTTP/3 endpoint ownership boundary.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const quic = @import("../../../quic/mod.zig");
const zio = @import("zio");

fn createEndpoint(io: std.Io) !*quic.runtime.Endpoint {
    const endpoint = try std.testing.allocator.create(quic.runtime.Endpoint);
    errdefer std.testing.allocator.destroy(endpoint);
    endpoint.* = try .bind(std.testing.allocator, io, .{ .ip4 = .loopback(0) }, .{});
    return endpoint;
}

fn expectIoRejection(owner_io: std.Io, requested_io: std.Io) !void {
    const allocator = std.testing.allocator;
    const endpoint = try createEndpoint(owner_io);
    var endpoint_owned = true;
    defer if (endpoint_owned) {
        endpoint.deinit();
        allocator.destroy(endpoint);
    };
    const result = runtime.SharedHandshakeClientPool.initWithOwnedEndpoint(allocator, requested_io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .client = .{ .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} } },
    }, endpoint);
    if (result) |value| {
        endpoint_owned = false;
        var pool = value;
        pool.deinit();
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(@as(anyerror, error.InvalidPoolOptions), err);

    var peer = try quic.runtime.Endpoint.bind(allocator, owner_io, .{ .ip4 = .loopback(0) }, .{});
    defer peer.deinit();
    try endpoint.sendFrames(peer.address(), &.{.{ .ping = {} }});
    var received = try peer.receiveBytesWithDeadline(.fromNow(owner_io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    defer received.deinit(allocator);
    try std.testing.expect(received.from.eql(&endpoint.address()));
}

test "HTTP3 endpoint adoption rejects a different IO context and preserves caller ownership" {
    var first = std.Io.Threaded.init(std.testing.allocator, .{});
    defer first.deinit();
    var second = std.Io.Threaded.init(std.testing.allocator, .{});
    defer second.deinit();
    try std.testing.expect(first.io().vtable == second.io().vtable);
    try std.testing.expect(first.io().userdata != second.io().userdata);
    try expectIoRejection(first.io(), second.io());
}

test "HTTP3 endpoint adoption rejects a different IO backend without taking ownership" {
    var owner = try zio.Runtime.init(std.testing.allocator, .{});
    defer owner.deinit();
    var foreign = std.Io.Threaded.init(std.testing.allocator, .{});
    defer foreign.deinit();
    try expectIoRejection(owner.io(), foreign.io());
}

test "HTTP3 endpoint adoption accepts a copy of its exact IO context" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const endpoint = try createEndpoint(io);
    var endpoint_owned = true;
    defer if (endpoint_owned) {
        endpoint.deinit();
        allocator.destroy(endpoint);
    };
    const copied_io = endpoint.io;
    var pool = try runtime.SharedHandshakeClientPool.initWithOwnedEndpoint(allocator, copied_io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .client = .{ .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} } },
    }, endpoint);
    endpoint_owned = false;
    defer pool.deinit();
    try std.testing.expect(std.meta.eql(pool.io, endpoint.io));
}

test "HTTP3 endpoint adoption checks IO before pool allocation" {
    const allocator = std.testing.allocator;
    var owner = std.Io.Threaded.init(allocator, .{});
    defer owner.deinit();
    var foreign = std.Io.Threaded.init(allocator, .{});
    defer foreign.deinit();
    const endpoint = try createEndpoint(owner.io());
    defer {
        endpoint.deinit();
        allocator.destroy(endpoint);
    }
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidPoolOptions, runtime.SharedHandshakeClientPool.initWithOwnedEndpoint(failing.allocator(), foreign.io(), .{
        .local_address = .{ .ip4 = .loopback(0) },
        .client = .{ .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} } },
    }, endpoint));
    try std.testing.expect(!failing.has_induced_failure);
}
