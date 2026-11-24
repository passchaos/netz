const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");
const runtime = @import("../runtime.zig");
const socks5 = @import("../../proxy/socks5.zig");
const checks = @import("../../internal/network_interface_test_support.zig");
const socket_binding = @import("../../internal/socket_binding.zig");
const stream_io = @import("../../internal/stream_io.zig");
const net = std.Io.net;

test "QUIC network interface adoption rejects an unconstrained association and preserves ownership" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos and builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var backend = try zio.Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    const accepted = try listener.accept(io);
    defer accepted.close(io);
    const local = net.IpAddress{ .ip4 = .loopback(0) };
    const socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    const relay = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer relay.close(io);
    var association = socks5.UdpAssociation.init(io, .{ .io = io, .stream = client, .deadline = null }, socket, relay.address);
    var association_owned = true;
    defer if (association_owned) association.deinit();
    const result = runtime.Endpoint.fromSocks5Association(allocator, &association, .{ .network_interface = checks.loopback() });
    if (result) |value| {
        association_owned = false;
        var endpoint = value;
        endpoint.deinit();
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(@as(anyerror, error.InterfaceBindingMismatch), err);
    try std.testing.expectError(error.InterfaceBindingMismatch, socket_binding.requireInterface(io, association.socket, checks.loopback()));

    // Rejected adoption retains both the control and the UDP data plane.
    try stream_io.writeAllParts(io, association.control.stream, "alive", "");
    var reader = accepted.reader(io, &.{});
    var control_bytes: [5]u8 = undefined;
    try reader.interface.readSliceAll(&control_bytes);
    try std.testing.expectEqualStrings("alive", &control_bytes);
    var framing: [64]u8 = undefined;
    try association.sendTo(.{ .ip = relay.address }, "still owned", &framing);
    var receive_buffer: [64]u8 = undefined;
    const received = try relay.receiveTimeout(io, &receive_buffer, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const packet = try socks5.udp.decodeDatagram(received.data);
    try std.testing.expectEqualStrings("still owned", packet.payload);
}

test "QUIC network interface adoption accepts an existing exact constraint by index" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos and builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var backend = try zio.Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    const accepted = try listener.accept(io);
    defer accepted.close(io);
    const local = net.IpAddress{ .ip4 = .loopback(0) };
    const selected = checks.loopback();
    const socket = try socket_binding.bindDatagram(io, local, selected);
    const relay = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer relay.close(io);
    var association = socks5.UdpAssociation.init(io, .{ .io = io, .stream = client, .deadline = null }, socket, relay.address);
    var association_owned = true;
    defer if (association_owned) association.deinit();
    const interface = @import("../../runtime.zig").NetworkInterface{ .index = (try selected.resolve(io)).index };
    var endpoint = try runtime.Endpoint.fromSocks5Association(allocator, &association, .{ .network_interface = interface });
    association_owned = false;
    defer endpoint.deinit();
    try socket_binding.requireInterface(io, endpoint.socket, interface);
    try endpoint.sendFrames(relay.address, &.{.{ .ping = {} }});
    var bytes: [64]u8 = undefined;
    const message = try relay.receiveTimeout(io, &bytes, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const datagram = try socks5.udp.decodeDatagram(message.data);
    try std.testing.expectEqualSlices(u8, &.{1}, datagram.payload);
}

test "QUIC network interface adoption rejects a foreign backend before native handle access" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(error.OptionUnsupported, socket_binding.requireInterface(threaded.io(), undefined, checks.loopback()));
}

test "QUIC network interface adoption checks receive filtering without rewriting it" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const native = struct {
        extern "ws2_32" fn setsockopt(socket: *opaque {}, level: c_int, option: c_int, value: [*]const u8, length: c_int) callconv(.winapi) c_int;
        extern "ws2_32" fn getsockopt(socket: *opaque {}, level: c_int, option: c_int, value: [*]u8, length: *c_int) callconv(.winapi) c_int;
    };
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const socket = try socket_binding.bindDatagram(io, .{ .ip4 = .loopback(0) }, checks.loopback());
    defer socket.close(io);
    const disabled: u32 = 0;
    try std.testing.expectEqual(@as(c_int, 0), native.setsockopt(@ptrCast(socket.handle), 0, 28, std.mem.asBytes(&disabled).ptr, @sizeOf(u32)));
    // Outgoing UNICAST_IF is still correct. Receive policy alone makes the
    // socket unsuitable for adoption, and the check must leave it disabled.
    try std.testing.expectError(error.InterfaceBindingMismatch, socket_binding.requireInterface(io, socket, checks.loopback()));
    var enabled: u32 = 0;
    var length: c_int = @sizeOf(u32);
    try std.testing.expectEqual(@as(c_int, 0), native.getsockopt(@ptrCast(socket.handle), 0, 28, std.mem.asBytes(&enabled).ptr, &length));
    try std.testing.expectEqual(@as(u32, 0), enabled);
}

test "QUIC network interface adoption rejects a receive list containing another interface" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const native = struct {
        extern "ws2_32" fn setsockopt(socket: *opaque {}, level: c_int, option: c_int, value: [*]const u8, length: c_int) callconv(.winapi) c_int;
        extern "ws2_32" fn getsockopt(socket: *opaque {}, level: c_int, option: c_int, value: [*]u8, length: *c_int) callconv(.winapi) c_int;
    };
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const selected = checks.loopback();
    const selected_index = (try selected.resolve(io)).index;
    const socket = try socket_binding.bindDatagram(io, .{ .ip4 = .loopback(0) }, selected);
    defer socket.close(io);
    // Add one other accepted index without changing the outgoing interface
    // or transmitting any packet. Some hosts expose only loopback.
    var added = false;
    for (1..65) |candidate| {
        if (candidate == selected_index) continue;
        const value: u32 = @intCast(candidate);
        if (native.setsockopt(@ptrCast(socket.handle), 0, 29, std.mem.asBytes(&value).ptr, @sizeOf(u32)) == 0) {
            added = true;
            break;
        }
    }
    if (!added) return error.SkipZigTest;
    var before: [2]u32 = @splat(0);
    var before_len: c_int = @sizeOf(@TypeOf(before));
    try std.testing.expectEqual(@as(c_int, 0), native.getsockopt(@ptrCast(socket.handle), 0, 33, std.mem.asBytes(&before).ptr, &before_len));
    try std.testing.expectEqual(@as(c_int, 8), before_len);
    try std.testing.expectError(error.InterfaceBindingMismatch, socket_binding.requireInterface(io, socket, selected));
    var after: [2]u32 = @splat(0);
    var after_len: c_int = @sizeOf(@TypeOf(after));
    try std.testing.expectEqual(@as(c_int, 0), native.getsockopt(@ptrCast(socket.handle), 0, 33, std.mem.asBytes(&after).ptr, &after_len));
    try std.testing.expectEqual(before_len, after_len);
    try std.testing.expectEqualSlices(u32, &before, &after);
}
