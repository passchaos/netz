const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const codec = @import("codec.zig");

const protected_packet_capacity = codec.stack_capacity + 64;

pub fn development(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    session_id: webtransport.SessionId,
    payload: []const u8,
) !void {
    var stack: [codec.stack_capacity]u8 = undefined;
    var encoded = try codec.encodeStackFirst(
        endpoint.allocator,
        &stack,
        session_id,
        payload,
    );
    defer encoded.deinit(endpoint.allocator);
    const frames = [_]quic.Frame{.{ .datagram = .{
        .data = encoded.bytes,
        .length_present = true,
    } }};
    try endpoint.sendFrames(to, &frames);
}

pub fn protected(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packet_number: *u64,
    session_id: webtransport.SessionId,
    payload: []const u8,
) !void {
    var datagram_stack: [codec.stack_capacity]u8 = undefined;
    var encoded = try codec.encodeStackFirst(
        endpoint.allocator,
        &datagram_stack,
        session_id,
        payload,
    );
    defer encoded.deinit(endpoint.allocator);
    const frames = [_]quic.Frame{.{ .datagram = .{
        .data = encoded.bytes,
        .length_present = true,
    } }};
    const options: quic.one_rtt.SendOptions = .{
        .destination_connection_id = destination_connection_id,
        .packet_number = packet_number.*,
        .frames = &frames,
    };
    const sizes = try quic.one_rtt.framePacketStorageSizes(options);
    if (sizes.packet <= protected_packet_capacity) {
        var packet_stack: [protected_packet_capacity]u8 = undefined;
        try quic.one_rtt.sendFramesInto(
            endpoint,
            to,
            keys,
            options,
            &packet_stack,
        );
    } else {
        try quic.one_rtt.sendFrames(endpoint, to, keys, options);
    }
    packet_number.* += 1;
}
