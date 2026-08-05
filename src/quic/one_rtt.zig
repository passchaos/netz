const std = @import("std");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.Error || error{
    MissingFrame,
};

pub const SendOptions = struct {
    destination_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    key_phase: bool = false,
    frames: []const quic.Frame,
};

pub const ReceivedPacket = struct {
    from: net.IpAddress,
    packet: quic.protection.OpenedShortPacket,
    frames: []quic.Frame,

    pub fn deinit(self: *ReceivedPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.frames);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub fn sendFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    for (options.frames) |frame| try frame.write(&payload, endpoint.allocator);
    const packet = try quic.protection.sealShortPacket(endpoint.allocator, keys, .{
        .destination_connection_id = options.destination_connection_id,
        .packet_number = options.packet_number,
        .packet_number_len = options.packet_number_len,
        .key_phase = options.key_phase,
        .payload = payload.items,
    });
    defer endpoint.allocator.free(packet);
    try endpoint.sendBytes(to, packet);
}

pub fn receive(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
    max_frames: usize,
) Error!ReceivedPacket {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    var packet = try quic.protection.openShortPacket(endpoint.allocator, keys, datagram.bytes, destination_connection_id_len, expected_packet_number);
    errdefer packet.deinit(endpoint.allocator);
    var frames: std.ArrayList(quic.Frame) = .empty;
    errdefer frames.deinit(endpoint.allocator);

    var pos: usize = 0;
    while (pos < packet.payload.len) {
        if (frames.items.len >= max_frames) return error.MissingFrame;
        const parsed = try quic.parseFrame(packet.payload[pos..]);
        try frames.append(endpoint.allocator, parsed.frame);
        pos += parsed.consumed;
    }
    if (frames.items.len == 0) return error.MissingFrame;
    return .{
        .from = datagram.from,
        .packet = packet,
        .frames = try frames.toOwnedSlice(endpoint.allocator),
    };
}

test "QUIC 1-RTT STREAM frame exchange over UDP endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server.deinit();
    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{ .max_datagram_size = 4096 });
    defer client.deinit();

    const client_dcid = [_]u8{ 0xca, 0xfe, 0xba, 0xbe };
    const server_dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x61} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x62} ** quic.protection.secret_len);

    const request_frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "GET /", .fin = true } }};
    try sendFrames(&client.endpoint, server.address(), client_keys, .{
        .destination_connection_id = &server_dcid,
        .packet_number = 0,
        .frames = &request_frames,
    });

    var request = try receive(&server.endpoint, client_keys, server_dcid.len, 0, 8);
    defer request.deinit(allocator);
    try std.testing.expect(request.from.eql(&client.address()));
    try std.testing.expectEqualSlices(u8, &server_dcid, request.packet.destination_connection_id);
    try std.testing.expectEqualStrings("GET /", request.frames[0].stream.data);

    const response_frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "OK", .fin = true } }};
    try sendFrames(&server.endpoint, request.from, server_keys, .{
        .destination_connection_id = &client_dcid,
        .packet_number = 0,
        .frames = &response_frames,
    });

    var response = try receive(&client.endpoint, server_keys, client_dcid.len, 0, 8);
    defer response.deinit(allocator);
    try std.testing.expect(response.from.eql(&server.address()));
    try std.testing.expectEqualSlices(u8, &client_dcid, response.packet.destination_connection_id);
    try std.testing.expectEqualStrings("OK", response.frames[0].stream.data);
}
