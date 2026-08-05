const std = @import("std");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.packet_space.Error || quic.Error || error{
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

pub const ConnectionConfig = struct {
    peer: net.IpAddress,
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    max_ack_ranges: usize = 64,
    max_frames_per_packet: usize = 16,
};

pub const Connection = struct {
    endpoint: *quic.runtime.Endpoint,
    config: ConnectionConfig,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,
    received: quic.packet_space.ReceivedPacketTracker,
    sent: quic.packet_space.SentPacketTracker,

    pub fn init(endpoint: *quic.runtime.Endpoint, config: ConnectionConfig) Connection {
        return .{
            .endpoint = endpoint,
            .config = config,
            .received = .init(endpoint.allocator, config.max_ack_ranges),
            .sent = .init(endpoint.allocator),
        };
    }

    pub fn deinit(self: *Connection) void {
        self.received.deinit();
        self.sent.deinit();
        self.* = undefined;
    }

    pub fn send(self: *Connection, frames: []const quic.Frame) Error!void {
        try sendFrames(self.endpoint, self.config.peer, self.config.send_keys, .{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = self.next_packet_number,
            .frames = frames,
        });
        try self.sent.sent(self.next_packet_number, ackEliciting(frames));
        self.next_packet_number += 1;
    }

    pub fn sendAck(self: *Connection, ack_delay: u64) Error!void {
        const ack = try self.received.ackFrame(self.endpoint.allocator, ack_delay);
        defer self.endpoint.allocator.free(ack.ranges);
        const frames = [_]quic.Frame{.{ .ack = ack }};
        try self.send(&frames);
    }

    pub fn receivePacket(self: *Connection) Error!ReceivedPacket {
        var packet = try receive(
            self.endpoint,
            self.config.receive_keys,
            self.config.local_connection_id.len,
            self.expected_packet_number,
            self.config.max_frames_per_packet,
        );
        errdefer packet.deinit(self.endpoint.allocator);
        self.expected_packet_number = packet.packet.packet_number + 1;
        try self.received.record(packet.packet.packet_number);
        for (packet.frames) |frame| {
            if (frame == .ack) _ = try self.sent.applyAck(frame.ack);
        }
        return packet;
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

fn ackEliciting(frames: []const quic.Frame) bool {
    for (frames) |frame| {
        switch (frame) {
            .ack, .padding => {},
            else => return true,
        }
    }
    return false;
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

test "QUIC 1-RTT connection sends ACK and marks sent packet acknowledged" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const server_cid = [_]u8{ 0x05, 0x06, 0x07, 0x08 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x71} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x72} ** quic.protection.secret_len);

    var client = Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();

    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "ack me", .fin = true } }};
    try client.send(&frames);
    try std.testing.expectEqual(@as(usize, 1), client.sent.packets.items.len);
    try std.testing.expect(!client.sent.packets.items[0].acknowledged);

    var received = try server.receivePacket();
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), received.packet.packet_number);
    try server.sendAck(0);

    var ack_packet = try client.receivePacket();
    defer ack_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), ack_packet.frames[0].ack.largest_acknowledged);
    try std.testing.expect(client.sent.packets.items[0].acknowledged);
}
