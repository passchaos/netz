const std = @import("std");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.packet_space.Error || quic.flow_control.Error || quic.recovery.Error || quic.Error || error{
    MissingFrame,
};

pub const SendOptions = struct {
    destination_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    key_phase: bool = false,
    frames: []const quic.Frame,
};

const PayloadSendOptions = struct {
    destination_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    key_phase: bool = false,
    payload: []const u8,
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
    initial_send_max_data: u64 = std.math.maxInt(u62),
    initial_receive_max_data: u64 = std.math.maxInt(u62),
    receive_window: u64 = 64 * 1024,
    initial_send_max_stream_data: u64 = std.math.maxInt(u62),
    initial_receive_max_stream_data: u64 = std.math.maxInt(u62),
    stream_receive_window: u64 = 64 * 1024,
};

const StreamFlowEntry = struct {
    stream_id: u64,
    flow: quic.flow_control.SendFlow,
};

const StreamRecvFlowEntry = struct {
    stream_id: u64,
    flow: quic.flow_control.RecvFlow,
    highest_received_end: u64 = 0,
};

pub const Connection = struct {
    endpoint: *quic.runtime.Endpoint,
    config: ConnectionConfig,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,
    received: quic.packet_space.ReceivedPacketTracker,
    sent: quic.packet_space.SentPacketTracker,
    recovery: quic.recovery.Queue,
    send_flow: quic.flow_control.SendFlow,
    recv_flow: quic.flow_control.RecvFlow,
    recv_data_total: u64 = 0,
    stream_send_flows: std.ArrayList(StreamFlowEntry) = .empty,
    stream_recv_flows: std.ArrayList(StreamRecvFlowEntry) = .empty,

    pub fn init(endpoint: *quic.runtime.Endpoint, config: ConnectionConfig) Error!Connection {
        return .{
            .endpoint = endpoint,
            .config = config,
            .received = .init(endpoint.allocator, config.max_ack_ranges),
            .sent = .init(endpoint.allocator),
            .recovery = .init(endpoint.allocator),
            .send_flow = .init(config.initial_send_max_data),
            .recv_flow = try .init(config.initial_receive_max_data, config.receive_window),
        };
    }

    pub fn deinit(self: *Connection) void {
        self.received.deinit();
        self.sent.deinit();
        self.recovery.deinit();
        self.stream_send_flows.deinit(self.endpoint.allocator);
        self.stream_recv_flows.deinit(self.endpoint.allocator);
        self.* = undefined;
    }

    pub fn send(self: *Connection, frames: []const quic.Frame) Error!void {
        const stream_bytes = countStreamBytes(frames);
        if (stream_bytes > 0) {
            self.send_flow.reserve(stream_bytes) catch |err| {
                try self.sendDataBlocked();
                return err;
            };
        }
        for (frames) |frame| {
            if (frame != .stream or frame.stream.data.len == 0) continue;
            const flow = try self.sendStreamFlow(frame.stream.stream_id);
            flow.reserve(frame.stream.data.len) catch |err| {
                try self.sendStreamDataBlocked(frame.stream.stream_id, flow.limit);
                return err;
            };
        }
        try self.sendTrackedFrames(frames);
    }

    fn sendDataBlocked(self: *Connection) Error!void {
        const frames = [_]quic.Frame{self.send_flow.dataBlockedFrame()};
        try self.sendTrackedFrames(&frames);
    }

    fn sendStreamDataBlocked(self: *Connection, stream_id: u64, limit: u64) Error!void {
        const frames = [_]quic.Frame{.{ .stream_data_blocked = .{ .stream_id = stream_id, .maximum_stream_data = limit } }};
        try self.sendTrackedFrames(&frames);
    }

    fn sendTrackedFrames(self: *Connection, frames: []const quic.Frame) Error!void {
        const packet_number = self.next_packet_number;
        const payload = try encodeFrames(self.endpoint.allocator, frames);
        defer self.endpoint.allocator.free(payload);

        const is_ack_eliciting = ackEliciting(frames);
        var tracked_recovery = false;
        if (is_ack_eliciting) {
            try self.recovery.trackSent(packet_number, payload);
            tracked_recovery = true;
        }
        errdefer {
            if (tracked_recovery) _ = self.recovery.forgetPacketNumber(packet_number);
        }
        try self.sent.sent(packet_number, is_ack_eliciting);
        errdefer _ = self.sent.forget(packet_number);
        try self.sendPayloadPacket(packet_number, payload);
        self.next_packet_number += 1;
    }

    fn sendPayloadPacket(self: *Connection, packet_number: u64, payload: []const u8) Error!void {
        try sendPayload(self.endpoint, self.config.peer, self.config.send_keys, .{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = packet_number,
            .payload = payload,
        });
    }

    pub fn retransmitPto(self: *Connection) Error!bool {
        const candidate = self.recovery.ptoCandidate() orelse return false;
        const packet_number = self.next_packet_number;
        try self.recovery.recordRetransmission(candidate.group_index, packet_number);
        errdefer _ = self.recovery.forgetPacketNumber(packet_number);
        try self.sent.sent(packet_number, true);
        errdefer _ = self.sent.forget(packet_number);
        try self.sendPayloadPacket(packet_number, candidate.payload);
        self.next_packet_number += 1;
        return true;
    }

    pub fn markPacketAcknowledged(self: *Connection, packet_number: u64) bool {
        const marked_sent = self.sent.markAcknowledged(packet_number);
        const removed_recovery = self.recovery.acknowledgePacketNumber(packet_number);
        return marked_sent or removed_recovery;
    }

    pub fn pendingRecoveryCount(self: Connection) usize {
        return self.recovery.pendingCount();
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
        if (packet.packet.packet_number >= self.expected_packet_number) {
            self.expected_packet_number = packet.packet.packet_number + 1;
        }
        try self.received.record(packet.packet.packet_number);
        for (packet.frames) |frame| {
            switch (frame) {
                .ack => {
                    _ = try self.sent.applyAck(frame.ack);
                    _ = try self.recovery.applyAck(frame.ack);
                },
                .max_data => |max_data| self.send_flow.updateLimit(max_data.maximum_data),
                .max_stream_data => |max_stream_data| {
                    const flow = try self.sendStreamFlow(max_stream_data.stream_id);
                    flow.updateLimit(max_stream_data.maximum_stream_data);
                },
                .stream => |stream| {
                    var recv_stream = try self.recvStreamFlow(stream.stream_id);
                    const data_len = std.math.cast(u64, stream.data.len) orelse return error.InvalidFrameLength;
                    const stream_end = std.math.add(u64, stream.offset, data_len) catch return error.InvalidFrameLength;
                    try recv_stream.flow.receive(stream_end);

                    // PTO retransmits the same STREAM bytes with a new packet
                    // number.  Flow control is offset-based, so a duplicate
                    // frame must not consume connection credit again.
                    if (stream_end > recv_stream.highest_received_end) {
                        const new_stream_credit = stream_end - recv_stream.highest_received_end;
                        const next_total = std.math.add(u64, self.recv_data_total, new_stream_credit) catch return error.FlowControlViolation;
                        try self.recv_flow.receive(next_total);
                        self.recv_data_total = next_total;
                        recv_stream.highest_received_end = stream_end;
                    }
                },
                else => {},
            }
        }
        return packet;
    }

    pub fn consumeReceived(self: *Connection, amount: u64) ?quic.Frame {
        if (self.recv_flow.consume(amount)) |_| return self.recv_flow.maxDataFrame();
        return null;
    }

    pub fn consumeStreamReceived(self: *Connection, stream_id: u64, amount: u64) Error!?quic.Frame {
        var recv_stream = try self.recvStreamFlow(stream_id);
        if (recv_stream.flow.consume(amount)) |_| return recv_stream.flow.maxStreamDataFrame(stream_id);
        return null;
    }

    fn sendStreamFlow(self: *Connection, stream_id: u64) Error!*quic.flow_control.SendFlow {
        for (self.stream_send_flows.items) |*entry| {
            if (entry.stream_id == stream_id) return &entry.flow;
        }
        try self.stream_send_flows.append(self.endpoint.allocator, .{
            .stream_id = stream_id,
            .flow = .init(self.config.initial_send_max_stream_data),
        });
        return &self.stream_send_flows.items[self.stream_send_flows.items.len - 1].flow;
    }

    fn recvStreamFlow(self: *Connection, stream_id: u64) Error!*StreamRecvFlowEntry {
        for (self.stream_recv_flows.items) |*entry| {
            if (entry.stream_id == stream_id) return entry;
        }
        try self.stream_recv_flows.append(self.endpoint.allocator, .{
            .stream_id = stream_id,
            .flow = try .init(self.config.initial_receive_max_stream_data, self.config.stream_receive_window),
        });
        return &self.stream_recv_flows.items[self.stream_recv_flows.items.len - 1];
    }
};

pub fn sendFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
) Error!void {
    const payload = try encodeFrames(endpoint.allocator, options.frames);
    defer endpoint.allocator.free(payload);
    try sendPayload(endpoint, to, keys, .{
        .destination_connection_id = options.destination_connection_id,
        .packet_number = options.packet_number,
        .packet_number_len = options.packet_number_len,
        .key_phase = options.key_phase,
        .payload = payload,
    });
}

pub fn encodeFrames(allocator: std.mem.Allocator, frames: []const quic.Frame) Error![]u8 {
    var payload: std.ArrayList(u8) = .empty;
    errdefer payload.deinit(allocator);
    for (frames) |frame| try frame.write(&payload, allocator);
    return payload.toOwnedSlice(allocator);
}

fn sendPayload(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: PayloadSendOptions,
) Error!void {
    const packet = try quic.protection.sealShortPacket(endpoint.allocator, keys, .{
        .destination_connection_id = options.destination_connection_id,
        .packet_number = options.packet_number,
        .packet_number_len = options.packet_number_len,
        .key_phase = options.key_phase,
        .payload = options.payload,
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

fn countStreamBytes(frames: []const quic.Frame) u64 {
    var total: u64 = 0;
    for (frames) |frame| {
        if (frame == .stream) total += frame.stream.data.len;
    }
    return total;
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
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
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
}

test "QUIC 1-RTT connection retransmits PTO payload and clears recovery on ACK" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const server_cid = [_]u8{ 0x35, 0x36, 0x37, 0x38 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xa1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xa2} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_data = 4,
        .initial_receive_max_stream_data = 4,
    });
    defer server.deinit();

    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 0, .data = "lost", .fin = false } }};
    try client.send(&frames);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());

    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.packet.packet_number);
    try std.testing.expectEqualStrings("lost", first.frames[0].stream.data);

    try std.testing.expect(try client.retransmitPto());
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packet_numbers.items.len);

    var retransmitted = try server.receivePacket();
    defer retransmitted.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), retransmitted.packet.packet_number);
    try std.testing.expectEqualStrings("lost", retransmitted.frames[0].stream.data);
    try std.testing.expectEqual(@as(u64, 4), server.recv_data_total);

    try server.sendAck(0);
    var ack_packet = try client.receivePacket();
    defer ack_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), ack_packet.frames[0].ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 1), ack_packet.frames[0].ack.first_ack_range);
    try std.testing.expect(client.sent.packets.items[0].acknowledged);
    try std.testing.expect(client.sent.packets.items[1].acknowledged);
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
    try std.testing.expect(!(try client.retransmitPto()));
}

test "QUIC 1-RTT connection emits DATA_BLOCKED and applies MAX_DATA" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x11, 0x12, 0x13, 0x14 };
    const server_cid = [_]u8{ 0x15, 0x16, 0x17, 0x18 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x81} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x82} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_data = 5,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();

    const too_much = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "123456", .fin = false } }};
    try std.testing.expectError(error.FlowControlBlocked, client.send(&too_much));
    var blocked = try server.receivePacket();
    defer blocked.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 5), blocked.frames[0].data_blocked.maximum_data);

    const grant = [_]quic.Frame{.{ .max_data = .{ .maximum_data = 10 } }};
    try server.send(&grant);
    var grant_packet = try client.receivePacket();
    defer grant_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 10), client.send_flow.limit);

    try client.send(&too_much);
    var data = try server.receivePacket();
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("123456", data.frames[0].stream.data);
}

test "QUIC 1-RTT connection handles stream-level flow control" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const server_cid = [_]u8{ 0x25, 0x26, 0x27, 0x28 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x91} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x92} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_stream_data = 3,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_stream_data = 6,
        .stream_receive_window = 6,
    });
    defer server.deinit();

    const too_much = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "abcd", .fin = false } }};
    try std.testing.expectError(error.FlowControlBlocked, client.send(&too_much));
    var blocked = try server.receivePacket();
    defer blocked.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), blocked.frames[0].stream_data_blocked.stream_id);
    try std.testing.expectEqual(@as(u64, 3), blocked.frames[0].stream_data_blocked.maximum_stream_data);

    const grant = [_]quic.Frame{.{ .max_stream_data = .{ .stream_id = 0, .maximum_stream_data = 8 } }};
    try server.send(&grant);
    var grant_packet = try client.receivePacket();
    defer grant_packet.deinit(allocator);

    try client.send(&too_much);
    var data = try server.receivePacket();
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("abcd", data.frames[0].stream.data);
    const max_stream = (try server.consumeStreamReceived(0, 4)).?;
    try std.testing.expectEqual(@as(u64, 0), max_stream.max_stream_data.stream_id);
    try std.testing.expectEqual(@as(u64, 10), max_stream.max_stream_data.maximum_stream_data);
}
