//! Two HTTP/3 owners sharing a real protected UDP CONNECT exchange.
const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");

pub const Role = enum { client, server };

pub const Pair = struct {
    endpoint: quic.runtime.Endpoint,
    client: runtime.HandshakeClient,
    server: runtime.HandshakeServerSession,

    pub fn init(self: *Pair, io: std.Io) !void {
        const allocator = std.testing.allocator;
        self.endpoint = try .bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.endpoint.deinit();
        const keys = quic.protection.deriveAes128Keys([_]u8{0x59} ** quic.protection.secret_len);
        var parameters = quic.practical_transport_parameters;
        parameters.max_datagram_frame_size = 1200;
        const settings = http3.Settings{ .enable_connect_protocol = true, .h3_datagram = true };
        self.client = try runtime.HandshakeClient.initPreconfigured(allocator, io, .{ .ip4 = .loopback(0) }, self.endpoint.address(), .{ .quic = .{ .max_datagram_size = 4096 } }, .{ .local_settings = settings }, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "datagram-client",
            .peer_connection_id = "datagram-server",
            .local_transport_parameters = parameters,
            .peer_transport_parameters = parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
        errdefer self.client.deinit();
        self.server = try runtime.HandshakeServerSession.initPreconfigured(&self.endpoint, self.client.address(), .{ .local_settings = settings, .auto_date_header = false }, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "datagram-server",
            .peer_connection_id = "datagram-client",
            .local_transport_parameters = parameters,
            .peer_transport_parameters = parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
        errdefer self.server.deinit();
        // Reserve control/QPACK IDs while suppressing unrelated startup packets.
        for (0..3) |_| {
            _ = try self.client.established.connection.openUnidirectionalStream();
            _ = try self.server.established.connection.openUnidirectionalStream();
        }
        self.client.control.settings.markSent(settings);
        self.client.control.settings.markReceived(settings);
        self.server.control.settings.markSent(settings);
        self.server.control.settings.markReceived(settings);
        self.client.qpack_encoder_prefix_sent = true;
        self.client.qpack_decoder_prefix_sent = true;
        self.server.qpack_encoder_prefix_sent = true;
        self.server.qpack_decoder_prefix_sent = true;
        try self.addConnect();
    }

    pub fn addConnect(self: *Pair) !void {
        const id = try self.client.startRequest(.{
            .method = "CONNECT",
            .scheme = "https",
            .authority = "localhost",
            .path = "/datagram",
            .headers = &.{.{ .name = ":protocol", .value = "test-datagram" }},
        }, null);
        var request = try self.server.receiveRequestEventWithTimeout(.fromSeconds(1));
        defer request.deinit(std.testing.allocator);
        try std.testing.expect(request == .message and request.message.value == .head);
        try std.testing.expectEqual(id, request.message.stream_id);
        try self.server.acceptConnectResponse(id, .{ .status = 200, .request_method = "CONNECT", .extended_connect = true });
        var response = (try self.client.receiveResponseEventWithTimeout(id, .fromSeconds(1))) orelse return error.TestUnexpectedResult;
        defer response.deinit(std.testing.allocator);
        try std.testing.expect(response == .head and response.head == .response);
        try std.testing.expectEqual(@as(u16, 200), response.head.response.status);
        try self.client.detachResponseStream(id);
    }

    pub fn deinit(self: *Pair) void {
        self.server.deinit();
        self.client.deinit();
        self.endpoint.deinit();
    }

    pub fn connection(self: *Pair, role: Role) *quic.one_rtt.Connection {
        return switch (role) {
            .client => &self.client.established.connection,
            .server => &self.server.established.connection,
        };
    }

    pub fn sendPeer(self: *Pair, receiver: Role, frames: []const quic.Frame) !void {
        return self.connection(if (receiver == .client) .server else .client).send(frames);
    }
};
