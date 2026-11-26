//! A protected GET exchange whose two protocol owners remain alive throughout.
const std = @import("std");
const h3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");
const allocator = std.testing.allocator;

pub const Pair = struct {
    endpoint: quic.runtime.Endpoint,
    client: runtime.HandshakeClient,
    server: runtime.HandshakeServerSession,
    head: h3.DecodedRequestHead,
    stream_id: u62,

    pub fn init(self: *Pair, io: std.Io) !void {
        self.endpoint = try .bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.endpoint.deinit();
        const keys = quic.protection.deriveAes128Keys([_]u8{0x5c} ** quic.protection.secret_len);
        self.client = try runtime.HandshakeClient.initPreconfigured(allocator, io, .{ .ip4 = .loopback(0) }, self.endpoint.address(), .{ .quic = .{ .max_datagram_size = 4096 } }, .{}, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "completion-client",
            .peer_connection_id = "completion-server",
            .local_transport_parameters = quic.practical_transport_parameters,
            .peer_transport_parameters = quic.practical_transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
        errdefer self.client.deinit();
        self.server = try runtime.HandshakeServerSession.initPreconfigured(&self.endpoint, self.client.address(), .{ .auto_date_header = false }, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "completion-server",
            .peer_connection_id = "completion-client",
            .local_transport_parameters = quic.practical_transport_parameters,
            .peer_transport_parameters = quic.practical_transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
        errdefer self.server.deinit();
        // Reserve real critical-stream IDs while avoiding unrelated startup
        // traffic. The request and response still use production parsers.
        for (0..3) |_| {
            _ = try self.client.established.connection.openUnidirectionalStream();
            _ = try self.server.established.connection.openUnidirectionalStream();
        }
        self.client.control.settings.markSent(.{});
        self.client.control.settings.markReceived(.{});
        self.server.control.settings.markSent(.{});
        self.server.control.settings.markReceived(.{});
        self.client.qpack_encoder_prefix_sent = true;
        self.client.qpack_decoder_prefix_sent = true;
        self.server.qpack_encoder_prefix_sent = true;
        self.server.qpack_decoder_prefix_sent = true;
        self.stream_id = try self.client.startRequest(.{ .method = "GET", .path = "/completion", .authority = "localhost" }, 0);
        var event = try self.server.receiveRequestEventWithTimeout(.fromSeconds(1));
        defer event.deinit(allocator);
        if (event != .message or event.message.value != .head or event.message.value.head != .request) return error.UnexpectedRequest;
        try std.testing.expectEqual(self.stream_id, event.message.stream_id);
        self.head = event.message.value.head.request;
        event.message.value = .finished;
    }

    pub fn deinit(self: *Pair) void {
        self.head.deinit(allocator);
        self.server.deinit();
        self.client.deinit();
        self.endpoint.deinit();
    }
};
