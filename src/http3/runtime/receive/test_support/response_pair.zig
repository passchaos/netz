const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");

pub const Pair = struct {
    server_endpoint: quic.runtime.Endpoint,
    client: runtime.HandshakeClient,
    server: quic.one_rtt.Connection,

    pub fn init(self: *Pair, io: std.Io) !void {
        const allocator = std.testing.allocator;
        self.server_endpoint = try .bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
        errdefer self.server_endpoint.deinit();
        const keys = quic.protection.deriveAes128Keys([_]u8{0x52} ** quic.protection.secret_len);
        self.client = try runtime.HandshakeClient.initPreconfigured(allocator, io, .{ .ip4 = .loopback(0) }, self.server_endpoint.address(), .{}, .{}, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "response-client",
            .peer_connection_id = "response-server",
            .local_transport_parameters = quic.practical_transport_parameters,
            .peer_transport_parameters = quic.practical_transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
        errdefer self.client.deinit();
        self.client.control.settings.markSent(.{});
        self.client.control.settings.markReceived(.{});
        self.client.qpack_encoder_prefix_sent = true;
        self.client.qpack_decoder_prefix_sent = true;
        for (0..3) |_| _ = try self.client.established.connection.openUnidirectionalStream();
        self.server = try quic.one_rtt.Connection.init(&self.server_endpoint, .{
            .peer = self.client.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "response-server",
            .peer_connection_id = "response-client",
            .local_endpoint = .server,
            .enable_pacing = false,
        });
        errdefer self.server.deinit();
        for (0..2) |index| {
            const id = try self.client.startRequest(.{ .method = "GET", .path = if (index == 0) "/first" else "/second", .authority = "localhost" }, 0);
            try std.testing.expectEqual(@as(u62, @intCast(index * 4)), id);
            var packet = try self.server.receivePacketServicingTimersDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
            packet.deinit(allocator);
        }
    }

    pub fn deinit(self: *Pair) void {
        self.server.deinit();
        self.client.deinit();
        self.server_endpoint.deinit();
    }

    pub fn send(self: *Pair, frames: []const quic.Frame) !void {
        try self.server.send(frames);
        var packet = try self.client.established.connection.receivePacketServicingTimersDeadline(.fromNow(self.server_endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
        defer packet.deinit(std.testing.allocator);
        try self.client.processResponsePacket(&packet);
    }
};

pub fn missingStatus(list: *std.ArrayList(u8)) !void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(std.testing.allocator);
    try http3.Qpack.encodeLiteralBlock(&block, std.testing.allocator, &.{.{ .name = "x-response", .value = "missing-status" }});
    try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, std.testing.allocator);
}
