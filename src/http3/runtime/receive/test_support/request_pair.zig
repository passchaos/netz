const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");

pub const Pair = struct {
    server_endpoint: quic.runtime.Endpoint,
    client_endpoint: quic.runtime.Endpoint,
    server: runtime.HandshakeServerSession,
    client: quic.one_rtt.Connection,

    pub fn init(self: *Pair, io: std.Io) !void {
        const allocator = std.testing.allocator;
        self.server_endpoint = try .bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
        errdefer self.server_endpoint.deinit();
        self.client_endpoint = try .bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
        errdefer self.client_endpoint.deinit();
        const keys = quic.protection.deriveAes128Keys([_]u8{0x51} ** quic.protection.secret_len);
        self.server = try runtime.HandshakeServerSession.initPreconfigured(&self.server_endpoint, self.client_endpoint.address(), .{}, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "pending-server",
            .peer_connection_id = "pending-client",
            .local_transport_parameters = quic.practical_transport_parameters,
            .peer_transport_parameters = quic.practical_transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
        errdefer self.server.deinit();
        self.server.control.settings.markSent(.{});
        self.server.control.settings.markReceived(.{});
        self.server.qpack_encoder_prefix_sent = true;
        self.server.qpack_decoder_prefix_sent = true;
        self.client = try quic.one_rtt.Connection.init(&self.client_endpoint, .{
            .peer = self.server_endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "pending-client",
            .peer_connection_id = "pending-server",
            .enable_pacing = false,
        });
    }

    pub fn deinit(self: *Pair) void {
        self.client.deinit();
        self.server.deinit();
        self.client_endpoint.deinit();
        self.server_endpoint.deinit();
    }

    pub fn send(self: *Pair, frames: []const quic.Frame) !void {
        try self.client.send(frames);
        var packet = try self.server.established.connection.receivePacketServicingTimersDeadline(.fromNow(self.server_endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
        defer packet.deinit(std.testing.allocator);
        try self.server.processRequestPacket(&packet);
    }
};

pub fn malformed(list: *std.ArrayList(u8), fields: []const http3.Qpack.HeaderField) !void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(std.testing.allocator);
    try http3.Qpack.encodeLiteralBlock(&block, std.testing.allocator, fields);
    try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, std.testing.allocator);
}
