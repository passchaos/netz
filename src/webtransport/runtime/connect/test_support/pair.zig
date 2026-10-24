const std = @import("std");
const webtransport = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");

pub const Pair = struct {
    client_endpoint: quic.runtime.Endpoint,
    server_endpoint: quic.runtime.Endpoint,
    client: runtime.PendingHandshakeConnect,
    server: http3.runtime.HandshakeServerSession,
    server_owned: bool = true,

    pub fn init(self: *Pair, io: std.Io, local_parameters: quic.TransportParameters, peer_parameters: quic.TransportParameters, fields: []const http3.Qpack.HeaderField) !void {
        return self.initWithProtocols(io, local_parameters, peer_parameters, fields, .{});
    }

    pub fn initWithProtocols(self: *Pair, io: std.Io, local_parameters: quic.TransportParameters, peer_parameters: quic.TransportParameters, fields: []const http3.Qpack.HeaderField, protocols: webtransport.application_protocol.Policy) !void {
        return self.initWithLimits(io, local_parameters, peer_parameters, fields, .{ .application_protocols = protocols });
    }

    pub fn initWithLimits(self: *Pair, io: std.Io, local_parameters: quic.TransportParameters, peer_parameters: quic.TransportParameters, fields: []const http3.Qpack.HeaderField, limits: runtime.Limits) !void {
        self.server_owned = true;
        const allocator = std.testing.allocator;
        self.client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.client_endpoint.deinit();
        self.server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.server_endpoint.deinit();
        const keys = quic.protection.deriveAes128Keys([_]u8{0x79} ** quic.protection.secret_len);
        const established = try quic.handshake.establishPreconfigured(&self.client_endpoint, self.server_endpoint.address(), .client, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "modern-client",
            .peer_connection_id = "modern-server",
            .local_transport_parameters = local_parameters,
            .peer_transport_parameters = peer_parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
        self.client = try runtime.HandshakeClientSession.beginEstablishedConnect(&self.client_endpoint, self.server_endpoint.address(), established, .{
            .authority = "localhost",
            .path = "/modern",
            .origin = "https://localhost",
            .headers = fields,
            .limits = limits,
            .h3 = .{ .max_frames_per_packet = 1 },
        });
        errdefer self.client.deinit();
        self.server = try http3.runtime.HandshakeServerSession.initPreconfigured(&self.server_endpoint, self.client_endpoint.address(), .{ .local_settings = webtransport.defaultSettings(.{}), .auto_date_header = false }, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "modern-server",
            .peer_connection_id = "modern-client",
            .local_transport_parameters = peer_parameters,
            .peer_transport_parameters = local_parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
    }

    pub fn deinit(self: *Pair) void {
        self.client.deinit();
        if (self.server_owned) self.server.deinit();
        self.client_endpoint.deinit();
        self.server_endpoint.deinit();
    }

    pub fn receiveClient(self: *Pair) !void {
        const connection = self.client.connection();
        const deadline = std.Io.Clock.Timestamp.fromNow(connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        var packet = try connection.receivePacketServicingTimersDeadline(deadline);
        defer packet.deinit(std.testing.allocator);
        try self.client.processPacket(&packet);
    }
};

pub fn parameters() quic.TransportParameters {
    var value = quic.practical_transport_parameters;
    value.max_datagram_frame_size = 1200;
    return value;
}
