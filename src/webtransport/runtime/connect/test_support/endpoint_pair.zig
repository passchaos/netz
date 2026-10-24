const std = @import("std");
const runtime = @import("../../../runtime.zig");
const webtransport = @import("../../../mod.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");

pub const Peer = struct {
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    client: http3.runtime.HandshakeClient,
    server: *http3.runtime.HandshakeServerSession,

    pub fn deinit(self: *Peer) void {
        self.client.deinit();
    }

    pub fn connect(self: *Peer, valid: bool) !u62 {
        return self.client.startRequest(.{
            .method = "CONNECT",
            .scheme = "https",
            .authority = "localhost",
            .path = "/retry",
            .headers = &.{
                .{ .name = ":protocol", .value = if (valid) "webtransport-h3" else "webtransport" },
                .{ .name = "origin", .value = "https://localhost" },
            },
        }, null);
    }
};

/// Real protected QUIC with stable registered HTTP/3 owners, initialized in place.
pub const Fixture = struct {
    template: runtime.HandshakeServer,
    endpoint: runtime.EndpointServer,

    pub fn init(self: *Fixture, io: std.Io) !void {
        self.template = try runtime.HandshakeServer.bindForEndpoint(std.testing.allocator, io, .{ .ip4 = .loopback(0) }, .{
            .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
            .max_sessions_per_connection = 2,
        }, .{ .handshake = .{ .local_connection_id = "retry-template" } });
        errdefer self.template.deinit();
        self.endpoint = try runtime.EndpointServer.init(&self.template, .{});
    }

    pub fn deinit(self: *Fixture) void {
        self.endpoint.deinit();
        self.template.deinit();
    }

    pub fn addPeer(self: *Fixture, handle: quic.endpoint_dispatcher.ConnectionHandle, client_cid: []const u8, server_cid: []const u8) !Peer {
        const allocator = std.testing.allocator;
        const io = self.template.h3.quic_server.endpoint.io;
        const keys = quic.protection.deriveAes128Keys([_]u8{0xd2} ** quic.protection.secret_len);
        const settings = try webtransport.settingsWithSessionCapacity(.{}, 2);
        var parameters = quic.practical_transport_parameters;
        parameters.max_datagram_frame_size = 1200;
        var client = try http3.runtime.HandshakeClient.initPreconfigured(allocator, io, .{ .ip4 = .loopback(0) }, self.endpoint.address(), .{ .quic = .{ .max_datagram_size = 4096 } }, .{ .local_settings = settings }, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = client_cid,
            .peer_connection_id = server_cid,
            .local_transport_parameters = parameters,
            .peer_transport_parameters = parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
        errdefer client.deinit();
        const server = try allocator.create(http3.runtime.HandshakeServerSession);
        errdefer allocator.destroy(server);
        server.* = try http3.runtime.HandshakeServerSession.initPreconfigured(&self.template.h3.quic_server.endpoint, client.address(), .{ .local_settings = settings }, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = server_cid,
            .peer_connection_id = client_cid,
            .local_transport_parameters = parameters,
            .peer_transport_parameters = parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
        errdefer server.deinit();
        client.control.settings.markSent(settings);
        server.control.settings.markReceived(settings);
        try server.ensureSettingsSent();
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        // Establish and acknowledge the real critical prefixes before handing
        // the server's sole receive ownership to the dispatcher.
        while (true) {
            const received_control = if (client.established.connection.recvStreamStats(3)) |stats| stats.highest_received_offset else 0;
            const received_encoder = if (client.established.connection.recvStreamStats(7)) |stats| stats.highest_received_offset else 0;
            const received_decoder = if (client.established.connection.recvStreamStats(11)) |stats| stats.highest_received_offset else 0;
            if (received_control >= server.control_send.next_offset and received_encoder >= server.qpack_encoder_send.next_offset and received_decoder >= server.qpack_decoder_send.next_offset) break;
            var prefix = try client.established.connection.receivePacketServicingTimersDeadline(deadline);
            try client.processResponsePacket(&prefix);
            prefix.deinit(allocator);
        }
        // Raw Connection receives do not run HTTP/3's ACK scheduling hook.
        // Acknowledge the observed critical-stream packets explicitly.
        try client.established.connection.sendAck(0);
        // ACK-only packets can be consumed without yielding an application
        // packet. A bounded receive drains them and verifies actual retirement.
        const ack_deadline = deadline;
        while (server.established.connection.pendingRecoveryCount() != 0) {
            var ack = server.established.connection.receivePacketServicingTimersDeadline(ack_deadline) catch |err| switch (err) {
                error.Timeout => {
                    try std.testing.expectEqual(@as(usize, 0), server.established.connection.pendingRecoveryCount());
                    break;
                },
                else => return err,
            };
            ack.deinit(allocator);
        }
        _ = try server.established.connection.tryFlushPendingAck();
        try server.bindDispatcher();
        try self.endpoint.h3.dispatcher.registerConnection(handle, &server.established.connection);
        errdefer _ = self.endpoint.h3.dispatcher.unregisterConnection(handle) catch {};
        try self.endpoint.h3.sessions.put(allocator, handle, .{
            .dispatcher = self.endpoint.h3.dispatcher,
            .allocator = allocator,
            .handle = handle,
            .session = server,
        });
        return .{ .handle = handle, .client = client, .server = server };
    }
};
