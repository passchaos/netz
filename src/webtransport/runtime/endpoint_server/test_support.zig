//! Preconfigured QUIC peers routed through the real shared endpoint owner.

const std = @import("std");
const runtime = @import("../../runtime.zig");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const control = @import("../session_control.zig");
const prefix = @import("../stream/prefix.zig");

pub const Fixture = struct {
    server: runtime.HandshakeServer,
    endpoint: runtime.EndpointServer,
    client: http3.runtime.HandshakeClient,
    endpoint_owned: bool = true,
    handle: quic.endpoint_dispatcher.ConnectionHandle = 71,

    pub fn init(self: *Fixture, io: std.Io) !void {
        const allocator = std.testing.allocator;
        self.endpoint_owned = true;
        self.server = try runtime.HandshakeServer.bindForEndpoint(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_sessions_per_connection = 4 }, .{ .handshake = .{ .local_connection_id = "wt-remove-server" } });
        errdefer self.server.deinit();
        self.endpoint = try runtime.EndpointServer.init(&self.server, .{});
        errdefer self.endpoint.deinit();
        const settings = try webtransport.settingsWithSessionCapacity(.{}, 4);
        const keys = quic.protection.deriveAes128Keys([_]u8{0x73} ** quic.protection.secret_len);
        var parameters = quic.practical_transport_parameters;
        parameters.max_datagram_frame_size = 1200;
        self.client = try http3.runtime.HandshakeClient.initPreconfigured(allocator, io, .{ .ip4 = .loopback(0) }, self.server.address(), .{}, .{ .local_settings = settings }, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-remove-client",
            .peer_connection_id = "wt-remove-server",
            .local_transport_parameters = parameters,
            .peer_transport_parameters = parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
        errdefer self.client.deinit();
        const h3 = try allocator.create(http3.runtime.HandshakeServerSession);
        errdefer allocator.destroy(h3);
        h3.* = try http3.runtime.HandshakeServerSession.initPreconfigured(&self.server.h3.quic_server.endpoint, self.client.address(), .{ .local_settings = settings, .auto_date_header = false }, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-remove-server",
            .peer_connection_id = "wt-remove-client",
            .local_transport_parameters = parameters,
            .peer_transport_parameters = parameters,
            .one_rtt = .{ .enable_pacing = false },
        });
        errdefer h3.deinit();
        for (0..3) |_| {
            _ = try h3.established.connection.openUnidirectionalStream();
            _ = try self.client.established.connection.openUnidirectionalStream();
        }
        h3.control.settings.markSent(settings);
        h3.control.settings.markReceived(settings);
        h3.qpack_encoder_prefix_sent = true;
        h3.qpack_decoder_prefix_sent = true;
        self.client.control.settings.markSent(settings);
        self.client.control.settings.markReceived(settings);
        self.client.qpack_encoder_prefix_sent = true;
        self.client.qpack_decoder_prefix_sent = true;
        try self.endpoint.h3.sessions.ensureUnusedCapacity(allocator, 1);
        try h3.bindDispatcher();
        try self.endpoint.h3.dispatcher.registerConnection(self.handle, &h3.established.connection);
        self.endpoint.h3.sessions.putAssumeCapacity(self.handle, .{ .dispatcher = self.endpoint.h3.dispatcher, .allocator = allocator, .handle = self.handle, .session = h3 });
    }

    pub fn deinit(self: *Fixture) void {
        self.client.deinit();
        if (self.endpoint_owned) self.endpoint.deinit();
        self.server.deinit();
    }

    pub fn connectionSession(self: *Fixture) *http3.runtime.HandshakeServerSession {
        return self.endpoint.h3.session(self.handle).?;
    }

    pub fn receive(self: *Fixture, output: []u8) !runtime.EndpointServerEvent {
        return self.endpoint.receiveWithTimeout(&.{quic.Version.version_1.wireValue()}, .fromSeconds(1), output);
    }

    pub fn addSession(self: *Fixture) !*runtime.EndpointAcceptedSession {
        const id = try self.client.startRequest(.{ .method = "CONNECT", .scheme = "https", .authority = "localhost", .path = "/remove", .headers = &.{.{ .name = ":protocol", .value = "webtransport-h3" }} }, null);
        var output: [16]u8 = undefined;
        var request = try self.receive(&output);
        defer request.deinit(std.testing.allocator);
        try std.testing.expect(request == .session_request);
        const accepted = try self.endpoint.accept(request.session_request);
        const deadline = std.Io.Clock.Timestamp.fromNow(self.client.established.connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        while (true) {
            var response = (try self.client.receiveResponseEventWithDeadline(id, deadline)) orelse continue;
            defer response.deinit(std.testing.allocator);
            if (response != .head) continue;
            try std.testing.expect(response.head == .response and response.head.response.status == 200);
            break;
        }
        try self.client.detachResponseStream(id);
        return accepted;
    }

    pub fn openPeerStream(self: *Fixture, session: *runtime.EndpointAcceptedSession) !u62 {
        const id = try self.client.tryOpenClientBidirectionalStream();
        var storage: [16]u8 = undefined;
        const header = try prefix.header(session.session_id, .bidirectional, &storage);
        if (self.client.established.connection.config.reliable_reset.peer) try self.client.established.connection.setStreamResetPrefix(id, header);
        try self.client.established.connection.send(&.{
            .{ .stream = .{ .stream_id = id, .data = header } },
            .{ .stream = .{ .stream_id = id, .offset = header.len, .data = "body" } },
        });
        var output: [16]u8 = undefined;
        var event = try self.receive(&output);
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .session_event and event.session_event.event == .stream);
        try std.testing.expectEqualStrings("body", output[0..event.session_event.event.stream.data.bytes]);
        return id;
    }

    pub fn closePeer(self: *Fixture, session: *runtime.EndpointAcceptedSession, reason: []const u8, suffix: []const u8) !void {
        var storage: [4 + webtransport.max_close_reason + 16]u8 = undefined;
        const capsule = try control.writeCloseInto(&storage, 77, reason);
        var data: std.ArrayList(u8) = .empty;
        defer data.deinit(std.testing.allocator);
        try data.appendSlice(std.testing.allocator, capsule);
        try data.appendSlice(std.testing.allocator, suffix);
        try self.client.sendRequestBodyPaced(session.session_id.value, data.items, false);
        var output: [16]u8 = undefined;
        var event = try self.receive(&output);
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .session_event and event.session_event.event == .session and event.session_event.event.session == .closed);
        try std.testing.expectEqualStrings(reason, event.session_event.event.session.closed.reason);
    }

    pub fn routeTransport(self: *Fixture) !void {
        const deadline = std.Io.Clock.Timestamp.fromNow(self.server.h3.quic_server.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        var event = try self.endpoint.h3.receiveTransportWithDeadline(&.{quic.Version.version_1.wireValue()}, deadline);
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .packet);
        try self.connectionSession().processRequestPacket(&event.packet.packet);
    }

    pub fn unclaimedFinStream(self: *Fixture, session_id: webtransport.SessionId) !u62 {
        const id: u62 = @intCast(try self.client.established.connection.openUnidirectionalStream());
        var storage: [16]u8 = undefined;
        const header = try prefix.header(session_id, .unidirectional, &storage);
        try self.client.established.connection.send(&.{
            .{ .stream = .{ .stream_id = id, .data = header } },
            .{ .stream = .{ .stream_id = id, .offset = header.len, .data = "unread", .fin = true } },
        });
        while ((if (self.connectionSession().established.connection.recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < header.len + 6) try self.routeTransport();
        return id;
    }

    pub fn expectPeerClosed(self: *Fixture, session_id: webtransport.SessionId, expected_code: u32) !void {
        var reader = try control.Control.init(std.testing.allocator, session_id);
        defer reader.deinit();
        const deadline = std.Io.Clock.Timestamp.fromNow(self.client.established.connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        while (true) {
            if (try reader.pollOnce(&self.client.established.connection)) |event| {
                try std.testing.expect(event == .closed);
                try std.testing.expectEqual(expected_code, event.closed.code);
                break;
            }
            try self.client.receiveDetachedResponseProgressWithDeadline(session_id.value, deadline);
        }
        // Consume the read-abort signal too, so the next server operation also
        // sees the peer's RESET_STREAM response on the removed CONNECT.
        while (self.client.established.connection.sendStreamStats(session_id.value).?.reset == null) try self.client.receiveDetachedResponseProgressWithDeadline(session_id.value, deadline);
    }
};
