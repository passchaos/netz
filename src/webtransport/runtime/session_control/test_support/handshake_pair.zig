//! Two independently owned, preconfigured-key H3/WebTransport sessions.
//! CONNECT request and response still traverse the production UDP/H3 parsers.

const std = @import("std");
const runtime = @import("../../../runtime.zig");
const webtransport = @import("../../../mod.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");
const control_mod = @import("../../session_control.zig");
const handshake_stream = @import("../../stream.zig");

pub const Role = enum { client, server };

pub const Pair = struct {
    endpoint: quic.runtime.Endpoint,
    server: runtime.AcceptedHandshakeSession,
    client: runtime.HandshakeClientSession,

    pub fn init(self: *Pair, io: std.Io) !void {
        const allocator = std.testing.allocator;
        self.endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.endpoint.deinit();
        const keys = quic.protection.deriveAes128Keys([_]u8{0xb1} ** quic.protection.secret_len);
        const settings = webtransport.defaultSettings(.{});
        self.client.h3 = try http3.runtime.HandshakeClient.initPreconfigured(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            self.endpoint.address(),
            .{ .quic = .{ .max_datagram_size = 4096 } },
            .{ .local_settings = settings },
            .{
                .receive_keys = keys,
                .send_keys = keys,
                .local_connection_id = "wt-owned-client",
                .peer_connection_id = "wt-owned-server",
                .one_rtt = .{ .enable_pacing = false },
            },
        );
        errdefer self.client.h3.deinit();
        self.server.h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
            &self.endpoint,
            self.client.h3.established.connection.endpoint.address(),
            .{ .local_settings = settings, .auto_date_header = false },
            .{
                .receive_keys = keys,
                .send_keys = keys,
                .local_connection_id = "wt-owned-server",
                .peer_connection_id = "wt-owned-client",
                .one_rtt = .{ .enable_pacing = false },
            },
        );
        errdefer self.server.h3.deinit();
        self.client.h3.control.settings.markSent(settings);
        self.client.h3.control.settings.markReceived(settings);
        self.server.h3.control.settings.markSent(settings);
        self.server.h3.control.settings.markReceived(settings);
        const id = try self.client.h3.startRequest(.{
            .method = "CONNECT",
            .scheme = "https",
            .authority = "localhost",
            .path = "/reject",
            .headers = &.{
                .{ .name = ":protocol", .value = "webtransport" },
                http3.capsule.protocol_header,
            },
        }, null);
        try std.testing.expectEqual(@as(u62, 0), id);
        var request_event = try self.server.h3.receiveRequestEventWithTimeout(.fromSeconds(1));
        defer request_event.deinit(allocator);
        const request = switch (request_event) {
            .message => |*message| switch (message.value) {
                .head => |head| switch (head) {
                    .request => |value| blk: {
                        message.value = .finished;
                        break :blk value;
                    },
                    else => return error.TestUnexpectedResult,
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        };
        var owned_request = runtime.OwnedHandshakeConnectRequest{ .stream_id = id, .request = request };
        errdefer owned_request.deinit(allocator);
        try self.server.h3.acceptConnectResponse(id, .{
            .status = 200,
            .headers = &.{http3.capsule.protocol_header},
            .request_method = "CONNECT",
            .extended_connect = true,
        });
        var response_event = (try self.client.h3.receiveResponseEventWithTimeout(id, .fromSeconds(1))) orelse return error.TestUnexpectedResult;
        defer response_event.deinit(allocator);
        try std.testing.expect(response_event == .head and response_event.head == .response);
        const response = response_event.head.response;
        response_event = .finished;
        var owned_response = response;
        errdefer owned_response.deinit(allocator);
        try self.client.h3.detachResponseStream(id);
        const session_id = webtransport.SessionId.init(id);
        var client_streams = try handshake_stream.initRegistry(allocator, session_id, .client, settings, settings, 8, null, null);
        errdefer client_streams.deinit();
        var server_streams = try handshake_stream.initRegistry(allocator, session_id, .server, settings, settings, 8, null, null);
        errdefer server_streams.deinit();
        self.client = .{
            .h3 = self.client.h3,
            .session_id = session_id,
            .response = response,
            .streams = client_streams,
            .control = try control_mod.Control.init(allocator, session_id),
        };
        self.server = .{
            .h3 = self.server.h3,
            .session_id = session_id,
            .request = owned_request,
            .streams = server_streams,
            .control = try control_mod.Control.init(allocator, session_id),
        };
    }

    pub fn deinit(self: *Pair) void {
        self.client.deinit();
        self.server.deinit();
        self.endpoint.deinit();
    }

    pub fn connection(self: *Pair, role: Role) *quic.one_rtt.Connection {
        return switch (role) {
            .client => &self.client.h3.established.connection,
            .server => &self.server.h3.established.connection,
        };
    }

    pub fn control(self: *Pair, role: Role) *control_mod.Control {
        return switch (role) {
            .client => &self.client.control,
            .server => &self.server.control,
        };
    }

    pub fn receiveProgress(self: *Pair, role: Role, deadline: std.Io.Clock.Timestamp) !void {
        switch (role) {
            .client => try self.client.h3.receiveDetachedResponseProgressWithDeadline(0, deadline),
            .server => try self.server.h3.receiveDetachedRequestProgressWithDeadline(0, deadline),
        }
    }

    pub fn sendCapsules(self: *Pair, receiver: Role, capsules: []const u8) !void {
        switch (receiver) {
            .client => try self.server.h3.sendResponseBodyPaced(0, capsules, false),
            .server => try self.client.h3.sendRequestBodyPaced(0, capsules, false),
        }
        const conn = self.connection(receiver);
        const deadline = std.Io.Clock.Timestamp.fromNow(conn.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        while ((conn.availableReceivedStream(0) orelse @as([]const u8, &.{})).len == 0) {
            try self.receiveProgress(receiver, deadline);
        }
    }

    pub fn openStream(self: *Pair) !u62 {
        const id = try self.client.openBidirectionalStream();
        // Stream association is lazy until the first application write.
        try self.client.sendStream(id, "prefix", false);
        const deadline = std.Io.Clock.Timestamp.fromNow(self.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        while ((self.server.h3.established.connection.availableReceivedStream(id) orelse @as([]const u8, &.{})).len == 0) {
            try self.receiveProgress(.server, deadline);
        }
        return id;
    }

    pub fn receive(self: *Pair, role: Role) !runtime.SessionEvent {
        return switch (role) {
            .client => self.client.receiveSessionEvent(),
            .server => self.server.receiveSessionEvent(),
        };
    }

    pub fn receiveWithTimeout(self: *Pair, role: Role, timeout: std.Io.Duration) !runtime.SessionEvent {
        return switch (role) {
            .client => self.client.receiveSessionEventWithTimeout(timeout),
            .server => self.server.receiveSessionEventWithTimeout(timeout),
        };
    }

    pub fn poll(self: *Pair, role: Role) !?runtime.SessionEvent {
        return switch (role) {
            .client => self.client.pollSessionEvent(),
            .server => self.server.pollSessionEvent(),
        };
    }

    pub fn expectRejected(self: *Pair, role: Role, stream_id: ?u62) !void {
        const conn = self.connection(role);
        const ctrl = self.control(role);
        try std.testing.expect(ctrl.state.closed and ctrl.capsule_error_reported);
        try std.testing.expect((try self.poll(role)) == null);
        try std.testing.expectError(error.InvalidSessionState, ctrl.ensureOpen());
        var buffer: [32]u8 = undefined;
        var outputs = [_][]u8{&buffer};
        var received_count: usize = 99;
        switch (role) {
            .client => {
                try std.testing.expectError(error.InvalidSessionState, self.client.pollStream(&buffer));
                try std.testing.expectError(error.ConnectDatagramAssociationClosed, self.client.pollDatagram());
                try std.testing.expectError(error.ConnectDatagramAssociationClosed, self.client.receiveDatagramWithTimeout(.fromMilliseconds(1)));
                try std.testing.expectError(error.ConnectDatagramAssociationClosed, self.client.receiveDatagramsInto(&outputs, &received_count));
                try std.testing.expectEqual(@as(usize, 0), received_count);
                received_count = 99;
                try std.testing.expectError(error.Timeout, self.client.receiveDatagramsIntoWithDeadline(&outputs, &received_count, .{ .clock = .awake, .raw = .zero }));
                try std.testing.expectEqual(@as(usize, 0), received_count);
            },
            .server => {
                try std.testing.expectError(error.InvalidSessionState, self.server.pollStream(&buffer));
                try std.testing.expectError(error.ConnectDatagramAssociationClosed, self.server.pollDatagram());
                try std.testing.expectError(error.ConnectDatagramAssociationClosed, self.server.receiveDatagramWithTimeout(.fromMilliseconds(1)));
                try std.testing.expectError(error.ConnectDatagramAssociationClosed, self.server.receiveDatagramsInto(&outputs, &received_count));
                try std.testing.expectEqual(@as(usize, 0), received_count);
                received_count = 99;
                try std.testing.expectError(error.Timeout, self.server.receiveDatagramsIntoWithDeadline(&outputs, &received_count, .{ .clock = .awake, .raw = .zero }));
                try std.testing.expectEqual(@as(usize, 0), received_count);
            },
        }
        try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), conn.sendStreamStats(0).?.reset.?.application_error_code);
        try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), conn.recvStreamStats(0).?.stop_sending_sent.?.application_error_code);
        if (stream_id) |id| {
            try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), conn.sendStreamStats(id).?.reset.?.application_error_code);
            try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), conn.recvStreamStats(id).?.stop_sending_sent.?.application_error_code);
        }
    }
};
