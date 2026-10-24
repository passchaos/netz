//! Legacy protected H3 peers; Extended CONNECT crosses the real UDP parsers.
const std = @import("std");
const runtime = @import("../../../runtime.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");
const control = @import("../../session_control.zig");
const reader = @import("../../protected_session_control.zig");

pub const Role = enum { client, server };

pub const Pair = struct {
    server: runtime.ProtectedServer,
    accepted: runtime.AcceptedProtectedSession,
    client: runtime.ProtectedClientSession,

    pub fn init(self: *Pair, io: std.Io) !void {
        const allocator = std.testing.allocator;
        const keys = quic.protection.deriveAes128Keys([_]u8{0xd3} ** quic.protection.secret_len);
        self.server = try runtime.ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } }, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-light-server",
            .peer_connection_id = "wt-light-client",
        });
        errdefer self.server.deinit();
        var config = self.server.h3.config;
        config.local_connection_id = "wt-light-client";
        config.peer_connection_id = "wt-light-server";
        self.client.h3 = try http3.runtime.ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, self.server.address(), .{ .quic = .{ .max_datagram_size = 4096 } }, config);
        errdefer self.client.h3.deinit();
        const id = try self.client.h3.startRequest(.{
            .method = "CONNECT",
            .scheme = "https",
            .authority = "localhost",
            .path = "/light-reset",
            .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
        }, null);
        var pending = try self.server.receiveSessionRequestWithTimeout(.fromSeconds(1));
        var pending_owned = true;
        defer if (pending_owned) pending.deinit();
        self.accepted = try pending.accept();
        pending_owned = false;
        errdefer self.accepted.deinit(allocator);
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        var event = while (true) {
            if (try self.client.h3.receiveResponseEventWithDeadline(id, deadline)) |response| break response;
        };
        defer event.deinit(allocator);
        try std.testing.expect(event == .head and event.head == .response);
        const response = event.head.response;
        const session_control = try control.Control.init(allocator, .init(id));
        event = .finished;
        self.client = .{
            .h3 = self.client.h3,
            .session_id = .init(id),
            .response = response,
            .control = reader.Reader.init(session_control),
        };
    }

    pub fn deinit(self: *Pair) void {
        self.client.deinit();
        self.accepted.deinit(std.testing.allocator);
        self.server.deinit();
    }

    pub fn resetConnect(self: *Pair, receiver: Role, code: u64) !void {
        const id = self.client.session_id.value;
        switch (receiver) {
            .client => {
                const h3 = &self.server.h3;
                try h3.protected_send.sendFrames(&h3.quic_server.endpoint, self.client.h3.quic_client.address(), h3.config.send_keys, h3.config.peer_connection_id, &h3.next_packet_number, &.{.{ .reset_stream = .{
                    .stream_id = id,
                    .application_error_code = code,
                    .final_size = h3.outbound_bodies.find(id).?.send.next_offset,
                } }}, h3.config.max_frames_per_packet);
            },
            .server => {
                const h3 = &self.client.h3;
                try h3.protected_send.sendFrames(&h3.quic_client.endpoint, h3.quic_client.peer, h3.config.send_keys, h3.config.peer_connection_id, &h3.next_packet_number, &.{.{ .reset_stream = .{
                    .stream_id = id,
                    .application_error_code = code,
                    .final_size = h3.outbound_bodies.find(id).?.send.next_offset,
                } }}, h3.config.max_frames_per_packet);
            },
        }
    }

    pub fn receive(self: *Pair, role: Role) !runtime.SessionEvent {
        return self.receiveWithTimeout(role, .fromSeconds(1));
    }

    pub fn receiveWithTimeout(self: *Pair, role: Role, timeout: std.Io.Duration) !runtime.SessionEvent {
        return switch (role) {
            .client => self.client.receiveSessionEventWithTimeout(timeout),
            .server => self.accepted.receiveSessionEventWithTimeout(&self.server, timeout),
        };
    }

    pub fn sendCapsules(self: *Pair, receiver: Role, bytes: []const u8) !void {
        switch (receiver) {
            .client => try self.server.h3.sendResponseBody(self.client.h3.quic_client.address(), self.client.session_id.value, bytes, false),
            .server => try self.client.h3.sendRequestBody(self.client.session_id.value, bytes, false),
        }
    }
};
