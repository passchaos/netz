const std = @import("std");
const client_mod = @import("../endpoint_client.zig");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const session_control = @import("../session_control.zig");
const handshake_stream = @import("../stream.zig");
const ObservedBatchSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

pub const Fixture = struct {
    peer_endpoint: quic.runtime.Endpoint,
    peer: quic.one_rtt.Connection,
    client: client_mod.Client,

    // Initialize in place: the peer connection borrows peer_endpoint.
    pub fn init(self: *Fixture, io: std.Io) !void {
        const allocator = std.testing.allocator;
        self.peer_endpoint = try quic.runtime.Endpoint.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_datagram_size = 4096 },
        );
        errdefer self.peer_endpoint.deinit();
        const keys = quic.protection.deriveAes128Keys(
            [_]u8{0xa5} ** quic.protection.secret_len,
        );
        var parameters = quic.practical_transport_parameters;
        parameters.max_datagram_frame_size = 1200;
        const settings = try webtransport.settingsWithSessionCapacity(.{}, 2);
        self.client = .{
            .allocator = allocator,
            .max_sessions = 2,
            .h3 = try http3.runtime.HandshakeClient.initPreconfigured(
                allocator,
                io,
                .{ .ip4 = .loopback(0) },
                self.peer_endpoint.address(),
                .{ .quic = .{ .max_datagram_size = 4096 } },
                .{ .local_settings = settings },
                .{
                    .receive_keys = keys,
                    .send_keys = keys,
                    .local_connection_id = "wt-terminal-client",
                    .peer_connection_id = "wt-terminal-server",
                    .local_transport_parameters = parameters,
                    .peer_transport_parameters = parameters,
                    .one_rtt = .{ .enable_pacing = false },
                },
            ),
        };
        errdefer self.client.deinit();
        self.client.h3.control.settings.markSent(settings);
        self.client.h3.control.settings.markReceived(settings);
        self.peer = try quic.one_rtt.Connection.init(&self.peer_endpoint, .{
            .peer = self.client.h3.established.connection.endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-terminal-server",
            .peer_connection_id = "wt-terminal-client",
            .local_endpoint = .server,
            .enable_pacing = false,
        });
    }

    pub fn deinit(self: *Fixture) void {
        self.client.deinit();
        self.peer.deinit();
        self.peer_endpoint.deinit();
    }

    pub fn addSession(self: *Fixture) !*client_mod.Session {
        const allocator = std.testing.allocator;
        const h3 = &self.client.h3;
        const stream_id = try h3.startRequest(.{
            .method = "CONNECT",
            .scheme = "https",
            .authority = "localhost",
            .path = "/terminal",
            .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
        }, null);
        var response_bytes: std.ArrayList(u8) = .empty;
        defer response_bytes.deinit(allocator);
        try (http3.Response{
            .status = 200,
            .extended_connect = true,
        }).write(&response_bytes, allocator);
        try self.peer.send(&.{.{ .stream = .{
            .stream_id = stream_id,
            .data = response_bytes.items,
        } }});
        var event = (try h3.receiveResponseEventWithTimeout(
            stream_id,
            .fromSeconds(1),
        )) orelse return error.TestUnexpectedResult;
        defer event.deinit(allocator);
        try std.testing.expect(event == .head and event.head == .response);
        try h3.detachResponseStream(stream_id);
        const session = try allocator.create(client_mod.Session);
        errdefer allocator.destroy(session);
        session.* = .{
            .session_id = .init(stream_id),
            .response = event.head.response,
            .streams = try handshake_stream.initRegistry(
                allocator,
                .init(stream_id),
                .client,
                h3.options.local_settings,
                h3.control.settings.peer,
                8,
                null,
                null,
            ),
            .control = try session_control.Control.init(allocator, .init(stream_id)),
        };
        event = .finished;
        try self.client.sessions.put(allocator, stream_id, session);
        return session;
    }

    pub fn appendConnect(self: *Fixture, session: *client_mod.Session, bytes: []const u8, fin: bool) !void {
        const connection = &self.client.h3.established.connection;
        const offset = connection.recvStreamStats(session.session_id.value).?.highest_received_offset;
        try self.peer.send(&.{.{ .stream = .{
            .stream_id = session.session_id.value,
            .offset = offset,
            .data = bytes,
            .fin = fin,
        } }});
        var packet = try connection.receivePacketTimeout(.{
            .duration = .{ .raw = .fromSeconds(1), .clock = .awake },
        });
        defer packet.deinit(std.testing.allocator);
        try self.client.h3.processDetachedResponsePacket(session.session_id.value, &packet);
    }

    pub fn close(self: *Fixture, session: *client_mod.Session, trailing: []const u8) !void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(std.testing.allocator);
        var storage: [64]u8 = undefined;
        const capsule = try session_control.writeCloseInto(&storage, 77, "done");
        try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = capsule, .consumed = 0 }).write(&encoded, std.testing.allocator);
        try encoded.appendSlice(std.testing.allocator, trailing);
        try self.appendConnect(session, encoded.items, false);
    }

    pub fn poll(self: *Fixture, session: *client_mod.Session) !?client_mod.Event {
        var buffer: [32]u8 = undefined;
        return self.client.poll(session.session_id, &buffer);
    }

    pub fn expectClose(self: *Fixture, session: *client_mod.Session) !void {
        const event = (try self.poll(session)) orelse return error.TestUnexpectedResult;
        try std.testing.expect(event == .session and event.session == .closed);
        try std.testing.expectEqual(@as(u32, 77), event.session.closed.code);
        try std.testing.expectEqualStrings("done", event.session.closed.reason);
    }

    pub fn queueDatagram(self: *Fixture, session: *client_mod.Session, payload: []const u8) !void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(std.testing.allocator);
        try (http3.Datagram{
            .quarter_stream_id = session.session_id.quarterStreamId(),
            .payload = payload,
        }).write(&encoded, std.testing.allocator);
        try self.client.h3.connect_datagrams.route(encoded.items);
    }

    pub fn expectWireCancellation(self: *Fixture, session_id: u62, expect_reset: bool) !void {
        var saw_reset = false;
        var saw_stop = false;
        for (0..32) |_| {
            var packet = try self.peer.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
            defer packet.deinit(std.testing.allocator);
            for (packet.frames) |frame| switch (frame) {
                .reset_stream => |reset| if (reset.stream_id == session_id) {
                    try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), reset.application_error_code);
                    saw_reset = true;
                },
                .stop_sending => |stop| if (stop.stream_id == session_id) {
                    try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), stop.application_error_code);
                    saw_stop = true;
                },
                else => {},
            };
            if (saw_stop and (saw_reset or !expect_reset)) break;
        }
        try std.testing.expectEqual(expect_reset, saw_reset);
        try std.testing.expect(saw_stop);
    }
};
