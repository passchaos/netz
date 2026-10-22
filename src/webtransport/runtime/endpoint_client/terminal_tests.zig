const std = @import("std");
const client_mod = @import("../endpoint_client.zig");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const session_control = @import("../session_control.zig");
const handshake_stream = @import("../stream.zig");
const ObservedBatchSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

const Fixture = struct {
    peer_endpoint: quic.runtime.Endpoint,
    peer: quic.one_rtt.Connection,
    client: client_mod.Client,

    // Initialize in place: the peer connection borrows peer_endpoint.
    fn init(self: *Fixture, io: std.Io) !void {
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

    fn deinit(self: *Fixture) void {
        self.client.deinit();
        self.peer.deinit();
        self.peer_endpoint.deinit();
    }

    fn addSession(self: *Fixture) !*client_mod.Session {
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

    fn appendConnect(self: *Fixture, session: *client_mod.Session, bytes: []const u8, fin: bool) !void {
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

    fn close(self: *Fixture, session: *client_mod.Session, trailing: []const u8) !void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(std.testing.allocator);
        var storage: [64]u8 = undefined;
        const capsule = try session_control.writeCloseInto(&storage, 77, "done");
        try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = capsule, .consumed = 0 }).write(&encoded, std.testing.allocator);
        try encoded.appendSlice(std.testing.allocator, trailing);
        try self.appendConnect(session, encoded.items, false);
    }

    fn poll(self: *Fixture, session: *client_mod.Session) !?client_mod.Event {
        var buffer: [32]u8 = undefined;
        return self.client.poll(session.session_id, &buffer);
    }

    fn expectClose(self: *Fixture, session: *client_mod.Session) !void {
        const event = (try self.poll(session)) orelse return error.TestUnexpectedResult;
        try std.testing.expect(event == .session and event.session == .closed);
        try std.testing.expectEqual(@as(u32, 77), event.session.closed.code);
        try std.testing.expectEqualStrings("done", event.session.closed.reason);
    }

    fn queueDatagram(self: *Fixture, session: *client_mod.Session, payload: []const u8) !void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(std.testing.allocator);
        try (http3.Datagram{
            .quarter_stream_id = session.session_id.quarterStreamId(),
            .payload = payload,
        }).write(&encoded, std.testing.allocator);
        try self.client.h3.connect_datagrams.route(encoded.items);
    }

    fn expectWireCancellation(self: *Fixture, session_id: u62, expect_reset: bool) !void {
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

test "WebTransport endpoint client rejects coalesced data after CLOSE and preserves sibling" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const closing = try fixture.addSession();
    const sibling = try fixture.addSession();
    try fixture.close(closing, &.{0xff});
    try fixture.expectClose(closing);
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(closing));
    try std.testing.expect(closing.control.handledPostTerminalData());
    try std.testing.expect(!closing.close_response_pending);
    try std.testing.expect(!closing.control.local_close_sent);
    try fixture.expectWireCancellation(closing.session_id.value, true);
    try fixture.queueDatagram(closing, "late");
    try fixture.queueDatagram(sibling, "sibling");
    try std.testing.expect((try fixture.poll(closing)) == null);
    var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .datagram);
    try std.testing.expectEqualStrings("sibling", event.datagram.payload);
    _ = try sibling.openBidirectionalStream(&fixture.client);
}

test "WebTransport endpoint client retries post-CLOSE cancellation without replying FIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    try fixture.close(session, &.{0xff});
    try fixture.expectClose(session);
    const endpoint = fixture.client.h3.established.connection.endpoint;
    const original_io = endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    var vtable = original_io.vtable.*;
    vtable.netSend = ObservedBatchSend.netSend;
    endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
    defer endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, fixture.poll(session));
    try std.testing.expect(!session.control.handledPostTerminalData());
    try std.testing.expect(session.close_response_pending);
    try std.testing.expect(!session.control.local_close_sent);
    observed.fail_on_call = null;
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(session));
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try std.testing.expect((try fixture.poll(session)) == null);
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try fixture.expectWireCancellation(session.session_id.value, true);
}

test "WebTransport endpoint client rejects late data after its close reply FIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    try fixture.close(session, &.{});
    try fixture.expectClose(session);
    try std.testing.expect((try fixture.poll(session)) == null);
    try std.testing.expect(session.control.local_close_sent);
    try fixture.appendConnect(session, &.{0xff}, false);
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(session));
    try fixture.expectWireCancellation(session.session_id.value, false);
    try std.testing.expect((try fixture.poll(session)) == null);
}

test "WebTransport endpoint client tears down associated streams after peer CLOSE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const stream_id = try session.openBidirectionalStream(&fixture.client);
    try quic.one_rtt.testing.applyReceivedFrames(&fixture.client.h3.established.connection, 20, &.{.{ .stream = .{
        .stream_id = stream_id,
        .data = "late",
    } }}, null, .not_ect);
    try fixture.queueDatagram(session, "late");
    try fixture.close(session, &.{});
    try fixture.expectClose(session);
    // One FIN, one RESET_STREAM, then one STOP_SENDING; no application data.
    for (0..4) |_| try std.testing.expect((try fixture.poll(session)) == null);
    const stream = session.streams.get(stream_id).?;
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.send_reset.?.http3_code);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.stop_sent.?.http3_code);
    try std.testing.expectError(error.InvalidSessionState, session.sendDatagram(&fixture.client, "late"));
}

test "WebTransport endpoint client removal rejects pending data before FIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const id = session.session_id;
    try fixture.close(session, &.{0xff});
    try fixture.expectClose(session);
    try std.testing.expect(try fixture.client.removeSession(id));
    try fixture.expectWireCancellation(id.value, true);
    try std.testing.expect(fixture.client.session(id) == null);
}

test "WebTransport endpoint client hides data and cleans streams after local CLOSE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const stream_id = try session.openBidirectionalStream(&fixture.client);
    try quic.one_rtt.testing.applyReceivedFrames(&fixture.client.h3.established.connection, 20, &.{.{ .stream = .{
        .stream_id = stream_id,
        .data = "late",
    } }}, null, .not_ect);
    try fixture.queueDatagram(session, "late");
    try session.close(&fixture.client, 81, "local done");
    for (0..3) |_| try std.testing.expect((try fixture.poll(session)) == null);
    const stream = session.streams.get(stream_id).?;
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.send_reset.?.http3_code);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.stop_sent.?.http3_code);
    try std.testing.expect(!session.control.terminal_reported);
    try std.testing.expect(session.control.local_close_sent);
}

test "WebTransport endpoint client defers paced cancellation while sibling progresses" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    try fixture.close(session, &.{0xff});
    try fixture.expectClose(session);
    const connection = &fixture.client.h3.established.connection;
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expect((try fixture.poll(session)) == null);
    try std.testing.expect(session.close_response_pending);
    try std.testing.expect(!session.control.handledPostTerminalData());
    try fixture.queueDatagram(sibling, "sibling");
    var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .datagram);
    try std.testing.expectEqualStrings("sibling", event.datagram.payload);
    connection.pacer.enabled = false;
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(session));
    try fixture.expectWireCancellation(session.session_id.value, true);
}

test "WebTransport endpoint client cancels malformed capsules and preserves sibling" {
    const cases = [_]struct { bytes: []const u8, fin: bool = false }{
        // Invalid UTF-8, short CLOSE value, oversized CLOSE declaration,
        // nonempty DRAIN, truncated Capsule varint, and truncated H3 DATA.
        .{ .bytes = &.{ 0, 8, 0x68, 0x43, 5, 0, 0, 0, 77, 0xff } },
        .{ .bytes = &.{ 0, 3, 0x68, 0x43, 3 } },
        .{ .bytes = &.{ 0, 4, 0x68, 0x43, 0x44, 5 } },
        .{ .bytes = &.{ 0, 5, 0x80, 0, 0x78, 0xae, 1 } },
        .{ .bytes = &.{ 0, 1, 0x40 }, .fin = true },
        .{ .bytes = &.{ 0, 4, 0x68 }, .fin = true },
    };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for (cases) |case| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        try fixture.appendConnect(session, case.bytes, case.fin);
        try std.testing.expectError(error.InvalidCapsule, fixture.poll(session));
        try std.testing.expect(session.control.capsule_error_rejected);
        try std.testing.expect(session.control.state.closed);
        try std.testing.expect(!session.close_response_pending);
        try std.testing.expect((try fixture.poll(session)) == null);
        try std.testing.expectError(error.InvalidSessionState, session.sendDatagram(&fixture.client, "late"));
        try fixture.expectWireCancellation(session.session_id.value, true);
        try fixture.queueDatagram(sibling, "sibling");
        var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .datagram);
        try std.testing.expectEqualStrings("sibling", event.datagram.payload);
        _ = try sibling.openBidirectionalStream(&fixture.client);
    }
}

test "WebTransport endpoint client retries malformed Capsule rejection after send failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    try fixture.appendConnect(session, &.{ 0, 3, 0x68, 0x43, 3 }, false);
    const endpoint = fixture.client.h3.established.connection.endpoint;
    const original_io = endpoint.io;
    const original_available = fixture.client.h3.established.connection.availableReceivedStream(session.session_id.value).?.len;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    var vtable = original_io.vtable.*;
    vtable.netSend = ObservedBatchSend.netSend;
    endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
    defer endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, fixture.poll(session));
    try std.testing.expect(session.control.capsule_error_pending);
    try std.testing.expect(!session.control.capsule_error_rejected);
    try std.testing.expectEqual(original_available, fixture.client.h3.established.connection.availableReceivedStream(session.session_id.value).?.len);
    try std.testing.expectError(error.InvalidSessionState, session.openBidirectionalStream(&fixture.client));
    observed.fail_on_call = null;
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(session));
    try std.testing.expect((try fixture.poll(session)) == null);
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try fixture.expectWireCancellation(session.session_id.value, true);
}

test "WebTransport endpoint client removal resumes pending malformed Capsule rejection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const id = session.session_id;
    try fixture.appendConnect(session, &.{ 0, 3, 0x68, 0x43, 3 }, false);
    const connection = &fixture.client.h3.established.connection;
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expect((try fixture.poll(session)) == null);
    try std.testing.expect(session.control.capsule_error_pending);
    try std.testing.expectError(error.InvalidSessionState, session.sendDatagram(&fixture.client, "late"));
    connection.pacer.enabled = false;
    try std.testing.expect(try fixture.client.removeSession(id));
    try fixture.expectWireCancellation(id.value, true);
}
