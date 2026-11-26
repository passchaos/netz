const std = @import("std");
const native_protocol_io = @import("../../../internal/testing/native_protocol_io.zig");
const runtime = @import("../../runtime.zig");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const control_mod = @import("../session_control.zig");
const handshake_stream = @import("../stream.zig");
const ObservedBatchSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

const Fixture = struct {
    endpoint: quic.runtime.Endpoint,
    peer_endpoint: quic.runtime.Endpoint,
    peer: quic.one_rtt.Connection,
    h3: http3.runtime.HandshakeServerSession,
    dispatcher: quic.endpoint_dispatcher.Dispatcher,
    sessions: [2]runtime.EndpointAcceptedSession,

    fn init(self: *Fixture, io: std.Io) !void {
        const allocator = std.testing.allocator;
        self.endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.endpoint.deinit();
        self.peer_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
        errdefer self.peer_endpoint.deinit();
        const keys = quic.protection.deriveAes128Keys([_]u8{0xb5} ** quic.protection.secret_len);
        const settings = try webtransport.settingsWithSessionCapacity(.{}, 2);
        self.h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(&self.endpoint, self.peer_endpoint.address(), .{ .local_settings = settings }, .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-reject-server",
            .peer_connection_id = "wt-reject-client",
            .one_rtt = .{ .enable_pacing = false },
        });
        errdefer self.h3.deinit();
        self.h3.control.settings.markSent(settings);
        self.h3.control.settings.markReceived(settings);
        self.peer = try quic.one_rtt.Connection.init(&self.peer_endpoint, .{
            .peer = self.endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-reject-client",
            .peer_connection_id = "wt-reject-server",
            .enable_pacing = false,
        });
        errdefer self.peer.deinit();
        self.dispatcher = quic.endpoint_dispatcher.Dispatcher.init(allocator, &self.endpoint);
        errdefer self.dispatcher.deinit();
        try self.dispatcher.registerConnection(1, &self.h3.established.connection);
        var initialized: usize = 0;
        errdefer for (self.sessions[0..initialized]) |*session| {
            session.control.deinit();
            session.streams.deinit();
        };
        for (&self.sessions, 0..) |*session, index| {
            const id = webtransport.SessionId.init(@intCast(index * 4));
            try self.h3.connect_datagrams.register(id.value);
            try self.h3.connect_datagrams.markStreamDetached(id.value);
            session.* = .{
                .handle = 1,
                .dispatcher = &self.dispatcher,
                .h3 = &self.h3,
                .request = undefined,
                .session_id = id,
                .streams = try handshake_stream.initRegistry(allocator, id, .server, settings, settings, 8, null, null),
                .control = try control_mod.Control.init(allocator, id),
            };
            initialized += 1;
        }
    }

    fn deinit(self: *Fixture) void {
        for (&self.sessions) |*session| {
            session.control.deinit();
            session.streams.deinit();
        }
        self.dispatcher.deinit();
        self.h3.deinit();
        self.peer.deinit();
        self.peer_endpoint.deinit();
        self.endpoint.deinit();
    }

    fn receive(self: *Fixture, index: usize, bytes: []const u8, fin: bool) !void {
        const id = self.sessions[index].session_id.value;
        try self.peer.send(&.{.{ .stream = .{ .stream_id = id, .data = bytes, .fin = fin } }});
        // A peer that just received STOP_SENDING may submit its RESET_STREAM
        // before this stream's data. Pump both packets without assuming that
        // a send call corresponds to one UDP datagram.
        const deadline = std.Io.Clock.Timestamp.fromNow(self.endpoint.io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        });
        while (true) {
            var packet = try self.h3.established.connection.receivePacketTimeout(.{ .deadline = deadline });
            defer packet.deinit(std.testing.allocator);
            try self.h3.processDetachedRequestPacket(id, &packet);
            const stats = self.h3.established.connection.recvStreamStats(id) orelse continue;
            if (stats.highest_received_offset >= bytes.len and
                (!fin or stats.final_size != null)) break;
        }
    }

    fn poll(self: *Fixture, index: usize) !?runtime.EndpointSessionEvent {
        var buffer: [32]u8 = undefined;
        return runtime.EndpointServer.testing.pollAcceptedSessionEntry(&self.sessions[index], &buffer);
    }

    fn expectCancellation(self: *Fixture) !void {
        var saw_reset = false;
        var saw_stop = false;
        for (0..32) |_| {
            var packet = try self.peer.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
            defer packet.deinit(std.testing.allocator);
            for (packet.frames) |frame| switch (frame) {
                .connection_close => return error.TestUnexpectedResult,
                .reset_stream => |reset| {
                    try std.testing.expectEqual(@as(u62, 0), reset.stream_id);
                    try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), reset.application_error_code);
                    saw_reset = true;
                },
                .stop_sending => |stop| {
                    try std.testing.expectEqual(@as(u62, 0), stop.stream_id);
                    try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), stop.application_error_code);
                    saw_stop = true;
                },
                else => {},
            };
            if (saw_reset and saw_stop) break;
        }
        try std.testing.expect(saw_reset and saw_stop);
    }
};

test "WebTransport endpoint server rejects malformed capsules without closing sibling" {
    const cases = [_]struct { bytes: []const u8, fin: bool = false }{
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
        try fixture.receive(0, case.bytes, case.fin);
        try std.testing.expectError(error.InvalidCapsule, fixture.poll(0));
        const session = &fixture.sessions[0];
        try std.testing.expect(session.control.capsule_error_rejected);
        try std.testing.expect(session.control.state.closed);
        try std.testing.expectError(error.InvalidSessionState, session.sendDatagram("late"));
        try std.testing.expect((try fixture.poll(0)) == null);
        try fixture.expectCancellation();
        // The second CONNECT carries a valid DRAIN on the same QUIC connection.
        try fixture.receive(1, &.{ 0, 5, 0x80, 0, 0x78, 0xae, 0 }, false);
        const sibling = (try fixture.poll(1)) orelse return error.TestUnexpectedResult;
        try std.testing.expect(sibling == .session and sibling.session == .draining);
        try fixture.sessions[1].control.ensureOpen();
        try std.testing.expect(!fixture.h3.established.connection.closing());
        try std.testing.expect(fixture.dispatcher.nextTimerDeadline() != null);
    }
}

test "WebTransport endpoint server defers paced malformed Capsule cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    try fixture.receive(0, &.{ 0, 3, 0x68, 0x43, 3 }, false);
    const connection = &fixture.h3.established.connection;
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expect((try fixture.poll(0)) == null);
    try std.testing.expect(fixture.sessions[0].control.capsule_error_pending);
    try std.testing.expect(!fixture.sessions[0].control.capsule_error_rejected);
    try std.testing.expectError(error.InvalidSessionState, fixture.sessions[0].sendDatagram("late"));
    try std.testing.expect(fixture.dispatcher.nextTimerDeadline() != null);
    connection.pacer.enabled = false;
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(0));
    try fixture.expectCancellation();
}

test "WebTransport endpoint server retries malformed Capsule cancellation after socket failure" {
    try native_protocol_io.run(retryMalformedCapsule);
}

fn retryMalformedCapsule(io: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    try fixture.receive(0, &.{ 0, 3, 0x68, 0x43, 3 }, false);
    const original_io = fixture.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    fixture.endpoint.io = observed.io();
    defer fixture.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, fixture.poll(0));
    try std.testing.expect(fixture.sessions[0].control.capsule_error_pending);
    try std.testing.expect(!fixture.sessions[0].control.capsule_error_rejected);
    try std.testing.expectError(error.InvalidSessionState, fixture.sessions[0].sendDatagram("late"));
    observed.fail_on_call = null;
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(0));
    try std.testing.expect((try fixture.poll(0)) == null);
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try fixture.expectCancellation();
}

test "WebTransport endpoint server suppresses all session events after QUIC termination" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    for (&fixture.sessions) |*session| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(std.testing.allocator);
        try (http3.Datagram{
            .quarter_stream_id = session.session_id.quarterStreamId(),
            .payload = "queued",
        }).write(&encoded, std.testing.allocator);
        try fixture.h3.connect_datagrams.route(encoded.items);
        session.close_response_pending = true;
    }
    fixture.h3.established.connection.failClosedApplication(99, "closed");
    const packet_number = fixture.h3.established.connection.next_packet_number;
    for (&fixture.sessions, 0..) |*session, index| {
        try std.testing.expect((try fixture.poll(index)) == null);
        try std.testing.expect(session.control.connection_terminated and session.control.state.closed);
        try std.testing.expect(!session.close_response_pending);
        try std.testing.expectEqual(@as(usize, 0), try fixture.h3.connect_datagrams.queuedCount(session.session_id.value));
    }
    try std.testing.expectEqual(packet_number, fixture.h3.established.connection.next_packet_number);
}
