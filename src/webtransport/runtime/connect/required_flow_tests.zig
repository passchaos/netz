const std = @import("std");
const webtransport = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const Pair = @import("test_support/pair.zig").Pair;
const parameters = @import("test_support/pair.zig").parameters;
const Fixture = @import("../endpoint_client/test_support.zig").Fixture;
const forwarded_io = @import("../../../internal/testing/forwarded_io.zig");
const native_protocol_io = @import("../../../internal/testing/native_protocol_io.zig");

const FailedSend = struct {
    delegate: std.Io,
    connection: *quic.one_rtt.Connection,
    fail: bool = true,

    fn io(self: *@This()) std.Io {
        return forwarded_io.observer(self, .{ .netSend = send });
    }
    fn send(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        if (self.fail and self.connection.sendStreamStats(0) != null) {
            self.fail = false;
            return .{ error.SystemResources, 0 };
        }
        return self.delegate.vtable.netSend(self.delegate.userdata, socket, messages, flags);
    }
};

test "WebTransport required Session flow control rejects shared and reused opens before CONNECT" {
    try native_protocol_io.run(rejectSharedOpens);
}

fn rejectSharedOpens(io: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    const sibling = try fixture.addSession();
    fixture.client.require_session_flow_control = true;
    fixture.client.h3.control.settings.peer = try webtransport.settingsWithInitialFlowLimits(.{}, 1, .{});
    const next_id = fixture.client.h3.next_stream_id;
    try std.testing.expectError(error.SessionFlowControlRequired, fixture.client.openSessionAttemptWithTimeout(.{
        .authority = "localhost",
    }, .fromMilliseconds(20)));
    try std.testing.expectError(error.SessionFlowControlRequired, runtime.HandshakeClientSession.connectSessionAttemptWithTimeout(&fixture.client.h3, .{
        .authority = "localhost",
        .limits = .{ .require_session_flow_control = true },
    }, .fromMilliseconds(20)));
    try std.testing.expectEqual(next_id, fixture.client.h3.next_stream_id);
    try std.testing.expect(fixture.client.h3.established.connection.sendStreamStats(next_id) == null);
    try std.testing.expect(!fixture.client.h3.request_lifecycle.contains(next_id));
    try std.testing.expectEqual(@as(usize, 0), fixture.client.pending_open_cleanup.count());
    try fixture.queueDatagram(sibling, "alive");
    var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("alive", event.datagram.payload);
    try std.testing.expect(!sibling.control.state.closed);
    try std.testing.expect(!fixture.client.h3.established.connection.closed());
}

test "WebTransport required Session flow control rejects queued CONNECT before stream allocation" {
    try native_protocol_io.run(rejectQueuedConnect);
}

fn rejectQueuedConnect(io: std.Io) !void {
    var pair: Pair = undefined;
    try pair.initWithLimits(io, parameters(), parameters(), &.{}, .{ .require_session_flow_control = true });
    defer pair.deinit();
    pair.server.options.local_settings = try webtransport.settingsWithInitialFlowLimits(.{}, 1, .{});
    try pair.server.ensureSettingsSent();
    try pair.receiveClient();
    var rejected = false;
    for (0..8) |_| {
        _ = pair.client.pollConnect() catch |err| {
            try std.testing.expectEqual(error.SessionFlowControlRequired, err);
            rejected = true;
            break;
        };
    }
    try std.testing.expect(rejected);
    try std.testing.expectEqual(@as(u64, 0), pair.client.connection().nextLocalBidirectionalStreamId());
    try std.testing.expect(pair.client.connection().sendStreamStats(0) == null);
    try std.testing.expect(!pair.client.h3.?.request_lifecycle.contains(0));
    try std.testing.expect(!pair.client.connection().closed());
}

test "WebTransport required Session flow control retries scoped server rejection" {
    try native_protocol_io.run(retryScopedRejection);
}

fn retryScopedRejection(io: std.Io) !void {
    var pair: Pair = undefined;
    try pair.initWithLimits(io, parameters(), parameters(), &.{}, .{ .initial_flow_limits = .{} });
    defer pair.deinit();
    try pair.server.ensureSettingsSent();
    try pair.receiveClient();
    while (pair.client.queued_connect != null) _ = try pair.client.pollConnect();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    while (!pair.server.control.settings.received or
        (if (pair.server.established.connection.recvStreamStats(0)) |stats| stats.highest_received_offset else 0) == 0)
    {
        try pair.server.pollControlWithDeadline(deadline);
    }
    _ = try pair.server.established.connection.tryFlushPendingAck();
    var admission = runtime.HandshakeAdmission{ .h3 = pair.server, .limits = .{ .require_session_flow_control = true } };
    defer pair.server = admission.h3;
    try admission.h3.bindDispatcher();
    const original_io = pair.server_endpoint.io;
    var failed = FailedSend{ .delegate = original_io, .connection = admission.connection() };
    pair.server_endpoint.io = failed.io();
    defer pair.server_endpoint.io = original_io;
    const first = admission.pollSessionRequest();
    // Restore a wrongly admitted Session too, so regressions report the
    // assertion failure without leaving the fixture's transport moved out.
    if (first) |pending| {
        if (pending) |value| {
            admission.h3 = value.h3;
            var request = value.request;
            request.deinit(std.testing.allocator);
        }
    } else |_| {}
    try std.testing.expectError(error.SystemResources, first);
    try std.testing.expect(admission.rejection_pending != null);
    try std.testing.expectError(error.SessionFlowControlRequired, admission.pollSessionRequest());
    try std.testing.expect(admission.rejection_pending == null);
    const connection = admission.connection();
    try std.testing.expectEqual(http3.ApplicationErrorCode.request_rejected, connection.sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expectEqual(http3.ApplicationErrorCode.request_rejected, connection.recvStreamStats(0).?.stop_sending_sent.?.application_error_code);
    try std.testing.expect(!connection.closed());
    // Ordinary HTTP requests can still use this authenticated transport.
    // This fixture has no registered dispatcher; return to its owning reader.
    admission.h3.dispatcher_bound = false;
    const sibling = try pair.client.h3.?.startRequest(.{ .method = "GET", .scheme = "https", .authority = "localhost", .path = "/sibling" }, 0);
    try std.testing.expectEqual(@as(u62, 4), sibling);
    while (true) {
        var event = try admission.h3.receiveRequestEventWithDeadline(deadline);
        defer event.deinit(std.testing.allocator);
        if (event != .message or event.message.stream_id != sibling or event.message.value != .head) continue;
        try std.testing.expectEqualStrings("GET", event.message.value.head.request.method);
        break;
    }
    try admission.h3.sendResponseWithDeadline(sibling, .{ .status = 200, .body = "usable", .request_method = "GET" }, deadline);
}

test "WebTransport required Session flow control rejects a pending server acceptance before 200" {
    try native_protocol_io.run(rejectPendingAcceptance);
}

fn rejectPendingAcceptance(io: std.Io) !void {
    var pair: Pair = undefined;
    try pair.initWithLimits(io, parameters(), parameters(), &.{}, .{ .initial_flow_limits = .{} });
    defer pair.deinit();
    try pair.server.ensureSettingsSent();
    try pair.receiveClient();
    while (pair.client.queued_connect != null) _ = try pair.client.pollConnect();
    var pending = try runtime.HandshakeServer.receiveSessionRequestFromSessionWithTimeout(&pair.server, .{ .require_session_flow_control = true }, .fromSeconds(1));
    defer pending.deinit();
    const original_io = pair.server_endpoint.io;
    var failed = FailedSend{ .delegate = original_io, .connection = &pending.h3.established.connection };
    pair.server_endpoint.io = failed.io();
    defer pair.server_endpoint.io = original_io;
    try std.testing.expectError(error.SystemResources, pending.accept());
    try std.testing.expect(pending.rejection_pending != null);
    try std.testing.expectError(error.SessionFlowControlRequired, pending.accept());
    const connection = &pending.h3.established.connection;
    try std.testing.expectEqual(http3.ApplicationErrorCode.request_rejected, connection.sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expectEqual(@as(u64, 0), connection.sendStreamStats(0).?.reset.?.final_size);
    try std.testing.expect(!connection.closed());
    // Verify the rejection carried over the protected wire to the client.
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while ((if (pair.client.connection().recvStreamStats(0)) |stats| stats.reset else null) == null) {
        var packet = try pair.client.connection().receivePacketServicingTimersDeadline(deadline);
        packet.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(http3.ApplicationErrorCode.request_rejected, pair.client.connection().recvStreamStats(0).?.reset.?.application_error_code);
}
