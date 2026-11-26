const std = @import("std");
const forwarded_io = @import("../../../internal/testing/forwarded_io.zig");
const webtransport = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const negotiation = @import("negotiation.zig");

const Pair = @import("test_support/pair.zig").Pair;
const parameters = @import("test_support/pair.zig").parameters;

test "WebTransport modern pending CONNECT waits for SETTINGS and retains long caller metadata" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var value = [_]u8{'v'} ** 8192;
    var pair: Pair = undefined;
    try pair.init(threaded.io(), parameters(), parameters(), &.{.{ .name = "x-large", .value = &value }});
    defer pair.deinit();
    value[0] = 'x';
    try std.testing.expect(pair.client.queued_connect != null);
    try std.testing.expectEqual(@as(u64, 0), pair.client.connection().nextLocalBidirectionalStreamId());
    try std.testing.expect(pair.client.connection().sendStreamStats(0) == null);
    try std.testing.expect((try pair.client.pollConnect()) == null);
    try std.testing.expect(pair.client.queued_connect != null);
    try pair.server.ensureSettingsSent();
    try pair.receiveClient();
    for (0..32) |_| {
        if (pair.client.queued_connect == null) break;
        try std.testing.expect((try pair.client.pollConnect()) == null);
    }
    try std.testing.expect(pair.client.queued_connect == null);
    try std.testing.expect(pair.client.h3.?.control.settings.sent);
    try std.testing.expect(pair.client.h3.?.qpack_encoder_prefix_sent);
    try std.testing.expect(pair.client.h3.?.qpack_decoder_prefix_sent);
    try std.testing.expectEqual(@as(u64, 4), pair.client.connection().nextLocalBidirectionalStreamId());
    var event = try pair.server.receiveRequestEventWithTimeout(.fromSeconds(1));
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .message and event.message.value == .head and event.message.value.head == .request);
    const head = event.message.value.head.request;
    try negotiation.validateRequest(&pair.server, head);
    var found = false;
    for (head.headers) |field| {
        if (std.mem.eql(u8, field.name, ":protocol")) try std.testing.expectEqualStrings("webtransport-h3", field.value);
        if (!std.mem.eql(u8, field.name, "x-large")) continue;
        found = true;
        try std.testing.expectEqual(@as(usize, 8192), field.value.len);
        for (field.value) |byte| try std.testing.expectEqual(@as(u8, 'v'), byte);
    }
    try std.testing.expect(found);
}

test "WebTransport modern pending CONNECT rejects missing transport support without opening a request" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ true, false }) |missing_local| {
        inline for (.{ true, false }) |missing_reset| {
            var local = parameters();
            var peer = parameters();
            const invalid = if (missing_local) &local else &peer;
            if (missing_reset) invalid.reset_stream_at = false else invalid.max_datagram_frame_size = 0;
            var pair: Pair = undefined;
            try pair.init(threaded.io(), local, peer, &.{});
            defer pair.deinit();
            try pair.server.ensureSettingsSent();
            try pair.receiveClient();
            const expected_error = if (missing_reset) error.ReliableResetNotNegotiated else error.DatagramsNotNegotiated;
            var rejected = false;
            for (0..4) |_| {
                _ = pair.client.pollConnect() catch |err| {
                    try std.testing.expectEqual(expected_error, err);
                    rejected = true;
                    break;
                };
            }
            try std.testing.expect(rejected);
            try std.testing.expectEqual(@as(u64, 0), pair.client.connection().nextLocalBidirectionalStreamId());
            try std.testing.expect(pair.client.connection().sendStreamStats(0) == null);
            try std.testing.expect(!pair.client.h3.?.request_lifecycle.contains(0));
        }
    }
}

test "WebTransport modern session streams allow the client to omit ENABLE_CONNECT_PROTOCOL" {
    const OwnedPair = @import("../session_control/test_support/handshake_pair.zig").Pair;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: OwnedPair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    pair.client.h3.options.local_settings.enable_connect_protocol = false;
    pair.server.h3.control.settings.peer.enable_connect_protocol = false;
    const id = try pair.client.openBidirectionalStream();
    try pair.client.sendStream(id, "request", true);
    var out: [32]u8 = undefined;
    const request = try pair.server.readStreamWithTimeout(&out, .fromSeconds(1));
    try std.testing.expect(request == .data and request.data.stream_id == id);
    try std.testing.expectEqualStrings("request", out[0..request.data.bytes]);
    try pair.server.sendStream(id, "response", true);
    const response = try pair.client.readStreamWithTimeout(&out, .fromSeconds(1));
    try std.testing.expect(response == .data and response.data.stream_id == id);
    try std.testing.expectEqualStrings("response", out[0..response.data.bytes]);
}

test "WebTransport malformed modern CONNECT sends MESSAGE_ERROR and leaves HTTP3 siblings usable" {
    const rejection = @import("rejection.zig");
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ true, false }) |missing_reset| {
        var local = parameters();
        if (missing_reset) local.reset_stream_at = false;
        var pair: Pair = undefined;
        try pair.init(threaded.io(), local, parameters(), &.{});
        defer pair.deinit();
        try pair.server.ensureSettingsSent();
        try pair.receiveClient();
        while (!try pair.client.preface.poll(&pair.client.h3.?)) {}
        const version: webtransport.Version = if (missing_reset) .draft16 else .legacy;
        while (!try pair.client.queued_connect.?.submit(&pair.client.h3.?, version, 0)) {}
        var event = try pair.server.receiveRequestEventWithTimeout(.fromSeconds(1));
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .message and event.message.value == .head and event.message.value.head == .request);
        const expected = if (missing_reset) error.ReliableResetNotNegotiated else error.InvalidConnect;
        const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(2) });
        try std.testing.expectError(error.Timeout, rejection.validate(&pair.server, 0, event.message.value.head.request, .{ .clock = .real, .raw = .zero }));
        try std.testing.expect(pair.server.established.connection.sendStreamStats(0) == null);
        try std.testing.expect(pair.server.established.connection.recvStreamStats(0).?.stop_sending_sent == null);
        try std.testing.expectError(expected, rejection.validate(&pair.server, 0, event.message.value.head.request, deadline));
        const connection = pair.client.connection();
        while ((if (connection.recvStreamStats(0)) |stats| stats.reset else null) == null) {
            var packet = try connection.receivePacketServicingTimersDeadline(deadline);
            packet.deinit(std.testing.allocator);
        }
        try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, connection.recvStreamStats(0).?.reset.?.application_error_code);
        try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, connection.sendStreamStats(0).?.stopped.?.application_error_code);
        try std.testing.expect(!connection.closed());
        try std.testing.expect(!pair.server.established.connection.closed());
        const sibling = try pair.client.h3.?.startRequest(.{ .method = "GET", .scheme = "https", .authority = "localhost", .path = "/sibling" }, 0);
        try std.testing.expectEqual(@as(u62, 4), sibling);
        while (true) {
            var request_event = try pair.server.receiveRequestEventWithDeadline(deadline);
            defer request_event.deinit(std.testing.allocator);
            if (request_event == .reset) continue;
            if (request_event != .message or request_event.message.stream_id != sibling) continue;
            if (request_event.message.value != .head) continue;
            try std.testing.expect(request_event.message.value.head == .request);
            try std.testing.expectEqualStrings("GET", request_event.message.value.head.request.method);
            break;
        }
        try pair.server.sendResponseWithDeadline(sibling, .{ .status = 200, .body = "usable", .request_method = "GET" }, deadline);
        var response = while (true) {
            if (try pair.client.h3.?.receiveResponseEventWithDeadline(sibling, deadline)) |ready| break ready;
        };
        defer response.deinit(std.testing.allocator);
        try std.testing.expect(response == .head and response.head == .response);
        try std.testing.expectEqual(@as(u16, 200), response.head.response.status);
        try std.testing.expect(!connection.closed());
    }
}

test "WebTransport routed malformed CONNECT retries failed MESSAGE_ERROR cancellation" {
    const FailedSend = struct {
        delegate: std.Io,
        connection: *quic.one_rtt.Connection,
        fail: bool = true,
        sleeps: usize = 0,
        fn send(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            if (self.fail and self.connection.sendStreamStats(0) != null) {
                self.fail = false;
                return .{ error.SystemResources, 0 };
            }
            return self.delegate.vtable.netSend(self.delegate.userdata, socket, messages, flags);
        }
        fn sleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.sleeps += 1;
            return self.delegate.vtable.sleep(self.delegate.userdata, timeout);
        }
    };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io(), parameters(), parameters(), &.{});
    defer pair.deinit();
    try pair.server.ensureSettingsSent();
    try pair.receiveClient();
    while (!try pair.client.preface.poll(&pair.client.h3.?)) {}
    while (!try pair.client.queued_connect.?.submit(&pair.client.h3.?, .legacy, 0)) {}
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(2) });
    while (!pair.server.control.settings.received or
        (if (pair.server.established.connection.recvStreamStats(0)) |stats| stats.highest_received_offset else 0) == 0)
    {
        try pair.server.pollControlWithDeadline(deadline);
    }
    _ = try pair.server.established.connection.tryFlushPendingAck();
    var admission = runtime.HandshakeAdmission{ .h3 = pair.server, .limits = .{} };
    defer pair.server = admission.h3;
    try admission.h3.bindDispatcher();
    const original_io = pair.server_endpoint.io;
    var failed = FailedSend{ .delegate = original_io, .connection = admission.connection() };
    pair.server_endpoint.io = forwarded_io.observer(&failed, .{ .netSend = FailedSend.send, .sleep = FailedSend.sleep });
    defer pair.server_endpoint.io = original_io;
    const connection = admission.connection();
    try std.testing.expectError(error.SystemResources, admission.pollSessionRequest());
    try std.testing.expect(admission.rejection_pending != null);
    try std.testing.expect(connection.sendStreamStats(0).?.reset == null);
    try std.testing.expectEqual(@as(usize, 0), failed.sleeps);
    try std.testing.expect(!connection.closed());
    try std.testing.expectError(error.InvalidConnect, admission.pollSessionRequest());
    try std.testing.expect(admission.rejection_pending == null);
    try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, connection.sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expectEqual(@as(usize, 0), failed.sleeps);
    try std.testing.expect(!connection.closed());
}
