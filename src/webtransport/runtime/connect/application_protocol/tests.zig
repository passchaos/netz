const std = @import("std");
const forwarded_io = @import("../../../../internal/testing/forwarded_io.zig");
const webtransport = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");
const Pair = @import("../test_support/pair.zig").Pair;
const parameters = @import("../test_support/pair.zig").parameters;
const prefix = @import("../../stream/prefix.zig");

fn begin(pair: *Pair, io: std.Io, fields: []const http3.Qpack.HeaderField, protocols: webtransport.application_protocol.Policy) !void {
    try pair.initWithProtocols(io, parameters(), parameters(), fields, protocols);
    errdefer pair.deinit();
    try pair.server.ensureSettingsSent();
    try pair.receiveClient();
    for (0..32) |_| {
        if (pair.client.queued_connect == null) return;
        try std.testing.expect((try pair.client.pollConnect()) == null);
    }
    return error.TestUnexpectedResult;
}

fn takeRequest(pair: *Pair) !runtime.OwnedHandshakeConnectRequest {
    var event = try pair.server.receiveRequestEventWithTimeout(.fromSeconds(1));
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .message and event.message.value == .head and event.message.value.head == .request);
    const result = runtime.OwnedHandshakeConnectRequest{ .stream_id = event.message.stream_id, .request = event.message.value.head.request };
    event.message.value = .finished;
    return result;
}

fn receiveAttempt(pair: *Pair) !runtime.HandshakeConnectAttempt {
    for (0..16) |_| {
        if (try pair.client.pollConnect()) |attempt| return attempt;
        try pair.receiveClient();
    }
    return error.TestUnexpectedResult;
}

test "WebTransport application protocol runtime selects client preference and exposes decoded values" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var first = [_]u8{ 'p', '2' };
    const values = [_][]const u8{ &first, "quoted\"value" };
    var pair: Pair = undefined;
    try pair.initWithProtocols(threaded.io(), parameters(), parameters(), &.{}, .{ .values = &values, .required = true });
    defer pair.deinit();
    first = .{ 'x', 'x' };
    try pair.server.ensureSettingsSent();
    try pair.receiveClient();
    for (0..16) |_| {
        if (pair.client.queued_connect == null) break;
        _ = try pair.client.pollConnect();
    }
    const request = try takeRequest(&pair);
    var pending = runtime.PendingHandshakeSession{
        .h3 = pair.server,
        .request = request,
        .session_id = .init(request.stream_id),
        .limits = .{ .application_protocols = .{ .values = &.{ "quoted\"value", "p2" }, .required = true } },
    };
    pair.server_owned = false;
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    try std.testing.expect(pending.offeredApplicationProtocols().?.containsValue("p2"));
    var server = try pending.accept();
    pending_owned = false;
    defer server.deinit();
    try std.testing.expect(server.applicationProtocol().?.eql("p2"));
    var attempt = try receiveAttempt(&pair);
    var attempt_owned = true;
    defer if (attempt_owned) attempt.deinit();
    var client = try attempt.requireAccepted();
    attempt_owned = false;
    defer client.deinit();
    try std.testing.expect(client.applicationProtocol().?.eql("p2"));
}

test "WebTransport application protocol no-common server decision remains retryable before status 200" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try begin(&pair, threaded.io(), &.{}, .{ .values = &.{"p1"}, .required = true });
    defer pair.deinit();
    const request = try takeRequest(&pair);
    var pending = runtime.PendingHandshakeSession{
        .h3 = pair.server,
        .request = request,
        .session_id = .init(request.stream_id),
        .limits = .{ .application_protocols = .{ .values = &.{"other"}, .required = true } },
    };
    pair.server_owned = false;
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    try std.testing.expectError(error.NoCommonApplicationProtocol, pending.accept());
    try std.testing.expect(pending.h3.established.connection.sendStreamStats(0) == null);
    pending.limits.application_protocols.values = &.{"p1"};
    var accepted = try pending.accept();
    pending_owned = false;
    defer accepted.deinit();
    try std.testing.expect(accepted.applicationProtocol().?.eql("p1"));
}

fn sendRawResponse(pair: *Pair, value: ?[]const u8, buffered_stream: bool) !?u62 {
    const allocator = std.testing.allocator;
    var fields: [1]http3.Qpack.HeaderField = undefined;
    if (value) |wire| fields[0] = .{ .name = webtransport.application_protocol.selected_header, .value = wire };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Response{ .status = 200, .headers = fields[0..@intFromBool(value != null)], .request_method = "CONNECT", .extended_connect = true }).write(&encoded, allocator);
    if (!buffered_stream) {
        try pair.server.established.connection.send(&.{.{ .stream = .{ .stream_id = 0, .data = encoded.items } }});
        return null;
    }
    var storage: [16]u8 = undefined;
    const header = try prefix.header(.init(0), .unidirectional, &storage);
    const id = try pair.server.tryOpenServerUnidirectionalStreamWithResetPrefix(header);
    try pair.server.established.connection.send(&.{
        .{ .stream = .{ .stream_id = 0, .data = encoded.items } },
        .{ .stream = .{ .stream_id = id, .data = header } },
        .{ .stream = .{ .stream_id = id, .offset = header.len, .data = "buffered" } },
    });
    return id;
}

test "WebTransport application protocol rejects bad success responses with scoped ALPN resets" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]?[]const u8{ "\"unoffered\"", null, "42", "\"p1\", \"p2\"" }) |response| {
        var pair: Pair = undefined;
        try begin(&pair, threaded.io(), &.{}, .{ .values = &.{"p1"}, .required = response == null or !std.mem.eql(u8, response.?, "\"unoffered\"") });
        defer pair.deinit();
        var request = try takeRequest(&pair);
        defer request.deinit(std.testing.allocator);
        const data_stream = (try sendRawResponse(&pair, response, true)).?;
        try pair.receiveClient();
        var rejected = false;
        for (0..16) |_| {
            _ = pair.client.pollConnect() catch |err| {
                try std.testing.expectEqual(error.ApplicationProtocolNegotiationFailed, err);
                rejected = true;
                break;
            };
            if (pair.client.protocol_rejection == null) try pair.receiveClient();
        }
        try std.testing.expect(rejected);
        try std.testing.expectEqual(webtransport.ApplicationErrorCode.alpn_error, pair.client.connection().sendStreamStats(0).?.reset.?.application_error_code);
        try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, pair.client.connection().recvStreamStats(data_stream).?.stop_sending_sent.?.application_error_code);
        try std.testing.expect(!pair.client.connection().closed());
        const sibling = try pair.client.h3.?.startRequest(.{ .method = "GET", .scheme = "https", .authority = "localhost", .path = "/sibling" }, 0);
        try std.testing.expectEqual(@as(u62, 4), sibling);
    }
}

test "WebTransport application protocol optional malformed response is ignored" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try begin(&pair, threaded.io(), &.{}, .{ .values = &.{"p1"} });
    defer pair.deinit();
    var request = try takeRequest(&pair);
    defer request.deinit(std.testing.allocator);
    _ = try sendRawResponse(&pair, "42", false);
    var attempt = try receiveAttempt(&pair);
    var attempt_owned = true;
    defer if (attempt_owned) attempt.deinit();
    var client = try attempt.requireAccepted();
    attempt_owned = false;
    defer client.deinit();
    try std.testing.expect(client.applicationProtocol() == null);
}

test "WebTransport application protocol endpoint rejection preserves an existing Session" {
    const Fixture = @import("../../endpoint_client/test_support.zig").Fixture;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    fixture.peer.config.local_max_datagram_frame_size = 1200;
    fixture.peer.config.peer_max_datagram_frame_size = 1200;
    fixture.peer.config.reliable_reset = .{ .local = true, .peer = true };
    const first = try fixture.addSession();
    const Worker = struct {
        fixture: *Fixture,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const peer = &self.fixture.peer;
            const deadline = std.Io.Clock.Timestamp.fromNow(peer.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(3) });
            while ((if (peer.recvStreamStats(4)) |stats| stats.highest_received_offset else 0) == 0) {
                var packet = try peer.receivePacketServicingTimersDeadline(deadline);
                packet.deinit(std.testing.allocator);
            }
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(std.testing.allocator);
            try (http3.Response{ .status = 200, .headers = &.{.{ .name = "wt-protocol", .value = "\"unoffered\"" }}, .request_method = "CONNECT", .extended_connect = true }).write(&encoded, std.testing.allocator);
            try peer.send(&.{.{ .stream = .{ .stream_id = 4, .data = encoded.items } }});
            var reset = false;
            var datagram = false;
            while (!reset or !datagram) {
                var packet = try peer.receivePacketServicingTimersDeadline(deadline);
                defer packet.deinit(std.testing.allocator);
                if (peer.recvStreamStats(4).?.reset) |received| {
                    try std.testing.expectEqual(webtransport.ApplicationErrorCode.alpn_error, received.application_error_code);
                    reset = true;
                }
                for (packet.frames) |frame| {
                    if (frame != .datagram) continue;
                    const parsed = try webtransport.Datagram.parse(frame.datagram.data);
                    try std.testing.expectEqual(@as(u62, 0), parsed.session_id.value);
                    try std.testing.expectEqualStrings("alive", parsed.payload);
                    datagram = true;
                }
            }
        }
    };
    var worker = Worker{ .fixture = &fixture };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    try std.testing.expectError(error.ApplicationProtocolNegotiationFailed, fixture.client.openSessionWithTimeout(.{
        .authority = "localhost",
        .path = "/bad-protocol",
        .application_protocols = .{ .values = &.{"p1"}, .required = true },
    }, .fromSeconds(2)));
    try std.testing.expectEqual(@as(usize, 1), fixture.client.sessionCount());
    try std.testing.expect(!fixture.client.h3.established.connection.closed());
    try first.sendDatagram(&fixture.client, "alive");
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "WebTransport application protocol dispatcher keeps failed ALPN cancellation retryable" {
    const FailedSend = struct {
        delegate: std.Io,
        pending: *runtime.PendingHandshakeConnect,
        failed: bool = false,
        sleeps: usize = 0,
        fn send(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            if (!self.failed and self.pending.protocol_rejection != null) {
                self.failed = true;
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
    try begin(&pair, threaded.io(), &.{}, .{ .values = &.{"p1"}, .required = true });
    defer pair.deinit();
    var request = try takeRequest(&pair);
    defer request.deinit(std.testing.allocator);
    _ = try sendRawResponse(&pair, "\"unoffered\"", false);
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(std.testing.allocator, &pair.client_endpoint);
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 51;
    try dispatcher.registerConnection(handle, pair.client.connection());
    const original_io = pair.client_endpoint.io;
    var failed = FailedSend{ .delegate = original_io, .pending = &pair.client };
    pair.client_endpoint.io = forwarded_io.observer(&failed, .{ .netSend = FailedSend.send, .sleep = FailedSend.sleep });
    defer pair.client_endpoint.io = original_io;
    while (!failed.failed) {
        try pair.receiveClient();
        _ = pair.client.pollConnectForDispatcher(&dispatcher, handle) catch |err| {
            try std.testing.expectEqual(error.SystemResources, err);
            break;
        };
    }
    try std.testing.expect(failed.failed);
    try std.testing.expect(pair.client.protocol_rejection != null);
    try std.testing.expect(pair.client.connection().sendStreamStats(0).?.reset == null);
    try std.testing.expectEqual(@as(usize, 0), failed.sleeps);
    try std.testing.expect(!pair.client.connection().closed());
    var rejected = false;
    for (0..8) |_| {
        _ = pair.client.pollConnectForDispatcher(&dispatcher, handle) catch |err| {
            try std.testing.expectEqual(error.ApplicationProtocolNegotiationFailed, err);
            rejected = true;
            break;
        };
    }
    try std.testing.expect(rejected);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.alpn_error, pair.client.connection().sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expectEqual(@as(usize, 0), failed.sleeps);
}
