const std = @import("std");
const runtime = @import("../../../runtime.zig");
const webtransport = @import("../../../mod.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");

const net = std.Io.net;

const Mode = enum { pending, before_connect, expired, rejected };

fn exercise(mode: Mode) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bindForEndpoint(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_sessions_per_connection = 2, .early_connect_streams = .{ .max_age = if (mode == .expired) .fromMilliseconds(100) else .fromSeconds(30) } }, .{
        .handshake = .{
            .local_connection_id = "wt-pending-root",
            .random = [_]u8{0xd1} ** 32,
            .x25519_secret_key = [_]u8{0xd2} ** 32,
            .handshake_recovery = .{ .initial_pto_ms = 20, .max_pto_ms = 40, .max_duration_ms = 2000 },
        },
    });
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{ .max_pending_handshakes = 1, .inbox_capacity = 8, .handshake_timeout_ms = 2000 });
    defer endpoint.deinit();
    const Worker = struct {
        io: std.Io,
        address: net.IpAddress,
        mode: Mode,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn response(h3: *http3.runtime.HandshakeClient, id: u62, status: u16, deadline: std.Io.Clock.Timestamp) !void {
            while (true) {
                var event = (try h3.receiveResponseEventWithDeadline(id, deadline)) orelse continue;
                defer event.deinit(allocator);
                if (event != .head) continue;
                try std.testing.expect(event.head == .response and event.head.response.status == status);
                if (status == 200) try h3.detachResponseStream(id);
                return;
            }
        }
        fn runFallible(self: *@This()) !void {
            var h3 = try http3.runtime.HandshakeClient.connect(allocator, self.io, .{ .ip4 = .loopback(0) }, self.address, .{}, .{
                .session = .{ .local_settings = webtransport.defaultSettings(.{}) },
                .handshake = .{
                    .original_destination_connection_id = "wt-pending-origin",
                    .local_connection_id = "wt-pending-client",
                    .server_name = "localhost",
                    .random = [_]u8{0xd3} ** 32,
                    .x25519_secret_key = [_]u8{0xd4} ** 32,
                    .handshake_recovery = .{ .initial_pto_ms = 20, .max_pto_ms = 40, .max_duration_ms = 2000 },
                },
            });
            defer h3.deinit();
            const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(5) });
            try h3.ensureSettingsSentWithDeadline(deadline);
            _ = try h3.receivePeerSettingsWithDeadline(deadline);
            const fields = [_]http3.Qpack.HeaderField{.{ .name = ":protocol", .value = "webtransport-h3" }};
            const first = try h3.startRequestWithDeadline(.{ .method = "CONNECT", .scheme = "https", .authority = "localhost", .path = "/first", .headers = &fields }, null, deadline);
            try response(&h3, first, 200, deadline);
            const before_connect = self.mode == .before_connect or self.mode == .expired;
            var second: u62 = 4;
            if (!before_connect) second = try h3.startRequestWithDeadline(.{ .method = "CONNECT", .scheme = "https", .authority = "localhost", .path = "/pending", .headers = &fields }, null, deadline);
            const stream: u62 = if (before_connect) @intCast(try h3.established.connection.openUnidirectionalStream()) else try h3.tryOpenClientBidirectionalStream();
            var storage: [16]u8 = undefined;
            const prefix = try @import("../../stream/prefix.zig").header(.init(second), if (before_connect) .unidirectional else .bidirectional, &storage);
            if (h3.established.connection.config.reliable_reset.peer) try h3.established.connection.setStreamResetPrefix(stream, prefix);
            try h3.established.connection.send(&.{
                .{ .stream = .{ .stream_id = stream, .data = prefix } },
                .{ .stream = .{ .stream_id = stream, .offset = prefix.len, .data = "ahead", .fin = self.mode != .expired and self.mode != .rejected } },
            });
            try h3.sendConnectDatagram(first, "barrier");
            if (self.mode == .before_connect) {
                var released = try h3.receiveConnectDatagramWithDeadline(first, deadline);
                defer released.deinit(allocator);
                try std.testing.expectEqualStrings("release", released.payload);
            } else if (self.mode == .expired) {
                const started = std.Io.Clock.awake.now(self.io);
                while (h3.established.connection.sendStreamStats(stream).?.stopped == null) try h3.receiveDetachedResponseProgressWithDeadline(first, deadline);
                try std.testing.expectEqual(webtransport.ApplicationErrorCode.buffered_stream_rejected, h3.established.connection.sendStreamStats(stream).?.stopped.?.application_error_code);
                try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(self.io)).nanoseconds < std.time.ns_per_s * 2);
            }
            if (before_connect) second = try h3.startRequestWithDeadline(.{ .method = "CONNECT", .scheme = "https", .authority = "localhost", .path = "/pending", .headers = &fields }, null, deadline);
            try std.testing.expectEqual(@as(u62, 4), second);
            try response(&h3, second, if (self.mode == .rejected) 403 else 200, deadline);
            if (self.mode == .rejected) {
                while (h3.established.connection.sendStreamStats(stream).?.stopped == null or
                    (if (h3.established.connection.recvStreamStats(stream)) |stats| stats.reset == null else true)) try h3.receiveDetachedResponseProgressWithDeadline(first, deadline);
                try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, h3.established.connection.sendStreamStats(stream).?.stopped.?.application_error_code);
                try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, h3.established.connection.recvStreamStats(stream).?.reset.?.application_error_code);
            }
            try h3.sendConnectDatagram(if (self.mode == .rejected) first else second, "after");
            try self.done.wait(self.io);
        }
    };
    var worker = Worker{ .io = io, .address = server.address(), .mode = mode };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        worker.done.set(io);
        thread.join();
    };
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(8) });
    var handle: ?quic.endpoint_dispatcher.ConnectionHandle = null;
    var pending: ?quic.endpoint_dispatcher.ConnectionHandle = null;
    var barrier = false;
    var stream_seen = mode == .expired or mode == .rejected;
    var after = false;
    var buffer: [32]u8 = undefined;
    while (!stream_seen or !after) {
        var event = endpoint.receiveWithDeadline(&versions, deadline, &buffer) catch |err| {
            if (worker.err) |client_error| return client_error;
            return err;
        };
        defer event.deinit(allocator);
        switch (event) {
            .connected => |id| handle = id,
            .session_request => |id| {
                const request = endpoint.pendingSession(id).?;
                if (std.mem.eql(u8, request.path(), "/first")) {
                    _ = try endpoint.accept(id);
                } else {
                    pending = id;
                }
            },
            .session_event => |ready| switch (ready.event) {
                .datagram => |value| {
                    if (ready.session_id.value == 0) {
                        if (std.mem.eql(u8, value.datagram.payload, "after")) {
                            try std.testing.expect(mode == .rejected);
                            after = true;
                        } else {
                            try std.testing.expectEqualStrings("barrier", value.datagram.payload);
                            barrier = true;
                            if (mode == .before_connect) try endpoint.session(handle.?).?.sendDatagram("release");
                        }
                    } else {
                        try std.testing.expectEqualStrings("after", value.datagram.payload);
                        after = true;
                    }
                },
                .stream => |value| {
                    try std.testing.expect(ready.session_id.value == 4 and value == .data);
                    try std.testing.expectEqualStrings("ahead", buffer[0..value.data.bytes]);
                    stream_seen = true;
                },
                .session => return error.TestUnexpectedResult,
            },
            .closed, .unrouted => return error.TestUnexpectedResult,
            .handshake_failed => |failure| return failure.err,
        }
        if (pending != null and barrier) {
            // The active Session's poll has seen the early data before acceptance.
            if (mode == .rejected) try endpoint.reject(pending.?, 403, &.{}) else _ = try endpoint.accept(pending.?);
            pending = null;
        }
    }
    try std.testing.expectEqual(@as(usize, if (mode == .rejected) 1 else 2), endpoint.sessionCountForConnection(handle.?));
    worker.done.set(io);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "WebTransport shared endpoint preserves data for a pending sibling Session" {
    try exercise(.pending);
}

test "WebTransport early STREAM arrives before CONNECT on an active sibling connection" {
    try exercise(.before_connect);
}

test "WebTransport early STREAM expiry wakes an otherwise idle endpoint" {
    try exercise(.expired);
}

test "WebTransport early STREAM rejected Session receives SESSION_GONE and keeps its sibling" {
    try exercise(.rejected);
}
