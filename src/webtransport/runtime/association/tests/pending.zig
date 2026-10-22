const std = @import("std");
const runtime = @import("../../../runtime.zig");
const webtransport = @import("../../../mod.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");

const net = std.Io.net;

test "WebTransport shared endpoint preserves data for a pending sibling Session" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bindForEndpoint(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_sessions_per_connection = 2 }, .{
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
        done: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn response(h3: *http3.runtime.HandshakeClient, id: u62, deadline: std.Io.Clock.Timestamp) !void {
            while (true) {
                var event = (try h3.receiveResponseEventWithDeadline(id, deadline)) orelse continue;
                defer event.deinit(allocator);
                if (event != .head) continue;
                try std.testing.expect(event.head == .response and event.head.response.status == 200);
                try h3.detachResponseStream(id);
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
            try response(&h3, first, deadline);
            const second = try h3.startRequestWithDeadline(.{ .method = "CONNECT", .scheme = "https", .authority = "localhost", .path = "/pending", .headers = &fields }, null, deadline);
            try std.testing.expectEqual(@as(u62, 4), second);
            const stream = try h3.tryOpenClientBidirectionalStream();
            var storage: [16]u8 = undefined;
            const prefix = try webtransport.BidirectionalStreamHeader.writeInto(&storage, .init(second));
            try h3.established.connection.send(&.{
                .{ .stream = .{ .stream_id = stream, .data = prefix } },
                .{ .stream = .{ .stream_id = stream, .offset = prefix.len, .data = "ahead", .fin = true } },
            });
            try h3.sendConnectDatagram(first, "barrier");
            try response(&h3, second, deadline);
            try h3.sendConnectDatagram(second, "after");
            try self.done.wait(self.io);
        }
    };
    var worker = Worker{ .io = io, .address = server.address() };
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
    var stream_seen = false;
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
                        try std.testing.expectEqualStrings("barrier", value.datagram.payload);
                        barrier = true;
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
            _ = try endpoint.accept(pending.?);
            pending = null;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), endpoint.sessionCountForConnection(handle.?));
    worker.done.set(io);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}
