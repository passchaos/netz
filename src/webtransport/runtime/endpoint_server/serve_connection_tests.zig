const std = @import("std");
const runtime = @import("../../runtime.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const Fixture = @import("../connect/test_support/endpoint_pair.zig").Fixture;
const Peer = @import("../connect/test_support/endpoint_pair.zig").Peer;
const versions = [_]u32{quic.Version.version_1.wireValue()};

fn peerFailureScenario(handshake: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    var good = try fixture.addPeer(92, "notify-good-client", "notify-good-server");
    defer good.deinit();
    var bad: ?Peer = if (handshake) null else try fixture.addPeer(91, "notify-bad-client", "notify-bad-server");
    defer if (bad) |*peer| peer.deinit();
    var shutdown: std.Io.Event = .unset;
    const Worker = struct {
        io: std.Io,
        address: std.Io.net.IpAddress,
        good: *Peer,
        bad: ?*Peer,
        shutdown: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.shutdown.set(self.io);
            self.exchange() catch |err| {
                self.err = err;
            };
        }

        fn exchange(self: *@This()) !void {
            if (self.bad) |peer| {
                try peer.client.established.connection.send(&.{.{ .stream = .{
                    .stream_id = 2,
                    .data = &.{@intFromEnum(http3.StreamType.control)},
                    .fin = true,
                } }});
            } else {
                var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, self.io, .{ .ip4 = .loopback(0) }, .{});
                defer endpoint.deinit();
                const attempt = quic.handshake.connectWithTimeout(&endpoint, self.address, .{
                    .original_destination_connection_id = "failed-origin",
                    .local_connection_id = "failed-client",
                    .alpn_protocols = &.{"unsupported"},
                    .handshake_recovery = .{ .initial_pto_ms = 2000, .max_pto_ms = 2000, .max_duration_ms = 2000 },
                }, .fromSeconds(1));
                if (attempt) |value| {
                    var unexpected = value;
                    unexpected.deinit();
                    return error.TestUnexpectedResult;
                } else |err| try std.testing.expectEqual(error.ConnectionClosed, err);
            }
            const id = try self.good.connect(true);
            var response = (try self.good.client.receiveResponseEventWithTimeout(id, .fromSeconds(2))) orelse return error.TestUnexpectedResult;
            defer response.deinit(std.testing.allocator);
            try std.testing.expect(response == .head and response.head == .response);
            try std.testing.expectEqual(@as(u16, 200), response.head.response.status);
            try self.good.client.detachResponseStream(id);
            try self.good.client.established.connection.sendDatagram("\x00alive");
            var echo = try self.good.client.receiveConnectDatagramWithTimeout(id, .fromSeconds(2));
            defer echo.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("echo", echo.payload);
        }
    };
    var worker = Worker{ .io = io, .address = fixture.endpoint.address(), .good = &good, .bad = if (bad) |*peer| peer else null, .shutdown = &shutdown };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        thread.join();
    };
    const Handler = struct {
        handshake: bool,
        failures: usize = 0,
        accepted: bool = false,
        received: bool = false,
        echo_session: ?runtime.EndpointSessionKey = null,

        fn echoWhenReady(self: *@This(), server: *runtime.EndpointServer) !void {
            if (self.failures == 0) return;
            const key = self.echo_session orelse return;
            const session = server.sessionById(key.handle, key.session_id) orelse return error.TestUnexpectedResult;
            try session.sendDatagram("echo");
            self.echo_session = null;
        }

        fn handle(self: *@This(), server: *runtime.EndpointServer, event: runtime.ServeEvent) !void {
            switch (event) {
                .handshake_failed => |failure| {
                    try std.testing.expect(self.handshake);
                    try std.testing.expectEqual(error.MissingAlpn, failure.err);
                    self.failures += 1;
                    try self.echoWhenReady(server);
                },
                .connection_failed => |failure| {
                    try std.testing.expect(!self.handshake);
                    try std.testing.expectEqual(@as(quic.endpoint_dispatcher.ConnectionHandle, 91), failure.handle);
                    try std.testing.expectEqual(error.ClosedCriticalStream, failure.err);
                    try std.testing.expectEqual(http3.ApplicationErrorCode.closed_critical_stream, failure.application_error_code);
                    try std.testing.expect(server.h3.session(failure.handle).?.established.connection.closing());
                    self.failures += 1;
                    try self.echoWhenReady(server);
                },
                .session_request => |pending| {
                    try std.testing.expectEqual(@as(quic.endpoint_dispatcher.ConnectionHandle, 92), pending.handle);
                    _ = try server.accept(pending.handle);
                    self.accepted = true;
                },
                .session_event => |value| {
                    if (value.event.* != .datagram) return;
                    try std.testing.expectEqualStrings("alive", value.event.datagram.datagram.payload);
                    self.received = true;
                    self.echo_session = .{ .handle = value.session.handle, .session_id = value.session.session_id };
                    try self.echoWhenReady(server);
                },
                .connected, .closed => {},
                else => return error.TestUnexpectedResult,
            }
        }
    };
    var handler = Handler{ .handshake = handshake };
    try fixture.endpoint.serveUntil(Handler, &handler, Handler.handle, .{ .shutdown = &shutdown, .supported_versions = &versions });
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), handler.failures);
    try std.testing.expect(handler.accepted and handler.received);
}

test "WebTransport serve loop reports a peer connection protocol failure and serves another connection" {
    try peerFailureScenario(false);
}

test "WebTransport serve loop reports a failed TLS handshake and serves another connection" {
    try peerFailureScenario(true);
}
