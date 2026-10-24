const std = @import("std");
const runtime = @import("../../runtime.zig");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const Fixture = @import("test_support.zig").Fixture;
const versions = [_]u32{quic.Version.version_1.wireValue()};
const SessionFault = enum { capsule, flow, post_close };

fn awaitReset(client: *http3.runtime.HandshakeClient, id: u62) !u64 {
    const connection = &client.established.connection;
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    while ((if (connection.recvStreamStats(id)) |stats| stats.reset else null) == null) {
        var packet = try connection.receivePacketServicingTimersDeadline(deadline);
        packet.deinit(std.testing.allocator);
    }
    return connection.recvStreamStats(id).?.reset.?.application_error_code;
}

fn receiveEcho(client: *http3.runtime.HandshakeClient, id: u62) !void {
    var echo = try client.receiveConnectDatagramWithTimeout(id, .fromSeconds(2));
    defer echo.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("echo", echo.payload);
}

fn rejectedConnectScenario(capacity: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    _ = try fixture.addSession();
    if (capacity) fixture.endpoint.limits.max_sessions_per_connection = 1;
    var shutdown: std.Io.Event = .unset;
    const Worker = struct {
        client: *http3.runtime.HandshakeClient,
        shutdown: *std.Io.Event,
        capacity: bool,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.shutdown.set(self.client.established.connection.endpoint.io);
            self.exchange() catch |err| {
                self.err = err;
            };
        }

        fn exchange(self: *@This()) !void {
            const id = try self.client.startRequest(.{
                .method = "CONNECT",
                .scheme = "https",
                .authority = "localhost",
                .path = "/refused",
                .headers = &.{.{ .name = ":protocol", .value = if (self.capacity) "webtransport-h3" else "webtransport" }},
            }, null);
            try std.testing.expectEqual(@as(u62, 4), id);
            const code: u64 = if (self.capacity) http3.ApplicationErrorCode.request_rejected else http3.ApplicationErrorCode.message_error;
            try std.testing.expectEqual(code, try awaitReset(self.client, id));
            try self.client.established.connection.sendDatagram("\x00alive");
            try receiveEcho(self.client, 0);
        }
    };
    var worker = Worker{ .client = &fixture.client, .shutdown = &shutdown, .capacity = capacity };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        thread.join();
    };
    const Handler = struct {
        expected: runtime.ConnectRejectionReason,
        refused: usize = 0,
        received: bool = false,

        fn handle(self: *@This(), server: *runtime.EndpointServer, event: runtime.ServeEvent) !void {
            try std.testing.expect(server.serve_failure_sink == null);
            switch (event) {
                .connect_rejected => |failure| {
                    try std.testing.expectEqual(@as(u62, 4), failure.session_id.value);
                    try std.testing.expectEqual(self.expected, failure.reason);
                    self.refused += 1;
                    var bytes: [1]u8 = undefined;
                    try std.testing.expectError(error.Timeout, server.receiveWithDeadline(&versions, .{ .clock = .real, .raw = .zero }, &bytes));
                },
                .session_event => |value| {
                    if (value.event.* != .datagram) return;
                    try std.testing.expectEqual(@as(usize, 1), self.refused);
                    try std.testing.expectEqualStrings("alive", value.event.datagram.datagram.payload);
                    try value.session.sendDatagram("echo");
                    self.received = true;
                },
                .connected, .closed => {},
                else => return error.TestUnexpectedResult,
            }
        }
    };
    var handler = Handler{ .expected = if (capacity) .session_limit_exceeded else .invalid_connect };
    try fixture.endpoint.serveUntil(Handler, &handler, Handler.handle, .{ .shutdown = &shutdown, .supported_versions = &versions });
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), handler.refused);
    try std.testing.expect(handler.received);
}

test "WebTransport serve loop observes malformed CONNECT and keeps its accepted sibling running" {
    try rejectedConnectScenario(false);
}

test "WebTransport serve loop observes capacity refusal and keeps its accepted sibling running" {
    try rejectedConnectScenario(true);
}

fn sessionFailureScenario(fault: SessionFault) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    _ = try fixture.addSession();
    _ = try fixture.addSession();
    var shutdown: std.Io.Event = .unset;
    const Worker = struct {
        client: *http3.runtime.HandshakeClient,
        shutdown: *std.Io.Event,
        fault: SessionFault,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.shutdown.set(self.client.established.connection.endpoint.io);
            self.exchange() catch |err| {
                self.err = err;
            };
        }

        fn exchange(self: *@This()) !void {
            var storage: [32]u8 = undefined;
            const capsule: []const u8 = switch (self.fault) {
                .flow => try (webtransport.Capsule{ .max_data = 0 }).writeInto(&storage),
                .capsule => &.{ 0x68, 0x43, 3, 0, 0, 0 },
                .post_close => value: {
                    const close = try @import("../session_control.zig").writeCloseInto(&storage, 77, "done");
                    storage[close.len] = 0;
                    break :value storage[0 .. close.len + 1];
                },
            };
            try self.client.sendRequestBodyPaced(0, capsule, false);
            const code: u64 = if (self.fault == .flow) webtransport.ApplicationErrorCode.flow_control_error else http3.ApplicationErrorCode.message_error;
            try std.testing.expectEqual(code, try awaitReset(self.client, 0));
            try self.client.established.connection.sendDatagram("\x01alive");
            try receiveEcho(self.client, 4);
        }
    };
    var worker = Worker{ .client = &fixture.client, .shutdown = &shutdown, .fault = fault };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        thread.join();
    };
    const Handler = struct {
        fault: SessionFault,
        failures: usize = 0,
        received: bool = false,
        close_seen: bool = false,

        fn handle(self: *@This(), _: *runtime.EndpointServer, event: runtime.ServeEvent) !void {
            switch (event) {
                .session_failed => |failure| {
                    try std.testing.expectEqual(@as(u62, 0), failure.session_id.value);
                    try std.testing.expectEqual(if (self.fault == .flow) error.FlowControlViolation else error.InvalidCapsule, failure.err);
                    if (self.fault == .post_close) try std.testing.expect(self.close_seen);
                    self.failures += 1;
                },
                .session_event => |value| {
                    if (value.event.* == .session and value.event.session == .closed) {
                        try std.testing.expect(self.fault == .post_close);
                        try std.testing.expectEqual(@as(u32, 77), value.event.session.closed.code);
                        self.close_seen = true;
                        return;
                    }
                    if (value.event.* != .datagram) return;
                    try std.testing.expectEqual(@as(usize, 1), self.failures);
                    try std.testing.expectEqual(@as(u62, 4), value.session.session_id.value);
                    try std.testing.expectEqualStrings("alive", value.event.datagram.datagram.payload);
                    try value.session.sendDatagram("echo");
                    self.received = true;
                },
                .connected, .closed => {},
                else => return error.TestUnexpectedResult,
            }
        }
    };
    var handler = Handler{ .fault = fault };
    try fixture.endpoint.serveUntil(Handler, &handler, Handler.handle, .{ .shutdown = &shutdown, .supported_versions = &versions });
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), handler.failures);
    try std.testing.expect(handler.received);
}

test "WebTransport serve loop observes malformed Capsule once and keeps sibling Session running" {
    try sessionFailureScenario(.capsule);
}

test "WebTransport serve loop observes flow violation once and keeps sibling Session running" {
    try sessionFailureScenario(.flow);
}

test "WebTransport serve loop reports stray post-close data after the valid close event" {
    try sessionFailureScenario(.post_close);
}
