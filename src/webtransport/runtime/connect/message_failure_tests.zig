const std = @import("std");
const forwarded_io = @import("../../../internal/testing/forwarded_io.zig");
const runtime = @import("../../runtime.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const support = @import("test_support/endpoint_pair.zig");
const Fixture = support.Fixture;
const malformed = @import("test_support/malformed_head.zig");
const versions = [_]u32{quic.Version.version_1.wireValue()};

fn sendMalformed(peer: *support.Peer, kind: malformed.Kind) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try malformed.write(&bytes, std.testing.allocator, kind);
    try peer.client.established.connection.send(&.{.{ .stream = .{ .stream_id = 0, .data = bytes.items } }});
}

test "WebTransport malformed HTTP3 HEADERS retain cancellation through socket failure" {
    const FailedSend = struct {
        delegate: std.Io,
        connection: *quic.one_rtt.Connection,
        fn send(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            if (self.connection.sendStreamStats(0) != null) return .{ error.SystemResources, 0 };
            return self.delegate.vtable.netSend(self.delegate.userdata, socket, messages, flags);
        }
    };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    var peer = try fixture.addPeer(91, "message-client", "message-server");
    defer peer.deinit();
    try sendMalformed(&peer, .missing_method);
    const original_io = fixture.template.h3.quic_server.endpoint.io;
    var output: [16]u8 = undefined;
    {
        var failed = FailedSend{ .delegate = original_io, .connection = &peer.server.established.connection };
        fixture.template.h3.quic_server.endpoint.io = forwarded_io.observer(&failed, .{ .netSend = FailedSend.send });
        defer fixture.template.h3.quic_server.endpoint.io = original_io;
        try std.testing.expectError(error.SystemResources, fixture.endpoint.receiveWithTimeout(&versions, .fromSeconds(1), &output));
    }
    try std.testing.expect(fixture.endpoint.request_rejection_pending.contains(peer.handle));
    try std.testing.expect(peer.server.established.connection.sendStreamStats(0).?.reset == null);
    // No new peer packet is required to complete the retained rejection.
    try std.testing.expectError(error.MissingMethod, fixture.endpoint.receiveOnce(&versions, .{ .clock = .awake, .raw = .fromMilliseconds(1) }, &output));
    try std.testing.expect(!fixture.endpoint.request_rejection_pending.contains(peer.handle));
    try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, peer.server.established.connection.sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expect(!peer.server.established.connection.closed());
}

fn coalescedScenario(kind: malformed.Kind) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    var peer = try fixture.addPeer(91, "message-client", "message-server");
    defer peer.deinit();
    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    var valid: std.ArrayList(u8) = .empty;
    defer valid.deinit(allocator);
    try malformed.write(&invalid, allocator, kind);
    try (http3.Request{ .method = "CONNECT", .path = "/valid", .authority = "localhost", .headers = &.{.{ .name = ":protocol", .value = "webtransport-h3" }} }).writeWithSettings(&valid, allocator, peer.client.control.settings.peer);
    try peer.client.established.connection.send(&.{
        .{ .stream = .{ .stream_id = 0, .data = invalid.items } },
        .{ .stream = .{ .stream_id = 4, .data = valid.items } },
    });
    var shutdown: std.Io.Event = .unset;
    const Watcher = struct {
        peer: *support.Peer,
        shutdown: *std.Io.Event,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            const connection = &self.peer.client.established.connection;
            defer self.shutdown.set(connection.endpoint.io);
            self.receive(connection) catch |err| {
                self.err = err;
            };
        }
        fn receive(_: *@This(), connection: *quic.one_rtt.Connection) !void {
            const deadline = std.Io.Clock.Timestamp.fromNow(connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
            while ((if (connection.recvStreamStats(4)) |stats| stats.highest_received_offset else 0) == 0) {
                var packet = try connection.receivePacketServicingTimersDeadline(deadline);
                packet.deinit(std.testing.allocator);
            }
        }
    };
    var watcher = Watcher{ .peer = &peer, .shutdown = &shutdown };
    const thread = try std.Thread.spawn(.{}, Watcher.run, .{&watcher});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        thread.join();
    };
    const Handler = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        expected: http3.runtime.Error,
        failures: usize = 0,
        accepted: bool = false,

        fn handle(self: *@This(), server: *runtime.EndpointServer, event: runtime.ServeEvent) !void {
            switch (event) {
                .connect_rejected => |failure| {
                    try std.testing.expectEqual(runtime.ConnectRejectionReason.http3_request_error, failure.reason);
                    try std.testing.expectEqual(self.expected, failure.http3_error.?);
                    try std.testing.expectEqual(@as(u62, 0), failure.session_id.value);
                    self.failures += 1;
                },
                .session_request => |pending| {
                    try std.testing.expectEqual(@as(usize, 1), self.failures);
                    try std.testing.expectEqual(@as(u62, 4), pending.session_id.value);
                    _ = try server.accept(pending.handle);
                    self.accepted = true;
                    self.shutdown.set(self.io);
                },
                .connected, .closed => {},
                else => return error.TestUnexpectedResult,
            }
        }
    };
    var handler = Handler{ .io = io, .shutdown = &shutdown, .expected = if (kind == .missing_method) error.MissingMethod else error.InvalidHeader };
    try fixture.endpoint.serveUntil(Handler, &handler, Handler.handle, .{ .shutdown = &shutdown, .supported_versions = &versions });
    thread.join();
    joined = true;
    if (watcher.err) |err| return err;
    try std.testing.expect(handler.accepted);
}

fn applyOnePacket(fixture: *Fixture, peer: *support.Peer) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(fixture.template.h3.quic_server.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    var event = try fixture.endpoint.h3.receiveTransportWithDeadline(&versions, deadline);
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .packet and event.packet.connection_handle == peer.handle);
    try peer.server.processRequestPacket(&event.packet.packet);
}

test "WebTransport malformed HTTP3 HEADERS transfer explicit rejection ownership from the parser" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    var peer = try fixture.addPeer(91, "message-client", "message-server");
    defer peer.deinit();
    try sendMalformed(&peer, .missing_method);
    try applyOnePacket(&fixture, &peer);
    var result = (try peer.server.pollRequestEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result == .failure);
    try std.testing.expectEqual(error.MissingMethod, result.failure.err);
    try std.testing.expectEqual(@as(u62, 0), result.failure.stream_id);
    try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, result.failure.application_error_code);
    try std.testing.expect(peer.server.established.connection.sendStreamStats(0) == null);
    try peer.server.tryCancelRequest(result.failure.stream_id, result.failure.application_error_code);
    try std.testing.expect(peer.server.established.connection.sendStreamStats(0).?.reset != null);
}

test "WebTransport malformed HTTP3 HEADERS owned polling propagates local allocation failures" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    var peer = try fixture.addPeer(91, "message-client", "message-server");
    defer peer.deinit();
    try sendMalformed(&peer, .missing_method);
    try applyOnePacket(&fixture, &peer);
    const original_allocator = peer.server.qpack_decode.allocator;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    {
        peer.server.qpack_decode.allocator = failing.allocator();
        defer peer.server.qpack_decode.allocator = original_allocator;
        try std.testing.expectError(error.OutOfMemory, peer.server.pollRequestEventOnceWithFailure());
    }
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(!peer.server.established.connection.closed());
    var result = (try peer.server.pollRequestEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result == .failure and result.failure.err == error.MissingMethod);
}

test "WebTransport malformed HTTP3 HEADERS QPACK errors retain connection scope" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    var peer = try fixture.addPeer(91, "message-client", "message-server");
    defer peer.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = &.{ 0, 0, 0x80 }, .consumed = 0 }).write(&bytes, std.testing.allocator);
    try peer.client.established.connection.send(&.{.{ .stream = .{ .stream_id = 0, .data = bytes.items } }});
    try applyOnePacket(&fixture, &peer);
    try std.testing.expectError(error.QpackDecompressionFailed, peer.server.pollRequestEventOnceWithFailure());
    try std.testing.expect(peer.server.established.connection.closing());
    try std.testing.expect(peer.server.established.connection.sendStreamStats(0) == null);
}

test "WebTransport malformed HTTP3 HEADERS report missing method and admit a coalesced sibling" {
    try coalescedScenario(.missing_method);
}

test "WebTransport malformed HTTP3 HEADERS report invalid fields and admit a coalesced sibling" {
    try coalescedScenario(.invalid_header);
}
