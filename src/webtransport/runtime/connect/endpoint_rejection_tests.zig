const std = @import("std");
const forwarded_io = @import("../../../internal/testing/forwarded_io.zig");
const runtime = @import("../../runtime.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const Fixture = @import("test_support/endpoint_pair.zig").Fixture;
const Peer = @import("test_support/endpoint_pair.zig").Peer;
const versions = [_]u32{quic.Version.version_1.wireValue()};

const FailedCancel = struct {
    delegate: std.Io,
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
    fail: bool = true,
    sleeps: usize = 0,

    fn send(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        if (self.fail and self.connection.sendStreamStats(self.stream_id) != null) {
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

fn retainFailedRejection(fixture: *Fixture, peer: *Peer) !void {
    const stream_id = try peer.connect(false);
    const original_io = fixture.template.h3.quic_server.endpoint.io;
    var failed = FailedCancel{ .delegate = original_io, .connection = &peer.server.established.connection, .stream_id = stream_id };
    fixture.template.h3.quic_server.endpoint.io = forwarded_io.observer(&failed, .{ .netSend = FailedCancel.send, .sleep = FailedCancel.sleep });
    defer fixture.template.h3.quic_server.endpoint.io = original_io;
    var buffer: [16]u8 = undefined;
    try std.testing.expectError(error.SystemResources, fixture.endpoint.receiveWithTimeout(&versions, .fromSeconds(1), &buffer));
    try std.testing.expect(fixture.endpoint.request_rejection_pending.contains(peer.handle));
    try std.testing.expect(peer.server.established.connection.sendStreamStats(stream_id).?.reset == null);
    try std.testing.expectEqual(@as(usize, 0), failed.sleeps);
}

fn blockPacing(peer: *Peer) void {
    const connection = &peer.server.established.connection;
    connection.pacer = quic.pacing.Pacer.initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
}

test "WebTransport endpoint retained rejection retries without new packets and refreshes recovery timer" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    var peer = try fixture.addPeer(91, "retry-client-a", "retry-server-a");
    defer peer.deinit();
    try retainFailedRejection(&fixture, &peer);
    try std.testing.expectEqual(@as(usize, 0), fixture.endpoint.sessions.count());
    // Clear delayed ACK work before the rejected CONNECT arms recovery.
    _ = try peer.server.established.connection.tryFlushPendingAck();
    try fixture.endpoint.h3.dispatcher.refreshConnectionTimer(peer.handle);
    const before = fixture.endpoint.h3.dispatcher.nextTimerDeadline();
    var buffer: [16]u8 = undefined;
    try std.testing.expectError(error.Timeout, fixture.endpoint.receiveWithDeadline(&versions, .{ .clock = .real, .raw = .zero }, &buffer));
    try std.testing.expect(peer.server.established.connection.sendStreamStats(0).?.reset == null);
    // The client performs no more I/O: completion must come from retained work.
    try std.testing.expectError(error.InvalidConnect, fixture.endpoint.receiveOnce(&versions, .{ .clock = .awake, .raw = .fromMilliseconds(1) }, &buffer));
    try std.testing.expect(!fixture.endpoint.request_rejection_pending.contains(peer.handle));
    const connection = &peer.server.established.connection;
    try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, connection.sendStreamStats(0).?.reset.?.application_error_code);
    const timer = connection.nextTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(quic.one_rtt.TimerDeadlineKind.pto, timer.kind);
    if (before) |old| try std.testing.expect(!std.meta.eql(old.timer, timer));
    const scheduled = fixture.endpoint.h3.dispatcher.nextTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(peer.handle, scheduled.connection_id);
    try std.testing.expectEqual(timer, scheduled.timer);
    try std.testing.expect(!connection.closed());
}

test "WebTransport endpoint retained rejection advances another connection while one is pacing blocked" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    var first = try fixture.addPeer(91, "retry-client-a", "retry-server-a");
    defer first.deinit();
    var second = try fixture.addPeer(92, "retry-client-b", "retry-server-b");
    defer second.deinit();
    try retainFailedRejection(&fixture, &first);
    blockPacing(&first);
    try retainFailedRejection(&fixture, &second);
    var buffer: [16]u8 = undefined;
    try std.testing.expectError(error.InvalidConnect, fixture.endpoint.receiveOnce(&versions, .{ .clock = .awake, .raw = .fromMilliseconds(1) }, &buffer));
    try std.testing.expect(fixture.endpoint.request_rejection_pending.contains(first.handle));
    try std.testing.expect(!fixture.endpoint.request_rejection_pending.contains(second.handle));
    try std.testing.expect(first.server.established.connection.sendStreamStats(0).?.reset == null);
    first.server.established.connection.pacer.enabled = false;
    try std.testing.expectError(error.InvalidConnect, fixture.endpoint.receiveOnce(&versions, .{ .clock = .awake, .raw = .fromMilliseconds(1) }, &buffer));
    try std.testing.expectEqual(@as(usize, 0), fixture.endpoint.request_rejection_pending.count());
}

test "WebTransport endpoint retained rejection leaves an accepted sibling readable under pacing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    var peer = try fixture.addPeer(91, "retry-client-a", "retry-server-a");
    defer peer.deinit();
    const session_id = try peer.connect(true);
    var buffer: [16]u8 = undefined;
    var request = try fixture.endpoint.receiveWithTimeout(&versions, .fromSeconds(1), &buffer);
    defer request.deinit(std.testing.allocator);
    try std.testing.expect(request == .session_request);
    const accepted = try fixture.endpoint.accept(peer.handle);
    try std.testing.expectEqual(session_id, accepted.session_id.value);
    try retainFailedRejection(&fixture, &peer);
    blockPacing(&peer);
    try peer.client.established.connection.sendDatagram("\x00alive");
    var event = try fixture.endpoint.receiveWithTimeout(&versions, .fromSeconds(1), &buffer);
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .session_event and event.session_event.event == .datagram);
    try std.testing.expectEqualStrings("alive", event.session_event.event.datagram.datagram.payload);
    try std.testing.expect(fixture.endpoint.request_rejection_pending.contains(peer.handle));
    try std.testing.expect(!accepted.control.state.closed);
    peer.server.established.connection.pacer.enabled = false;
    try std.testing.expectError(error.InvalidConnect, fixture.endpoint.receiveOnce(&versions, .{ .clock = .awake, .raw = .fromMilliseconds(1) }, &buffer));
    try std.testing.expect(!fixture.endpoint.request_rejection_pending.contains(peer.handle));
}
