const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const http3 = @import("../../../http3/mod.zig");
const support = @import("test_support/handshake_pair.zig");
const Pair = support.Pair;
const Role = support.Role;
const control_mod = @import("../session_control.zig");
const ObservedBatchSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;
const native_protocol_io = @import("../../../internal/testing/native_protocol_io.zig");
const forwarded_io = @import("../../../internal/testing/forwarded_io.zig");

test "WebTransport standalone malformed capsules terminate both handshake roles" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const stream_id = try pair.openStream();
        try pair.sendCapsules(role, &.{ 0x68, 0x43, 3 });
        try std.testing.expectError(error.InvalidCapsule, pair.receive(role));
        try pair.expectRejected(role, stream_id);
    }
}

test "WebTransport standalone malformed Capsule deadline resumes cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const stream_id = try pair.openStream();
        try pair.sendCapsules(role, &.{ 0x68, 0x43, 3 });
        const conn = pair.connection(role);
        conn.pacer = .initWithRateLimit(true, 1200, 1, 0);
        conn.pacer.budget = 0;
        conn.pacer.setLastSentTimeNs(0);
        try std.testing.expectError(error.Timeout, pair.receiveWithTimeout(role, .fromMilliseconds(5)));
        const ctrl = pair.control(role);
        try std.testing.expect(ctrl.capsule_error_pending and !ctrl.capsule_error_rejected);
        try std.testing.expectError(error.InvalidSessionState, ctrl.ensureOpen());
        conn.pacer.enabled = false;
        try std.testing.expectError(error.InvalidCapsule, pair.receiveWithTimeout(role, .fromSeconds(1)));
        try pair.expectRejected(role, stream_id);
    }
}

const PaceAfterFirstSend = struct {
    delegate: std.Io,
    table: std.Io.VTable = undefined,
    connection: *quic.one_rtt.Connection,
    calls: usize = 0,

    fn io(self: *@This()) std.Io {
        self.table = forwarded_io.table(from, baseIo, mapTimeout);
        self.table.netSend = netSend;
        return .{ .userdata = self, .vtable = &self.table };
    }
    fn from(userdata: ?*anyopaque) *@This() {
        return @ptrCast(@alignCast(userdata.?));
    }
    fn baseIo(self: *@This()) std.Io {
        return self.delegate;
    }
    fn mapTimeout(_: *@This(), timeout: std.Io.Timeout) std.Io.Timeout {
        return timeout;
    }

    fn netSend(
        userdata: ?*anyopaque,
        handle: std.Io.net.Socket.Handle,
        messages: []std.Io.net.OutgoingMessage,
        flags: std.Io.net.SendFlags,
    ) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        self.calls += 1;
        const result = self.delegate.vtable.netSend(self.delegate.userdata, handle, messages, flags);
        if (self.calls == 1 and result[1] != 0) {
            self.connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
            self.connection.pacer.budget = 0;
            self.connection.pacer.setLastSentTimeNs(0);
        }
        return result;
    }
};

test "WebTransport standalone retains malformed Capsule error through cleanup timeout" {
    try native_protocol_io.run(retainedMalformedCapsule);
}

fn retainedMalformedCapsule(io: std.Io) !void {
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(io);
        defer pair.deinit();
        const stream_id = try pair.openStream();
        try pair.sendCapsules(role, &.{ 0x68, 0x43, 3 });
        const conn = pair.connection(role);
        const original_io = conn.endpoint.io;
        var observed = PaceAfterFirstSend{ .delegate = original_io, .connection = conn };
        conn.endpoint.io = observed.io();
        defer conn.endpoint.io = original_io;
        try std.testing.expectError(error.Timeout, pair.receiveWithTimeout(role, .fromMilliseconds(5)));
        const ctrl = pair.control(role);
        try std.testing.expect(ctrl.capsule_error_rejected and !ctrl.capsule_error_reported);
        try std.testing.expectEqual(@as(usize, 1), observed.calls);
        try std.testing.expect(conn.sendStreamStats(stream_id).?.reset == null);
        conn.pacer.enabled = false;
        try std.testing.expectError(error.InvalidCapsule, pair.receiveWithTimeout(role, .fromSeconds(1)));
        try pair.expectRejected(role, stream_id);
    }
}

test "WebTransport standalone CLOSE suffix rejection preserves deadline and metadata" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        var storage: [64]u8 = undefined;
        const close = try control_mod.writeCloseInto(&storage, 77, "done");
        storage[close.len] = 0xff;
        try pair.sendCapsules(role, storage[0 .. close.len + 1]);
        const conn = pair.connection(role);
        conn.pacer = .initWithRateLimit(true, 1200, 1, 0);
        conn.pacer.budget = 0;
        conn.pacer.setLastSentTimeNs(0);
        try std.testing.expectError(error.Timeout, pair.receiveWithTimeout(role, .fromMilliseconds(5)));
        conn.pacer.enabled = false;
        const event = try pair.receiveWithTimeout(role, .fromSeconds(1));
        try std.testing.expect(event == .closed);
        try std.testing.expectEqual(@as(u32, 77), event.closed.code);
        try std.testing.expectEqualStrings("done", event.closed.reason);
        try std.testing.expect(pair.control(role).handledPostTerminalData());
        try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), conn.sendStreamStats(0).?.reset.?.application_error_code);
        try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), conn.recvStreamStats(0).?.stop_sending_sent.?.application_error_code);
        try std.testing.expect((try pair.poll(role)) == null);
    }
}

test "WebTransport standalone dispatcher retains rejection through bounded cleanup" {
    try native_protocol_io.run(dispatcherRejection);
}

fn dispatcherRejection(io: std.Io) !void {
    var pair: Pair = undefined;
    try pair.init(io);
    defer pair.deinit();
    const stream_id = try pair.openStream();
    try pair.sendCapsules(.client, &.{ 0x68, 0x43, 3 });
    const conn = pair.connection(.client);
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(std.testing.allocator, conn.endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, conn);
    // Hand receive ownership to the dispatcher for this scope, then restore
    // the Pair's endpoint ownership before its normal teardown.
    pair.client.h3.owns_endpoint = false;
    defer pair.client.h3.owns_endpoint = true;
    try pair.client.h3.bindDispatcher();
    pair.client.dispatcher = &dispatcher;
    pair.client.dispatcher_handle = 1;
    defer {
        _ = dispatcher.unregisterConnection(1) catch false;
        pair.client.dispatcher = null;
        pair.client.dispatcher_handle = null;
        pair.client.h3.dispatcher_bound = false;
    }
    const original_io = conn.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io };
    conn.endpoint.io = observed.io();
    defer conn.endpoint.io = original_io;
    // CONNECT cancellation, associated RESET_STREAM, then STOP_SENDING each
    // occupy one poll. The original protocol error is reported after all three.
    for (1..4) |calls| {
        try std.testing.expect((try pair.client.pollSessionEvent()) == null);
        try std.testing.expectEqual(calls, observed.calls);
        try std.testing.expect(!pair.client.control.capsule_error_reported);
        try std.testing.expect(dispatcher.nextTimerDeadline() != null);
    }
    try std.testing.expectError(error.InvalidCapsule, pair.client.pollSessionEvent());
    // Blocking raw receivers still reject dispatcher ownership even after
    // the Session becomes terminal. Check that boundary, then hand ownership
    // back before running the common standalone post-rejection matrix.
    try std.testing.expectError(error.InvalidDispatcherState, pair.client.receiveDatagramWithTimeout(.fromSeconds(1)));
    _ = dispatcher.unregisterConnection(1) catch false;
    pair.client.dispatcher = null;
    pair.client.dispatcher_handle = null;
    pair.client.h3.dispatcher_bound = false;
    pair.client.h3.owns_endpoint = true;
    try pair.expectRejected(.client, stream_id);
    try std.testing.expectEqual(@as(usize, 3), observed.calls);
}
