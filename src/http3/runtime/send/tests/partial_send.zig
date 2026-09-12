const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const packetizer = @import("../packetizer.zig");
const protected_send_module = @import("../protected.zig");
const body_sender = @import("../body.zig");
const body_batch = @import("../../body_batch.zig");
const outbound_body = @import("../../stream/outbound_body.zig");
const ObservedBatchSend =
    @import("../../../../quic/one_rtt/tests/observed_batch_send.zig")
        .ObservedBatchSend;
const ProtectedSendState = protected_send_module.State;
const OutboundBodySet = outbound_body.Set;
const net = std.Io.net;

const FailOnCall = struct {
    delegate: std.Io,
    fail_on_call: usize,
    calls: usize = 0,

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: net.Socket.Handle,
        messages: []net.OutgoingMessage,
        flags: net.SendFlags,
    ) struct { ?net.Socket.SendError, usize } {
        const self: *FailOnCall = @ptrCast(@alignCast(userdata));
        self.calls += 1;
        if (self.calls == self.fail_on_call) {
            return .{ error.NetworkDown, 0 };
        }
        return self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
    }
};

const FixedClockSend = struct {
    delegate: std.Io,
    now_ns: i96,
    send_calls: usize = 0,
    sleep_calls: usize = 0,
    advance_after_send_ns: i96 = 0,

    fn now(
        userdata: ?*anyopaque,
        _: std.Io.Clock,
    ) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(userdata.?));
        return .fromNanoseconds(self.now_ns);
    }

    fn sleep(
        userdata: ?*anyopaque,
        _: std.Io.Timeout,
    ) std.Io.Cancelable!void {
        const self: *@This() = @ptrCast(@alignCast(userdata.?));
        self.sleep_calls += 1;
        return error.Canceled;
    }

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: net.Socket.Handle,
        messages: []net.OutgoingMessage,
        flags: net.SendFlags,
    ) struct { ?net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata.?));
        self.send_calls += 1;
        const result = self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
        if (result[1] != 0) self.now_ns += self.advance_after_send_ns;
        return result;
    }
};

test "HTTP/3 stateful packetizer fails closed after a visible prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x91} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .enable_pacing = false,
        .tls_handshake_complete = true,
    });
    defer connection.deinit();

    var partial = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 1,
    };
    var vtable = sender.io.vtable.*;
    vtable.netSend = ObservedBatchSend.netSend;
    sender.io = .{ .userdata = &partial, .vtable = &vtable };
    defer sender.io = partial.delegate;

    const frames = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = "first" } },
        .{ .stream = .{ .stream_id = 0, .offset = 5, .data = "second" } },
    };
    try std.testing.expectError(
        error.NetworkDown,
        packetizer.send(allocator, &connection, &frames, 1),
    );
    const close = quic.one_rtt.testing.localCloseInfo(&connection) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(close.application);
    try std.testing.expectEqual(
        http3.ApplicationErrorCode.internal_error,
        close.error_code,
    );
}

test "HTTP/3 stateful packetizer deadline preserves zero progress and closes after visible prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9a} ** quic.protection.secret_len,
    );

    var fixed = FixedClockSend{
        .delegate = sender.io,
        .now_ns = 1_000_000,
    };
    var vtable = sender.io.vtable.*;
    vtable.now = FixedClockSend.now;
    vtable.sleep = FixedClockSend.sleep;
    vtable.netSend = FixedClockSend.netSend;
    sender.io = .{ .userdata = &fixed, .vtable = &vtable };
    defer sender.io = fixed.delegate;

    var zero_progress = try quic.one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "zero-client",
        .peer_connection_id = "zero-server",
        .pacing_max_burst_packets = 1,
        .tls_handshake_complete = true,
    });
    defer zero_progress.deinit();
    quic.one_rtt.testing.exhaustPacingAt(
        &zero_progress,
        @intCast(fixed.now_ns),
    );
    const ping = [_]quic.Frame{.{ .ping = {} }};
    try std.testing.expectError(
        error.Timeout,
        packetizer.sendWithDeadline(
            allocator,
            &zero_progress,
            &ping,
            1,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.now_ns + 1),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed.send_calls);
    try std.testing.expectEqual(@as(usize, 0), fixed.sleep_calls);
    try std.testing.expectEqual(@as(u64, 0), zero_progress.next_packet_number);
    try std.testing.expect(!zero_progress.closed());

    var partial = try quic.one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "partial-client",
        .peer_connection_id = "partial-server",
        .pacing_max_burst_packets = 1,
        .tls_handshake_complete = true,
    });
    defer partial.deinit();
    fixed.send_calls = 0;
    var first: [1000]u8 = .{0xa1} ** 1000;
    var second: [1000]u8 = .{0xa2} ** 1000;
    const frames = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = &first } },
        .{ .stream = .{ .stream_id = 0, .offset = first.len, .data = &second } },
    };
    try std.testing.expectError(
        error.Timeout,
        packetizer.sendWithDeadline(
            allocator,
            &partial,
            &frames,
            1,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.now_ns + 1),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), fixed.send_calls);
    try std.testing.expectEqual(@as(usize, 0), fixed.sleep_calls);
    try std.testing.expect(partial.closed());
    const close = quic.one_rtt.testing.localCloseInfo(&partial) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        http3.ApplicationErrorCode.internal_error,
        close.error_code,
    );
    try std.testing.expectEqualStrings("partial-http3-send", close.reason_phrase);
}

test "HTTP/3 protected sender rejects reuse after a visible prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x92} ** quic.protection.secret_len,
    );
    var send = protected_send_module.State.init(allocator);
    defer send.deinit();
    var next_packet_number: u64 = 0;

    var partial = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 1,
    };
    var vtable = sender.io.vtable.*;
    vtable.netSend = ObservedBatchSend.netSend;
    sender.io = .{ .userdata = &partial, .vtable = &vtable };
    defer sender.io = partial.delegate;

    const frames = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = "first" } },
        .{ .stream = .{ .stream_id = 0, .offset = 5, .data = "second" } },
    };
    try std.testing.expectError(
        error.NetworkDown,
        send.sendFrames(
            &sender,
            receiver.address(),
            keys,
            "server",
            &next_packet_number,
            &frames,
            1,
        ),
    );
    try std.testing.expect(!send.isUsable());
    try std.testing.expectEqual(@as(u64, 2), next_packet_number);

    try std.testing.expectError(
        error.ConnectionUnusable,
        send.sendFrames(
            &sender,
            receiver.address(),
            keys,
            "server",
            &next_packet_number,
            frames[0..1],
            1,
        ),
    );
}

test "HTTP/3 protected sender deadline rejects reuse after a completed batch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9b} ** quic.protection.secret_len,
    );
    var send = ProtectedSendState.init(allocator);
    defer send.deinit();
    var next_packet_number: u64 = 0;

    var fixed = FixedClockSend{
        .delegate = sender.io,
        .now_ns = 1_000_000,
        .advance_after_send_ns = std.time.ns_per_s,
    };
    var vtable = sender.io.vtable.*;
    vtable.now = FixedClockSend.now;
    vtable.netSend = FixedClockSend.netSend;
    sender.io = .{ .userdata = &fixed, .vtable = &vtable };
    defer sender.io = fixed.delegate;

    var frames: [quic.one_rtt.max_batch_packets + 1]quic.Frame = undefined;
    for (&frames, 0..) |*frame, index| {
        frame.* = .{ .stream = .{
            .stream_id = 0,
            .offset = index,
            .data = "x",
        } };
    }
    try std.testing.expectError(
        error.Timeout,
        send.sendFramesWithDeadline(
            &sender,
            receiver.address(),
            keys,
            "server",
            &next_packet_number,
            &frames,
            1,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.now_ns + 1),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), fixed.send_calls);
    try std.testing.expectEqual(
        @as(u64, quic.one_rtt.max_batch_packets),
        next_packet_number,
    );
    try std.testing.expect(!send.isUsable());
    try std.testing.expectError(
        error.ConnectionUnusable,
        send.sendFrames(
            &sender,
            receiver.address(),
            keys,
            "server",
            &next_packet_number,
            frames[0..1],
            1,
        ),
    );
}

test "HTTP/3 protected sender detects a prior completed packet batch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x93} ** quic.protection.secret_len,
    );
    var send = ProtectedSendState.init(allocator);
    defer send.deinit();
    var next_packet_number: u64 = 0;

    var fail_second_call = FailOnCall{
        .delegate = sender.io,
        .fail_on_call = 2,
    };
    var vtable = sender.io.vtable.*;
    vtable.netSend = FailOnCall.netSend;
    sender.io = .{ .userdata = &fail_second_call, .vtable = &vtable };
    defer sender.io = fail_second_call.delegate;

    var frames: [quic.one_rtt.max_batch_packets + 1]quic.Frame = undefined;
    for (&frames, 0..) |*frame, index| {
        frame.* = .{ .stream = .{
            .stream_id = 0,
            .offset = index,
            .data = "x",
        } };
    }
    try std.testing.expectError(
        error.NetworkDown,
        send.sendFrames(
            &sender,
            receiver.address(),
            keys,
            "server",
            &next_packet_number,
            &frames,
            1,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), fail_second_call.calls);
    try std.testing.expect(!send.isUsable());
    try std.testing.expectEqual(
        @as(u64, quic.one_rtt.max_batch_packets + 1),
        next_packet_number,
    );
}

test "HTTP/3 zero-progress send failure remains retryable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x94} ** quic.protection.secret_len,
    );

    var partial = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 0,
    };
    var vtable = sender.io.vtable.*;
    vtable.netSend = ObservedBatchSend.netSend;
    sender.io = .{ .userdata = &partial, .vtable = &vtable };
    defer sender.io = partial.delegate;

    const frames = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = "first" } },
        .{ .stream = .{ .stream_id = 0, .offset = 5, .data = "second" } },
    };
    var connection = try quic.one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .enable_pacing = false,
        .tls_handshake_complete = true,
    });
    defer connection.deinit();
    try std.testing.expectError(
        error.NetworkDown,
        packetizer.send(allocator, &connection, &frames, 1),
    );
    try std.testing.expect(
        quic.one_rtt.testing.localCloseInfo(&connection) == null,
    );

    var send = ProtectedSendState.init(allocator);
    defer send.deinit();
    var next_packet_number: u64 = 0;
    try std.testing.expectError(
        error.NetworkDown,
        send.sendFrames(
            &sender,
            receiver.address(),
            keys,
            "server",
            &next_packet_number,
            &frames,
            1,
        ),
    );
    try std.testing.expect(send.isUsable());
    try std.testing.expectEqual(@as(u64, 2), next_packet_number);
}

test "HTTP/3 protected sender retires sealed packets after interceptor allocation failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();

    const AlwaysHold = struct {
        fn hold(_: *anyopaque, _: []const u8) bool {
            return true;
        }
    };
    var interceptor_context: u8 = 0;
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .send_interceptor = .{
                .context = &interceptor_context,
                .should_hold = AlwaysHold.hold,
            },
        },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x95} ** quic.protection.secret_len,
    );
    var send = ProtectedSendState.init(allocator);
    defer send.deinit();
    var next_packet_number: u64 = 7;
    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "payload",
    } }};

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    sender.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        send.sendFrames(
            &sender,
            receiver.address(),
            keys,
            "server",
            &next_packet_number,
            &frames,
            1,
        ),
    );
    sender.allocator = allocator;
    sender.limits.send_interceptor = null;
    try std.testing.expect(send.isUsable());
    try std.testing.expectEqual(@as(u64, 8), next_packet_number);
    try std.testing.expect(failing.has_induced_failure);

    try send.sendFrames(
        &sender,
        receiver.address(),
        keys,
        "server",
        &next_packet_number,
        &frames,
        1,
    );
    try std.testing.expectEqual(@as(u64, 9), next_packet_number);
    var received = try quic.one_rtt.receive(
        &receiver,
        keys,
        "server".len,
        8,
        4,
    );
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 8), received.packet.packet_number);
}

test "HTTP/3 protected body batch commits only a visible prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x95} ** quic.protection.secret_len,
    );
    const config = .{
        .send_keys = keys,
        .peer_connection_id = @as([]const u8, "server"),
        .max_stream_frame_data = @as(usize, 64),
        .max_frames_per_packet = @as(usize, 4),
    };
    var send = ProtectedSendState.init(allocator);
    defer send.deinit();
    var bodies = OutboundBodySet.init(allocator, 2);
    defer bodies.deinit();
    inline for (.{ @as(u62, 0), @as(u62, 4) }) |stream_id| {
        try bodies.reserveOpen(stream_id);
        bodies.appendOpenAssumeCapacity(
            stream_id,
            quic.stream_state.SendState.init(stream_id),
            3,
        );
    }
    var next_packet_number: u64 = 0;
    var partial = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 1,
    };
    var vtable = sender.io.vtable.*;
    vtable.netSend = ObservedBatchSend.netSend;
    sender.io = .{ .userdata = &partial, .vtable = &vtable };
    defer sender.io = partial.delegate;

    const Context = struct {
        finished: ?u62 = null,

        fn finish(self: *@This(), stream_id: u62) void {
            self.finished = stream_id;
        }
    };
    var context: Context = .{};
    try std.testing.expectError(
        error.NetworkDown,
        body_sender.sendProtectedBodyBatchProgress(
            &sender,
            receiver.address(),
            config,
            &next_packet_number,
            &send,
            &bodies,
            &.{
                .{ .stream_id = 0, .data = "one", .fin = true },
                .{ .stream_id = 4, .data = "two", .fin = true },
            },
            &context,
            Context.finish,
        ),
    );
    try std.testing.expect(send.isUsable());
    try std.testing.expectEqual(@as(?u62, 0), context.finished);
    try std.testing.expect(bodies.find(0) == null);
    try std.testing.expectEqual(
        @as(u64, 0),
        bodies.find(4).?.send.next_offset,
    );
    try std.testing.expectEqual(@as(u64, 2), next_packet_number);
}

test "HTTP/3 protected body deadline resumes after a complete packet batch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9c} ** quic.protection.secret_len,
    );
    const config = .{
        .send_keys = keys,
        .peer_connection_id = @as([]const u8, "server"),
        .max_stream_frame_data = @as(usize, 64),
        .max_frames_per_packet = @as(usize, 4),
    };
    var send = ProtectedSendState.init(allocator);
    defer send.deinit();
    const chunk_count = quic.one_rtt.max_batch_packets + 1;
    var bodies = OutboundBodySet.init(allocator, chunk_count);
    defer bodies.deinit();
    var chunks: [chunk_count]body_batch.Chunk = undefined;
    for (&chunks, 0..) |*chunk, index| {
        const stream_id: u62 = @intCast(index * 4);
        try bodies.reserveOpen(stream_id);
        bodies.appendOpenAssumeCapacity(
            stream_id,
            quic.stream_state.SendState.init(stream_id),
            1,
        );
        chunk.* = .{ .stream_id = stream_id, .data = "x", .fin = true };
    }
    var next_packet_number: u64 = 0;
    var fixed = FixedClockSend{
        .delegate = sender.io,
        .now_ns = 1_000_000,
        .advance_after_send_ns = std.time.ns_per_s,
    };
    var vtable = sender.io.vtable.*;
    vtable.now = FixedClockSend.now;
    vtable.netSend = FixedClockSend.netSend;
    sender.io = .{ .userdata = &fixed, .vtable = &vtable };
    defer sender.io = fixed.delegate;

    const Context = struct {
        finished: usize = 0,

        fn receive(_: *@This(), _: std.Io.Clock.Timestamp) !void {
            return error.Timeout;
        }

        fn finish(self: *@This(), _: u62) void {
            self.finished += 1;
        }
    };
    var context: Context = .{};
    var committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        body_sender.sendProtectedBodyBatchPacedWithDeadline(
            &sender,
            receiver.address(),
            config,
            &next_packet_number,
            &send,
            &bodies,
            &chunks,
            &context,
            Context.receive,
            Context.finish,
            &committed,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.now_ns + 1),
            },
        ),
    );
    try std.testing.expectEqual(
        @as(usize, quic.one_rtt.max_batch_packets),
        committed,
    );
    try std.testing.expectEqual(committed, context.finished);
    try std.testing.expectEqual(@as(usize, 1), fixed.send_calls);
    try std.testing.expectEqual(@as(u64, @intCast(committed)), next_packet_number);
    try std.testing.expect(send.isUsable());
    for (chunks[0..committed]) |chunk| {
        try std.testing.expect(bodies.find(chunk.stream_id) == null);
    }
    try std.testing.expectEqual(
        @as(u64, 0),
        bodies.find(chunks[committed].stream_id).?.send.next_offset,
    );

    sender.io = fixed.delegate;
    var suffix_committed: usize = 99;
    try body_sender.sendProtectedBodyBatchPacedWithDeadline(
        &sender,
        receiver.address(),
        config,
        &next_packet_number,
        &send,
        &bodies,
        chunks[committed..],
        &context,
        Context.receive,
        Context.finish,
        &suffix_committed,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(usize, 1), suffix_committed);
    try std.testing.expectEqual(chunk_count, context.finished);
    try std.testing.expect(bodies.isEmpty());
}

test "HTTP/3 stateful body batch returns socket-visible error prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x96} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "batch-client",
        .peer_connection_id = "batch-server",
        .enable_pacing = false,
        .tls_handshake_complete = true,
    });
    defer connection.deinit();
    var bodies = OutboundBodySet.init(allocator, 2);
    defer bodies.deinit();
    inline for (.{ @as(u62, 0), @as(u62, 4) }) |stream_id| {
        try bodies.reserveOpen(stream_id);
        bodies.appendOpenAssumeCapacity(
            stream_id,
            quic.stream_state.SendState.init(stream_id),
            3,
        );
    }

    var partial = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 1,
    };
    var vtable = sender.io.vtable.*;
    vtable.netSend = ObservedBatchSend.netSend;
    sender.io = .{ .userdata = &partial, .vtable = &vtable };
    defer sender.io = partial.delegate;

    const Context = struct {
        finished: [2]u62 = undefined,
        count: usize = 0,

        fn finish(self: *@This(), stream_id: u62) void {
            self.finished[self.count] = stream_id;
            self.count += 1;
        }
    };
    const options = .{
        .paced_body_chunk_bytes = @as(usize, 64),
        .max_stream_frame_data = @as(usize, 64),
        .max_frames_per_packet = @as(usize, 4),
    };
    const chunks = [_]body_batch.Chunk{
        .{ .stream_id = 0, .data = "one", .fin = true },
        .{ .stream_id = 4, .data = "two", .fin = true },
    };
    var context: Context = .{};
    const progress = try body_sender.sendConnectionBodyBatchPacedProgress(
        &connection,
        &bodies,
        &chunks,
        options,
        &context,
        Context.finish,
    );
    try std.testing.expectEqual(@as(usize, 1), progress.sent_count);
    try std.testing.expectEqual(error.NetworkDown, progress.send_error.?);
    try std.testing.expectEqual(@as(usize, 1), context.count);
    try std.testing.expectEqual(@as(u62, 0), context.finished[0]);
    try std.testing.expect(bodies.find(0) == null);
    try std.testing.expectEqual(
        @as(u64, 0),
        bodies.find(4).?.send.next_offset,
    );

    sender.io = partial.delegate;
    const retry = try body_sender.sendConnectionBodyBatchPacedProgress(
        &connection,
        &bodies,
        chunks[progress.sent_count..],
        options,
        &context,
        Context.finish,
    );
    try std.testing.expectEqual(@as(usize, 1), retry.sent_count);
    try std.testing.expect(retry.send_error == null);
    try std.testing.expectEqual(@as(usize, 2), context.count);
    try std.testing.expectEqual(@as(u62, 4), context.finished[1]);
    try std.testing.expect(bodies.isEmpty());
}

test "HTTP/3 deadline body batch retains socket-visible error prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x97} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "deadline-client",
        .peer_connection_id = "deadline-server",
        .enable_pacing = false,
        .tls_handshake_complete = true,
    });
    defer connection.deinit();
    var bodies = OutboundBodySet.init(allocator, 2);
    defer bodies.deinit();
    inline for (.{ @as(u62, 0), @as(u62, 4) }) |stream_id| {
        try bodies.reserveOpen(stream_id);
        bodies.appendOpenAssumeCapacity(
            stream_id,
            quic.stream_state.SendState.init(stream_id),
            3,
        );
    }

    var partial = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 1,
    };
    var vtable = sender.io.vtable.*;
    vtable.netSend = ObservedBatchSend.netSend;
    sender.io = .{ .userdata = &partial, .vtable = &vtable };
    defer sender.io = partial.delegate;

    const Context = struct {
        fn receive(_: *@This(), _: std.Io.Clock.Timestamp) !void {
            return error.Timeout;
        }

        fn finish(_: *@This(), _: u62) void {}
    };
    const chunks = [_]body_batch.Chunk{
        .{ .stream_id = 0, .data = "one", .fin = true },
        .{ .stream_id = 4, .data = "two", .fin = true },
    };
    const options = .{
        .paced_body_chunk_bytes = @as(usize, 64),
        .max_stream_frame_data = @as(usize, 64),
        .max_frames_per_packet = @as(usize, 4),
    };
    var context: Context = .{};
    var committed: usize = 99;
    try std.testing.expectError(
        error.NetworkDown,
        body_sender.sendConnectionBodyBatchPacedWithDeadline(
            &connection,
            &bodies,
            &chunks,
            options,
            &context,
            Context.receive,
            Context.finish,
            &committed,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), committed);
    try std.testing.expect(bodies.find(0) == null);
    try std.testing.expectEqual(
        @as(u64, 0),
        bodies.find(4).?.send.next_offset,
    );
}

test "HTTP/3 protected send state reuses batch scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x6b} ** quic.protection.secret_len,
    );
    const frame_storage = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = "one" } },
        .{ .stream = .{ .stream_id = 0, .offset = 3, .data = "two" } },
        .{ .stream = .{ .stream_id = 0, .offset = 6, .data = "three" } },
    };
    var send_state = ProtectedSendState.init(allocator);
    defer send_state.deinit();
    var next_packet_number: u64 = 0;
    try send_state.sendFrames(
        &sender,
        receiver.address(),
        keys,
        "cid",
        &next_packet_number,
        &frame_storage,
        1,
    );
    const payload_capacity = send_state.payload_scratch.capacity;
    const packet_capacity = send_state.packet_scratch.capacity;
    try std.testing.expect(payload_capacity != 0);
    try std.testing.expect(packet_capacity != 0);
    try std.testing.expectEqual(@as(u64, 3), next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), send_state.payload_scratch.items.len);
    try std.testing.expectEqual(@as(usize, 0), send_state.packet_scratch.items.len);

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    send_state.allocator = no_alloc.allocator();
    try send_state.sendFrames(
        &sender,
        receiver.address(),
        keys,
        "cid",
        &next_packet_number,
        &frame_storage,
        1,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(payload_capacity, send_state.payload_scratch.capacity);
    try std.testing.expectEqual(packet_capacity, send_state.packet_scratch.capacity);
    try std.testing.expectEqual(@as(u64, 6), next_packet_number);

    const original_endpoint_allocator = sender.allocator;
    sender.allocator = no_alloc.allocator();
    defer sender.allocator = original_endpoint_allocator;
    try send_state.sendFrames(
        &sender,
        receiver.address(),
        keys,
        "cid",
        &next_packet_number,
        frame_storage[0..1],
        1,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(u64, 7), next_packet_number);
}
