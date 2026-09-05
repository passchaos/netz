const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const packetizer = @import("../packetizer.zig");
const protected_send_module = @import("../protected.zig");
const body_sender = @import("../body.zig");
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
