const std = @import("std");
const body_sender = @import("../body.zig");
const quic = @import("../../../../quic/mod.zig");
const runtime_error = @import("../../error.zig");
const protected_send_module = @import("../protected.zig");
const outbound_body = @import("../../stream/outbound_body.zig");

const Error = runtime_error.Error;
const ProtectedSendState = protected_send_module.State;
const OutboundBodySet = outbound_body.Set;

const ProtectedOptions = struct {
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    max_frames_per_packet: usize = 8,
    max_stream_frame_data: usize = 1200,
};

test "HTTP/3 response capacity bypasses header-only send credit" {
    try std.testing.expectEqual(
        @as(usize, 0),
        body_sender.responseBodySendCapacity(256, 64, 256, 256, 1200, 1024),
    );
    try std.testing.expectEqual(
        @as(usize, 192),
        body_sender.responseBodySendCapacity(256, 512, 256, 512, 1200, 1024),
    );
    try std.testing.expectEqual(
        @as(usize, 100),
        body_sender.responseBodySendCapacity(100, 512, 512, 512, 1200, 1024),
    );
    try std.testing.expectEqual(
        @as(usize, 1024),
        body_sender.responseBodySendCapacity(2048, 4096, 4096, 4096, 1200, 1024),
    );
}

test "HTTP/3 body batch validates transport progress before commit" {
    try std.testing.expect(body_sender.batchProgressIsValid(0, 0, 4));
    try std.testing.expect(body_sender.batchProgressIsValid(2, 4, 4));
    try std.testing.expect(body_sender.batchProgressIsValid(4, 4, 4));

    try std.testing.expect(!body_sender.batchProgressIsValid(3, 2, 4));
    try std.testing.expect(!body_sender.batchProgressIsValid(2, 5, 4));
    try std.testing.expect(!body_sender.batchProgressIsValid(5, 5, 4));
}

test "HTTP/3 protected DATA send retries without allocation" {
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
        [_]u8{0xb5} ** quic.protection.secret_len,
    );
    const config: ProtectedOptions = .{
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .max_stream_frame_data = 5,
        .max_frames_per_packet = 2,
    };
    var protected_send = ProtectedSendState.init(allocator);
    defer protected_send.deinit();
    var bodies = OutboundBodySet.init(allocator, 1);
    defer bodies.deinit();
    try bodies.reserveOpen(0);
    bodies.appendOpenAssumeCapacity(
        0,
        quic.stream_state.SendState.init(0),
        12,
    );
    try bodies.frame_scratch.ensureTotalCapacity(allocator, 16);

    var next_packet_number: u64 = 0;
    try body_sender.sendProtectedBodyChunk(
        &sender,
        receiver.address(),
        config,
        &next_packet_number,
        &protected_send,
        &bodies,
        0,
        "first-",
        false,
    );
    const first_entry = bodies.find(0).?.*;
    const body_frame_capacity = bodies.frame_scratch.capacity;
    const body_frame_ptr = bodies.frame_scratch.allocatedSlice().ptr;
    const wire_payload_capacity = protected_send.payload_scratch.capacity;
    const wire_packet_capacity = protected_send.packet_scratch.capacity;
    const wire_payload_ptr = protected_send.payload_scratch.allocatedSlice().ptr;
    const wire_packet_ptr = protected_send.packet_scratch.allocatedSlice().ptr;
    try std.testing.expectEqual(@as(usize, 0), bodies.payload_scratch.capacity);

    // Flow-control rejection happens after the direct-prefix frame plan is
    // built. The body offset, byte count, and FIN state must all roll back.
    bodies.find(0).?.flow_limit = first_entry.send.next_offset;
    try std.testing.expectError(
        error.FlowControlBlocked,
        body_sender.sendProtectedBodyChunk(
            &sender,
            receiver.address(),
            config,
            &next_packet_number,
            &protected_send,
            &bodies,
            0,
            "second",
            true,
        ),
    );
    const blocked_entry = bodies.find(0).?.*;
    try std.testing.expectEqual(first_entry.send.next_offset, blocked_entry.send.next_offset);
    try std.testing.expectEqual(first_entry.written, blocked_entry.written);
    try std.testing.expectEqual(first_entry.send.fin_sent, blocked_entry.send.fin_sent);
    // Flow-control validation precedes packet protection, so a rejected retry
    // cannot consume a packet number.
    try std.testing.expectEqual(@as(u64, 1), next_packet_number);
    bodies.find(0).?.flow_limit = null;

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    sender.allocator = no_alloc.allocator();
    protected_send.allocator = no_alloc.allocator();
    defer {
        sender.allocator = allocator;
        protected_send.allocator = allocator;
    }
    try body_sender.sendProtectedBodyChunk(
        &sender,
        receiver.address(),
        config,
        &next_packet_number,
        &protected_send,
        &bodies,
        0,
        "second",
        true,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expect(bodies.find(0) == null);
    try std.testing.expectEqual(body_frame_capacity, bodies.frame_scratch.capacity);
    try std.testing.expectEqual(body_frame_ptr, bodies.frame_scratch.allocatedSlice().ptr);
    try std.testing.expectEqual(@as(usize, 0), bodies.payload_scratch.capacity);
    try std.testing.expectEqual(
        wire_payload_capacity,
        protected_send.payload_scratch.capacity,
    );
    try std.testing.expectEqual(
        wire_packet_capacity,
        protected_send.packet_scratch.capacity,
    );
    try std.testing.expectEqual(
        wire_payload_ptr,
        protected_send.payload_scratch.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        wire_packet_ptr,
        protected_send.packet_scratch.allocatedSlice().ptr,
    );
}

test "HTTP/3 protected body batch sends and rejects duplicate streams" {
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
        [_]u8{0xc5} ** quic.protection.secret_len,
    );
    const config: ProtectedOptions = .{
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .max_stream_frame_data = 64,
        .max_frames_per_packet = 4,
    };
    var protected_send = ProtectedSendState.init(allocator);
    defer protected_send.deinit();
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
    const Context = struct {
        finished: usize = 0,

        fn receiveProgress(_: *@This()) Error!void {
            return error.Unexpected;
        }

        fn finish(self: *@This(), _: u62) void {
            self.finished += 1;
        }
    };
    var context: Context = .{};
    try std.testing.expectError(
        error.UnexpectedStream,
        body_sender.sendProtectedBodyBatchPaced(
            &sender,
            receiver.address(),
            config,
            &next_packet_number,
            &protected_send,
            &bodies,
            &.{
                .{ .stream_id = 0, .data = "one", .fin = true },
                .{ .stream_id = 0, .data = "one", .fin = true },
            },
            &context,
            Context.receiveProgress,
            Context.finish,
        ),
    );
    try std.testing.expectEqual(@as(u64, 0), next_packet_number);
    try std.testing.expectEqual(@as(u64, 0), bodies.find(0).?.send.next_offset);

    try body_sender.sendProtectedBodyBatchPaced(
        &sender,
        receiver.address(),
        config,
        &next_packet_number,
        &protected_send,
        &bodies,
        &.{
            .{ .stream_id = 0, .data = "one", .fin = true },
            .{ .stream_id = 4, .data = "two", .fin = true },
        },
        &context,
        Context.receiveProgress,
        Context.finish,
    );
    try std.testing.expectEqual(@as(u64, 2), next_packet_number);
    try std.testing.expectEqual(@as(usize, 2), context.finished);
    try std.testing.expectEqual(@as(usize, 0), bodies.count());

    var first = try quic.one_rtt.receive(
        &receiver,
        keys,
        config.peer_connection_id.len,
        0,
        4,
    );
    defer first.deinit(allocator);
    var second = try quic.one_rtt.receive(
        &receiver,
        keys,
        config.peer_connection_id.len,
        1,
        4,
    );
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.frames[0].stream.stream_id);
    try std.testing.expectEqual(@as(u64, 4), second.frames[0].stream.stream_id);
    try std.testing.expect(first.frames[first.frames.len - 1].stream.fin);
    try std.testing.expect(second.frames[second.frames.len - 1].stream.fin);
}
