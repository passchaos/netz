const std = @import("std");
const quic = @import("../../../../quic/mod.zig");
const message_sender = @import("../message.zig");
const protected_send_module = @import("../protected.zig");
const send_scratch = @import("../scratch.zig");
const qpack_state = @import("../../qpack/state.zig");

const ProtectedSendState = protected_send_module.State;
const PushSendScratch = send_scratch.Push;
const QpackEncodeState = qpack_state.QpackEncodeState;
const server_qpack_encoder_stream_id: u62 = 7;
const first_server_push_stream_id: u62 = 15;

const ProtectedOptions = struct {
    send_keys: quic.protection.PacketProtectionKeys,
    peer_connection_id: []const u8,
    max_frames_per_packet: usize = 8,
    max_stream_frame_data: usize = 1200,
};
test "HTTP/3 Push send scratch rolls back QPACK references on allocation failure" {
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
        [_]u8{0xf9} ** quic.protection.secret_len,
    );
    const config: ProtectedOptions = .{
        .send_keys = keys,
        .peer_connection_id = "client",
        .max_stream_frame_data = 1200,
    };
    var protected_send = ProtectedSendState.init(allocator);
    defer protected_send.deinit();
    var qpack = QpackEncodeState.init(allocator, 256, 4096);
    defer qpack.deinit();
    try qpack.setCapacity(256);
    _ = try qpack.insertField("x-push-dynamic", "reused-value");
    qpack.known_received_count = qpack.table.insert_count;

    var scratch: PushSendScratch = .{};
    defer scratch.deinit(allocator);
    try scratch.parent.ensureTotalCapacity(allocator, 512);
    try scratch.pushed.ensureTotalCapacity(allocator, 16);
    try scratch.frames.ensureTotalCapacity(allocator, 16);
    const parent_ptr = scratch.parent.allocatedSlice().ptr;
    const pushed_ptr = scratch.pushed.allocatedSlice().ptr;
    const frame_ptr = scratch.frames.allocatedSlice().ptr;
    const pending_sections_len = qpack.pending_sections.items.len;
    var qpack_encoder_send = quic.stream_state.SendState.init(
        server_qpack_encoder_stream_id,
    );
    var qpack_encoder_prefix_sent = false;
    var next_packet_number: u64 = 0;

    var fail_growth = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    sender.allocator = fail_growth.allocator();
    defer sender.allocator = allocator;
    try std.testing.expectError(
        error.OutOfMemory,
        message_sender.sendProtectedPush(
            &sender,
            receiver.address(),
            config,
            &scratch,
            .{
                .qpack_max_table_capacity = 256,
                .qpack_blocked_streams = 2,
            },
            0,
            .{
                .status = 204,
                .headers = &.{.{
                    .name = "x-push-dynamic",
                    .value = "reused-value",
                }},
            },
            first_server_push_stream_id,
            .{
                .push_id = 0,
                .request = .{
                    .method = "GET",
                    .path = "/asset.css",
                    .authority = "example.test",
                    .headers = &.{.{
                        .name = "x-push-dynamic",
                        .value = "reused-value",
                    }},
                },
                // Force the second live output buffer to grow only after the
                // parent has already registered dynamic QPACK references.
                .response = .{
                    .status = 200,
                    .body = &([_]u8{'x'} ** 512),
                },
            },
            &qpack,
            &qpack_encoder_send,
            &qpack_encoder_prefix_sent,
            &next_packet_number,
            &protected_send,
        ),
    );
    try std.testing.expect(fail_growth.has_induced_failure);
    try std.testing.expectEqual(
        pending_sections_len,
        qpack.pending_sections.items.len,
    );
    try std.testing.expectEqual(@as(usize, 0), qpack.reference_counts.count());
    try std.testing.expectEqual(@as(u64, 0), qpack_encoder_send.next_offset);
    try std.testing.expect(!qpack_encoder_prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), next_packet_number);
    try std.testing.expectEqual(parent_ptr, scratch.parent.allocatedSlice().ptr);
    try std.testing.expectEqual(pushed_ptr, scratch.pushed.allocatedSlice().ptr);
    try std.testing.expectEqual(frame_ptr, scratch.frames.allocatedSlice().ptr);
}
