const std = @import("std");
const runtime = @import("../../../../runtime.zig");
const quic = @import("../../../../../quic/mod.zig");
const control_receive = @import("../../../control/receive.zig");

test "HTTP/3 protected client sends priority update for promised push" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xb5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xb6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb8} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();
    try server.promised_push_ids.prepareInsertValue(allocator, 2);
    server.promised_push_ids.insertAssumeCapacity(2);
    try client.sendMaxPushId(2);
    try client.push_streams.registerPromise(2, 0);
    try std.testing.expectError(
        error.UnexpectedStream,
        client.sendPushPriorityUpdate(1, .{}),
    );
    const packet_number = client.next_packet_number;
    const control_offset = client.control_send.next_offset;
    try std.testing.expectError(
        error.Timeout,
        client.sendPushPriorityUpdateWithDeadline(
            2,
            .{ .urgency = 4 },
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(packet_number, client.next_packet_number);
    try std.testing.expectEqual(control_offset, client.control_send.next_offset);
    try client.sendPushPriorityUpdateWithTimeout(2, .{
        .urgency = 1,
        .incremental = true,
    }, .fromSeconds(1));
    while (server.control.pushPriorityUpdate(2) == null) {
        var packet = try server.receive_packets.take(
            &server.quic_server.endpoint,
            server.config.receive_keys,
            server.config.local_connection_id.len,
            &server.expected_packet_number,
            server.config.max_frames_per_packet,
        );
        defer packet.deinit(allocator);
        for (packet.frames) |frame| {
            if (frame != .stream) continue;
            _ = try control_receive.applyControlStreamFrameForRoleWithPushes(
                &server.control,
                allocator,
                frame.stream,
                .server,
                .{ .set = &server.promised_push_ids },
                null,
                null,
            );
        }
    }
    const update = server.control.pushPriorityUpdate(2).?;
    try std.testing.expectEqual(@as(u3, 1), update.priority().urgency);
    try std.testing.expect(update.priority().incremental);
}
