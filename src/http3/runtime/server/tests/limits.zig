const std = @import("std");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");

test "HTTP/3 protected server bounds concurrent request streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x95, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x96, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x97} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x98} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            },
            .max_concurrent_request_streams = 1,
        },
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
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const frames = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = "partial-zero" } },
        .{ .stream = .{ .stream_id = 4, .data = "partial-four" } },
    };
    try client.protected_send.sendFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &frames,
        frames.len,
    );
    try std.testing.expectError(error.ExcessiveLoad, server.receiveRequest());
    try std.testing.expectEqual(@as(usize, 1), server.request_streams.count());
}

test "HTTP/3 runtime rejects blocked-stream limit above retention bound" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xb5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xb6, 0x10, 0x20, 0x30 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb7} ** quic.protection.secret_len,
    );
    try std.testing.expectError(
        error.QpackDynamicTableUnsupported,
        runtime.ProtectedClient.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(9) },
            .{ .max_concurrent_request_streams = 1 },
            .{
                .receive_keys = keys,
                .send_keys = keys,
                .local_connection_id = &client_cid,
                .peer_connection_id = &server_cid,
                .local_settings = .{ .qpack_blocked_streams = 2 },
            },
        ),
    );
}
