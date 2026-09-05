const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");
const protected_send_module = @import("../../send/protected.zig");

const server_qpack_encoder_stream_id: u62 = 7;

fn sendProtectedFrames(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    next_packet_number: *u64,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
    send: *protected_send_module.State,
) !void {
    try send.sendFrames(
        endpoint,
        to,
        keys,
        destination_connection_id,
        next_packet_number,
        frames,
        max_frames_per_packet,
    );
}

test "HTTP/3 protected client decodes dynamic QPACK response and sends feedback" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xea, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xeb, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xe3} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xe4} ** quic.protection.secret_len);

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    );
    defer server_endpoint.deinit();
    var client = try runtime.ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server_endpoint.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_settings = .{ .qpack_max_table_capacity = 256 },
        .max_stream_frame_data = 1024,
    });
    defer client.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        client_address: std.Io.net.IpAddress,
        server_keys: quic.protection.PacketProtectionKeys,
        client_keys: quic.protection.PacketProtectionKeys,
        client_cid: []const u8,
        server_cid: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            // Consume the client's static request plus control/QPACK bootstrap.
            var request_recv = quic.stream_state.RecvState.init(
                allocator,
                0,
                64 * 1024,
            );
            defer request_recv.deinit();
            var expected_packet_number: u64 = 0;
            while (request_recv.final_size == null or
                request_recv.contiguous_end < request_recv.final_size.?)
            {
                var packet = try quic.one_rtt.receive(
                    shared.endpoint,
                    shared.client_keys,
                    shared.server_cid.len,
                    expected_packet_number,
                    8,
                );
                defer packet.deinit(allocator);
                expected_packet_number = packet.packet.packet_number + 1;
                for (packet.frames) |frame| {
                    if (frame == .stream and frame.stream.stream_id == 0) {
                        try request_recv.insert(frame.stream);
                    }
                }
            }

            var encoder: std.ArrayList(u8) = .empty;
            defer encoder.deinit(allocator);
            try http3.writeQpackEncoderStreamPrefix(&encoder, allocator);
            try http3.Qpack.writeEncoderInstruction(
                &encoder,
                allocator,
                .{ .set_capacity = 256 },
            );
            try http3.Qpack.writeEncoderInstruction(
                &encoder,
                allocator,
                .{ .insert_literal = .{
                    .name = "x-response",
                    .value = "dynamic-client",
                } },
            );
            var frames: std.ArrayList(quic.Frame) = .empty;
            defer frames.deinit(allocator);
            var protected_send = protected_send_module.State.init(allocator);
            defer protected_send.deinit();
            var encoder_send = quic.stream_state.SendState.init(
                server_qpack_encoder_stream_id,
            );
            try encoder_send.appendFrames(
                &frames,
                allocator,
                encoder.items,
                encoder.items.len,
                false,
            );
            var next_packet_number: u64 = 0;
            try sendProtectedFrames(
                shared.endpoint,
                shared.client_address,
                shared.server_keys,
                shared.client_cid,
                &next_packet_number,
                frames.items,
                8,
                &protected_send,
            );

            var table = http3.Qpack.DynamicTable.init(allocator, 256);
            defer table.deinit();
            try table.setCapacity(256);
            _ = try table.insert("x-response", "dynamic-client");
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(allocator);
            try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "2" },
                .{ .name = "x-response", .value = "dynamic-client" },
            }, table);
            var message: std.ArrayList(u8) = .empty;
            defer message.deinit(allocator);
            try (http3.Frame{
                .frame_type = http3.FrameType.headers,
                .payload = block.items,
                .consumed = 0,
            }).write(&message, allocator);
            try (http3.Frame{
                .frame_type = http3.FrameType.data,
                .payload = "ok",
                .consumed = 0,
            }).write(&message, allocator);
            frames.clearRetainingCapacity();
            var response_send = quic.stream_state.SendState.init(0);
            try response_send.appendFrames(
                &frames,
                allocator,
                message.items,
                message.items.len,
                true,
            );
            try sendProtectedFrames(
                shared.endpoint,
                shared.client_address,
                shared.server_keys,
                shared.client_cid,
                &next_packet_number,
                frames.items,
                8,
                &protected_send,
            );
        }
    };

    var shared = Shared{
        .endpoint = &server_endpoint,
        .client_address = client.quic_client.address(),
        .server_keys = server_keys,
        .client_keys = client_keys,
        .client_cid = &client_cid,
        .server_cid = &server_cid,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var response = try client.request(.{
        .method = "GET",
        .path = "/dynamic-response",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("ok", response.response.body);
    var dynamic_value: ?[]const u8 = null;
    for (response.response.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-response")) {
            dynamic_value = header.value;
        }
    }
    try std.testing.expectEqualStrings("dynamic-client", dynamic_value orelse
        return error.TestUnexpectedResult);
    try std.testing.expectEqual(@as(u64, 1), client.qpack_decode.table.insert_count);
}

test "HTTP/3 protected client closes when zero blocked streams are advertised" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xe0, 0x21, 0x22, 0x23 };
    const server_cid = [_]u8{ 0xe1, 0x21, 0x22, 0x23 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe2} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe3} ** quic.protection.secret_len,
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
            .local_settings = .{ .qpack_max_table_capacity = 256 },
        },
    );
    defer client.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/blocked-response",
        .authority = "localhost",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-blocked", "response");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "204" },
        .{ .name = "x-blocked", .value = "response" },
    }, encoder_table);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&message, allocator);
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &.{.{ .stream = .{
            .stream_id = stream_id,
            .data = message.items,
            .fin = true,
        } }},
        server.config.max_frames_per_packet,
        &server.protected_send,
    );

    try std.testing.expectError(
        error.QpackDecompressionFailed,
        client.receiveResponse(stream_id),
    );
    var saw_close = false;
    while (!saw_close) {
        var packet = try server.receive_packets.takeWithDeadline(
            &server.quic_server.endpoint,
            server.config.receive_keys,
            server.config.local_connection_id.len,
            &server.expected_packet_number,
            server.config.max_frames_per_packet,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        );
        defer packet.deinit(allocator);
        for (packet.frames) |frame| switch (frame) {
            .application_close => |close| {
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.qpack_decompression_failed),
                    close.error_code,
                );
                saw_close = true;
            },
            else => {},
        };
    }
}
