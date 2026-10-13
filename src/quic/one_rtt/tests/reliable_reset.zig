const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");

test "QUIC reliable reset waits for its prefix and ignores later increases" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd1} ** quic.protection.secret_len,
    );
    var receiver = try one_rtt.Connection.init(&receiver_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "reliable-server",
        .peer_connection_id = "reliable-client",
        .local_endpoint = .server,
        .reliable_reset = .{ .local = true },
        .enable_pacing = false,
    });
    defer receiver.deinit();

    try one_rtt.testing.applyReceivedFrames(&receiver, 0, &.{.{
        .reset_stream_at = .{
            .stream_id = 0,
            .application_error_code = 17,
            .final_size = 8,
            .reliable_size = 6,
        },
    }}, null, .not_ect);
    try std.testing.expect(!(try receiver.requestCompletedPeerStreamRelease(0)));

    // A lower Reliable Size replaces the original commitment. A later,
    // reordered increase is ignored as required by the extension.
    try one_rtt.testing.applyReceivedFrames(&receiver, 1, &.{.{
        .reset_stream_at = .{
            .stream_id = 0,
            .application_error_code = 17,
            .final_size = 8,
            .reliable_size = 4,
        },
    }}, null, .not_ect);
    try one_rtt.testing.applyReceivedFrames(&receiver, 2, &.{.{
        .reset_stream_at = .{
            .stream_id = 0,
            .application_error_code = 17,
            .final_size = 8,
            .reliable_size = 5,
        },
    }}, null, .not_ect);
    try std.testing.expectEqual(
        @as(u64, 4),
        receiver.streamResetReceived(0).?.reliable_size,
    );

    try one_rtt.testing.applyReceivedFrames(&receiver, 3, &.{.{ .stream = .{
        .stream_id = 0,
        .offset = 4,
        .data = "tail",
    } }}, null, .not_ect);
    var storage: [16]u8 = undefined;
    try std.testing.expect((try receiver.pollStreamId(0, &storage)) == null);
    try std.testing.expect(!(try receiver.requestCompletedPeerStreamRelease(0)));

    try one_rtt.testing.applyReceivedFrames(&receiver, 4, &.{.{ .stream = .{
        .stream_id = 0,
        .data = "head",
    } }}, null, .not_ect);
    const data = (try receiver.pollStreamId(0, &storage)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(data == .data);
    try std.testing.expectEqualStrings("head", storage[0..data.data.bytes]);
    try std.testing.expect(!data.data.fin);

    const reset = (try receiver.pollStreamId(0, &storage)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(reset == .reset);
    try std.testing.expectEqual(@as(u64, 0), reset.reset.stream_id);
    try std.testing.expectEqual(@as(u64, 17), reset.reset.application_error_code);
    try std.testing.expectEqual(@as(u64, 8), reset.reset.final_size);
    try std.testing.expect((try receiver.pollStreamId(0, &storage)) == null);
}

test "QUIC reliable reset negotiation and sender downgrade are enforced" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd2} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "reliable-client",
        .peer_connection_id = "reliable-server",
        .enable_pacing = false,
    });
    defer sender.deinit();

    const raw_reset = quic.Frame{ .reset_stream_at = .{
        .stream_id = 0,
        .application_error_code = 19,
        .final_size = 0,
        .reliable_size = 0,
    } };
    try std.testing.expectError(error.InvalidFrame, sender.send(&.{raw_reset}));
    try std.testing.expectError(
        error.InvalidFrame,
        sender.resetStreamReliably(0, 19, 0),
    );

    sender.config.reliable_reset.peer = true;
    try sender.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "abcdef",
    } }});
    try sender.resetStreamReliably(0, 19, 4);
    try std.testing.expectEqual(
        @as(u64, 4),
        sender.sendStreamStats(0).?.reset.?.reliable_size,
    );

    const packet_number_before = one_rtt.testing.nextPacketNumber(&sender);
    try std.testing.expectError(
        error.InvalidFrame,
        sender.resetStreamReliably(0, 19, 5),
    );
    try std.testing.expectEqual(
        packet_number_before,
        one_rtt.testing.nextPacketNumber(&sender),
    );

    // Ordinary RESET_STREAM is the permitted Reliable Size = 0 downgrade.
    try sender.resetStream(0, 19);
    try std.testing.expectEqual(
        @as(u64, 0),
        sender.sendStreamStats(0).?.reset.?.reliable_size,
    );
    try std.testing.expect(
        one_rtt.testing.recoveryPayloadForPacket(&sender, 0) == null,
    );
    try std.testing.expect(
        one_rtt.testing.recoveryPayloadForPacket(&sender, 1) == null,
    );
    const reset_payload = one_rtt.testing.recoveryPayloadForPacket(
        &sender,
        packet_number_before,
    ) orelse return error.TestUnexpectedResult;
    const parsed = try quic.parseFrame(reset_payload);
    try std.testing.expect(parsed.frame == .reset_stream);
    try std.testing.expectEqual(@as(u64, 6), parsed.frame.reset_stream.final_size);
}

test "QUIC reliable reset rejects conflicting reset identity transactionally" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd3} ** quic.protection.secret_len,
    );
    var receiver = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "identity-local",
        .peer_connection_id = "identity-peer",
        .local_endpoint = .server,
        .reliable_reset = .{ .local = true },
        .enable_pacing = false,
    });
    defer receiver.deinit();

    try one_rtt.testing.applyReceivedFrames(&receiver, 0, &.{.{
        .reset_stream_at = .{
            .stream_id = 0,
            .application_error_code = 23,
            .final_size = 8,
            .reliable_size = 4,
        },
    }}, null, .not_ect);
    try std.testing.expectError(
        error.StreamStateError,
        one_rtt.testing.applyReceivedFrames(&receiver, 1, &.{.{
            .reset_stream_at = .{
                .stream_id = 0,
                .application_error_code = 24,
                .final_size = 8,
                .reliable_size = 3,
            },
        }}, null, .not_ect),
    );
    const reset = receiver.streamResetReceived(0) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 23), reset.application_error_code);
    try std.testing.expectEqual(@as(u64, 4), reset.reliable_size);
}
