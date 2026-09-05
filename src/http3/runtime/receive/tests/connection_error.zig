const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const connection_error = @import("../connection_error.zig");
const protected_send_module = @import("../../send/protected.zig");

const ProtectedSendState = protected_send_module.State;

const ProtectedOptions = struct {
    send_keys: quic.protection.PacketProtectionKeys,
    peer_connection_id: []const u8,
    max_frames_per_packet: usize = 8,
};

test "HTTP/3 protocol failures install exact connection close codes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x83} ** quic.protection.secret_len,
    );

    inline for (.{
        .{ error.StreamCreationError, http3.ApplicationErrorCode.stream_creation_error },
        .{ error.ClosedCriticalStream, http3.ApplicationErrorCode.closed_critical_stream },
        .{ error.UnexpectedFrame, http3.ApplicationErrorCode.frame_unexpected },
        .{ error.InvalidFrame, http3.ApplicationErrorCode.frame_error },
        .{ error.ExcessiveLoad, http3.ApplicationErrorCode.excessive_load },
        .{ error.IdError, http3.ApplicationErrorCode.id_error },
        .{ error.InvalidSetting, http3.ApplicationErrorCode.settings_error },
        .{ error.MissingSettings, http3.ApplicationErrorCode.missing_settings },
        .{ error.QpackDecompressionFailed, http3.ApplicationErrorCode.qpack_decompression_failed },
        .{ error.QpackEncoderStreamError, http3.ApplicationErrorCode.qpack_encoder_stream_error },
        .{ error.QpackDecoderStreamError, http3.ApplicationErrorCode.qpack_decoder_stream_error },
    }) |expected| {
        var endpoint = try quic.runtime.Endpoint.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{},
        );
        defer endpoint.deinit();
        var connection = try quic.one_rtt.Connection.init(&endpoint, .{
            .peer = endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "server",
            .peer_connection_id = "client",
            .local_endpoint = .server,
            .enable_pacing = false,
        });
        defer connection.deinit();

        try connection_error.closeConnection(&connection, expected[0]);
        const close = quic.one_rtt.testing.localCloseInfo(&connection) orelse
            return error.TestUnexpectedResult;
        try std.testing.expect(close.application);
        try std.testing.expectEqual(expected[1], close.error_code);
    }

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server",
        .peer_connection_id = "client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    try connection_error.closeConnection(&connection, error.OutOfMemory);
    try std.testing.expect(
        quic.one_rtt.testing.localCloseInfo(&connection) == null,
    );
}

test "HTTP/3 protected protocol failures emit exact application close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x84} ** quic.protection.secret_len,
    );
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer sender.deinit();
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer peer.deinit();
    const config: ProtectedOptions = .{
        .send_keys = keys,
        .peer_connection_id = "client",
    };
    var protected_send = ProtectedSendState.init(allocator);
    defer protected_send.deinit();
    var packet_number: u64 = 0;

    inline for (.{
        .{ error.ClosedCriticalStream, http3.ApplicationErrorCode.closed_critical_stream },
        .{ error.InvalidSetting, http3.ApplicationErrorCode.settings_error },
        .{ error.QpackEncoderStreamError, http3.ApplicationErrorCode.qpack_encoder_stream_error },
    }) |expected| {
        connection_error.sendProtectedClose(
            &sender,
            peer.address(),
            config,
            &packet_number,
            &protected_send,
            expected[0],
        );
        var received = try quic.one_rtt.receive(
            &peer,
            keys,
            config.peer_connection_id.len,
            packet_number - 1,
            1,
        );
        defer received.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), received.frames.len);
        try std.testing.expect(received.frames[0] == .application_close);
        try std.testing.expectEqual(
            expected[1],
            received.frames[0].application_close.error_code,
        );
    }

    const before = packet_number;
    connection_error.sendProtectedClose(
        &sender,
        peer.address(),
        config,
        &packet_number,
        &protected_send,
        error.OutOfMemory,
    );
    try std.testing.expectEqual(before, packet_number);
}
