const std = @import("std");
const stream_root = @import("../../stream.zig");

const association = @import("../../stream_association.zig");
const quic = @import("../../../../quic/mod.zig");
const webtransport = @import("../../../mod.zig");

const finish = stream_root.finish;
const finishWithDeadline = stream_root.finishWithDeadline;
const initRegistry = stream_root.initRegistry;
const poll = stream_root.poll;
const prepare = stream_root.prepare;
const receive = stream_root.receive;
const receiveWithDeadline = stream_root.receiveWithDeadline;
const send = stream_root.send;
const sendOnce = stream_root.sendOnce;
const sendSlices = stream_root.sendSlices;
const sendSlicesOnce = stream_root.sendSlicesOnce;
const sendSlicesWithDeadline = stream_root.sendSlicesWithDeadline;
const sendWithDeadline = stream_root.sendWithDeadline;
const wholeStreamLengths = stream_root.wholeStreamLengths;
const write = stream_root.write;
const writeSlices = stream_root.writeSlices;
const writeSlicesWithDeadline = stream_root.writeSlicesWithDeadline;
const writeWithDeadline = stream_root.writeWithDeadline;

test "WebTransport registry accepts peers without legacy stream settings" {
    var registry = try initRegistry(
        std.testing.allocator,
        .init(0),
        .server,
        .{ .enable_connect_protocol = true, .enable_webtransport = true },
        .{ .enable_connect_protocol = true, .enable_webtransport = true },
        8,
        null,
        null,
    );
    defer registry.deinit();
    try std.testing.expectEqual(@as(u62, 1), (try registry.openLocal(.bidirectional)).stream_id);
    try std.testing.expectEqual(@as(u62, 15), (try registry.openLocal(.unidirectional)).stream_id);
}

test "WebTransport whole-stream lengths preserve checked final size" {
    const lengths = try wholeStreamLengths(13, 5);
    try std.testing.expectEqual(@as(usize, 13), lengths.wire);
    try std.testing.expectEqual(@as(usize, 8), lengths.payload);
    try std.testing.expectError(
        error.InvalidStreamState,
        wholeStreamLengths(4, 5),
    );

    if (comptime @bitSizeOf(usize) < 64) {
        try std.testing.expectError(
            error.IntegerOverflow,
            wholeStreamLengths(@as(u64, std.math.maxInt(usize)) + 1, 8),
        );
    }
}

test "WebTransport whole-stream oversize advances sibling and permits incremental drain" {
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
        [_]u8{0x8d} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-limit-server",
        .peer_connection_id = "wt-limit-client",
        .local_endpoint = .server,
        .initial_receive_max_streams_bidi = 3,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 2 },
    );
    defer registry.deinit();

    var header_storage: [16]u8 = undefined;
    const header = try webtransport.BidirectionalStreamHeader.writeInto(
        &header_storage,
        session_id,
    );
    const oversized_payload = "0123456789abcdefg";
    var oversized_storage: [64]u8 = undefined;
    const oversized = oversized_storage[0 .. header.len + oversized_payload.len];
    @memcpy(oversized[0..header.len], header);
    @memcpy(oversized[header.len..], oversized_payload);
    var sibling_storage: [32]u8 = undefined;
    const sibling_payload = "sibling";
    const sibling_bytes = sibling_storage[0 .. header.len + sibling_payload.len];
    @memcpy(sibling_bytes[0..header.len], header);
    @memcpy(sibling_bytes[header.len..], sibling_payload);
    // First observe the oversized stream before FIN. This commits its parsed
    // association and `.whole` claim in an earlier poll turn.
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 4,
            .data = oversized,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect((try poll(
        &connection,
        &registry,
        session_id,
        16,
    )) == null);
    try std.testing.expectEqual(
        webtransport.ReceiveMode.whole,
        registry.get(4).?.receive_mode,
    );

    // A later FIN reveals the aggregate mismatch. The scanner must release
    // the old whole-stream claim and continue to the ready sibling.
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .offset = oversized.len,
                .data = &.{},
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = 8,
                .data = sibling_bytes,
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    var sibling = (try poll(
        &connection,
        &registry,
        session_id,
        16,
    )) orelse return error.TestUnexpectedResult;
    defer sibling.deinit();
    try std.testing.expectEqual(@as(u62, 8), sibling.stream_id);
    try std.testing.expectEqualStrings(sibling_payload, sibling.payload);

    // With no smaller sibling left, surface the aggregate API mismatch while
    // preserving the stream for a caller-buffer read.
    try std.testing.expectError(
        error.StreamLimitExceeded,
        poll(&connection, &registry, session_id, 16),
    );
    try std.testing.expectEqual(
        webtransport.ReceiveMode.unset,
        registry.get(4).?.receive_mode,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(4).?.bytes_read,
    );

    var out: [32]u8 = undefined;
    const event = (try @import("../../stream_incremental.zig").poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(@as(u62, 4), event.data.stream_id);
    try std.testing.expectEqualStrings(
        oversized_payload,
        out[0..event.data.bytes],
    );
    try std.testing.expect(event.data.fin);
}

test "WebTransport whole-stream poll rejects wrong-session uni and advances sibling" {
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
        [_]u8{0x8e} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-wrong-uni-server",
        .peer_connection_id = "wt-wrong-uni-client",
        .local_endpoint = .server,
        .initial_receive_max_streams_bidi = 2,
        .initial_receive_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 1, .max_peer_uni = 1 },
    );
    defer registry.deinit();

    var wrong: std.ArrayList(u8) = .empty;
    defer wrong.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &wrong,
        allocator,
        .init(4),
    );
    try wrong.appendSlice(allocator, "bad");
    var valid_header_storage: [16]u8 = undefined;
    const valid_header = try webtransport.BidirectionalStreamHeader.writeInto(
        &valid_header_storage,
        session_id,
    );
    var valid_bytes_storage: [32]u8 = undefined;
    const valid_bytes = valid_bytes_storage[0 .. valid_header.len + "ok".len];
    @memcpy(valid_bytes[0..valid_header.len], valid_header);
    @memcpy(valid_bytes[valid_header.len..], "ok");
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{ .stream_id = 2, .data = wrong.items } },
            .{ .stream = .{
                .stream_id = 4,
                .data = valid_bytes,
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    var sibling = (try poll(
        &connection,
        &registry,
        session_id,
        16,
    )) orelse return error.TestUnexpectedResult;
    defer sibling.deinit();
    try std.testing.expectEqual(@as(u62, 4), sibling.stream_id);
    try std.testing.expectEqualStrings("ok", sibling.payload);
    try std.testing.expect(registry.get(2) == null);
    try std.testing.expect(connection.sendStreamStats(2) == null);
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.buffered_stream_rejected,
        connection.recvStreamStats(2).?.stop_sending_sent.?
            .application_error_code,
    );
    var rejection_datagram = try sender.receiveBytes();
    defer rejection_datagram.deinit(allocator);
    var rejection = try quic.one_rtt.openReceivedBytes(
        &sender,
        rejection_datagram.from,
        rejection_datagram.bytes,
        keys,
        "wt-wrong-uni-client".len,
        0,
        4,
    );
    defer rejection.deinit(allocator);
    var saw_stop = false;
    for (rejection.frames) |frame| switch (frame) {
        .stop_sending => |stop_info| {
            try std.testing.expectEqual(@as(u64, 2), stop_info.stream_id);
            try std.testing.expectEqual(
                webtransport.ApplicationErrorCode.buffered_stream_rejected,
                stop_info.application_error_code,
            );
            saw_stop = true;
        },
        .reset_stream => return error.TestUnexpectedResult,
        else => {},
    };
    try std.testing.expect(saw_stop);
    try std.testing.expectEqual(
        @as(usize, 0),
        quic.one_rtt.testing.receiveStreamAvailableLen(&connection, 2).?,
    );

    // Late bytes on the rejected stream are discarded, and FIN lets QUIC
    // return its stream slot without ever admitting it to this session.
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{
            .stream_id = 2,
            .offset = wrong.items.len,
            .data = "late",
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect((try poll(
        &connection,
        &registry,
        session_id,
        16,
    )) == null);
    try std.testing.expect(connection.peerStreamClosed(2));
    try std.testing.expect(connection.recvStreamStats(2) == null);
    try std.testing.expect(registry.get(2) == null);
}

test "WebTransport whole-stream deadline preserves ready stream before retirement" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd5} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-retire-server",
        .peer_connection_id = "wt-retire-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_uni = 1 },
    );
    defer registry.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &encoded,
        allocator,
        session_id,
    );
    try encoded.appendSlice(allocator, "payload");
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 2,
            .data = encoded.items,
            .fin = true,
        } }},
        null,
        .not_ect,
    );

    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(2).?.bytes_read,
    );
    try std.testing.expect(registry.get(2) == null);
    try std.testing.expectError(
        error.Timeout,
        receiveWithDeadline(
            &connection,
            &registry,
            session_id,
            64,
            .fromNow(threaded.io(), .{
                .clock = .real,
                .raw = .fromSeconds(1),
            }),
        ),
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(2).?.bytes_read,
    );
    try std.testing.expect(registry.get(2) == null);

    var stream = try receiveWithDeadline(
        &connection,
        &registry,
        session_id,
        64,
        .fromNow(threaded.io(), .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    defer stream.deinit();
    try std.testing.expectEqualStrings("payload", stream.payload);
    try std.testing.expect(connection.peerStreamClosed(2));
    try std.testing.expect(registry.get(2) != null);
}

test "WebTransport whole-stream poll drains stopped sibling" {
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
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-whole-server",
        .peer_connection_id = "wt-whole-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 16,
        .receive_window = 16,
        .max_receive_window = 16,
        .initial_receive_max_stream_data = 16,
        .stream_receive_window = 16,
        .max_stream_receive_window = 16,
        .initial_receive_max_streams_bidi = 3,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 3 },
    );
    defer registry.deinit();

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        session_id,
    );
    var cancelled_start: [17]u8 = undefined;
    @memcpy(cancelled_start[0..prefix.len], prefix);
    cancelled_start[prefix.len] = 'a';
    const cancelled_start_len = prefix.len + 1;
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 4,
            .data = cancelled_start[0..cancelled_start_len],
        } }},
        null,
        .not_ect,
    );
    const cancelled = (try association.identify(
        &connection,
        &registry,
        session_id,
        4,
        .whole,
    )) orelse return error.TestUnexpectedResult;
    const stop_code = webtransport.applicationErrorCodeToHttp3(22);
    try connection.sendStopSending(4, stop_code);
    cancelled.stop_sent = .fromHttp3(stop_code);
    var stop_datagram = try sender.receiveBytes();
    defer stop_datagram.deinit(allocator);

    var target_bytes: [18]u8 = undefined;
    @memcpy(target_bytes[0..prefix.len], prefix);
    @memcpy(target_bytes[prefix.len..][0..2], "ok");
    const target_len = prefix.len + 2;
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .offset = cancelled_start_len,
                .data = "late",
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = 8,
                .data = target_bytes[0..target_len],
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    var target = (try poll(
        &connection,
        &registry,
        session_id,
        64,
    )) orelse return error.TestUnexpectedResult;
    defer target.deinit();
    try std.testing.expectEqual(@as(u62, 8), target.stream_id);
    try std.testing.expectEqualStrings("ok", target.payload);
    try std.testing.expectEqual(
        @as(usize, 0),
        quic.one_rtt.testing.receiveStreamAvailableLen(&connection, 4).?,
    );
    try std.testing.expectEqual(
        @as(u64, 16),
        connection.recvStreamStats(4).?.receive_limit,
    );
    try std.testing.expect(registry.get(4).?.peer_fin);
}

test "WebTransport whole-stream stopped reset remains observable" {
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
        [_]u8{0xd9} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reset-server",
        .peer_connection_id = "wt-reset-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .initial_receive_max_streams_bidi = 2,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 2 },
    );
    defer registry.deinit();

    var storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &storage,
        session_id,
    );
    var initial: [17]u8 = undefined;
    @memcpy(initial[0..prefix.len], prefix);
    initial[prefix.len] = 'x';
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 4,
            .data = initial[0 .. prefix.len + 1],
        } }},
        null,
        .not_ect,
    );
    const stream = (try association.identify(
        &connection,
        &registry,
        session_id,
        4,
        .whole,
    )) orelse return error.TestUnexpectedResult;
    const stop_code = webtransport.applicationErrorCodeToHttp3(23);
    try connection.sendStopSending(4, stop_code);
    stream.stop_sent = .fromHttp3(stop_code);
    var stop_datagram = try sender.receiveBytes();
    defer stop_datagram.deinit(allocator);
    var stop_credit_datagram = try sender.receiveBytes();
    defer stop_credit_datagram.deinit(allocator);
    var stop_credit = try quic.one_rtt.openReceivedBytes(
        &sender,
        stop_credit_datagram.from,
        stop_credit_datagram.bytes,
        keys,
        "wt-reset-client".len,
        1,
        8,
    );
    defer stop_credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), stop_credit.frames.len);
    try std.testing.expect(stop_credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 12),
        stop_credit.frames[0].max_data.maximum_data,
    );

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .reset_stream = .{
            .stream_id = 4,
            .application_error_code = stop_code,
            .final_size = 8,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expectError(
        error.InvalidStreamState,
        poll(&connection, &registry, session_id, 64),
    );
    try std.testing.expect(registry.get(4).?.receive_reset != null);
    try std.testing.expectEqual(
        @as(u64, 8),
        connection.recvStreamStats(4).?.receive_limit,
    );
    var credit_datagram = try sender.receiveBytes();
    defer credit_datagram.deinit(allocator);
    var credit = try quic.one_rtt.openReceivedBytes(
        &sender,
        credit_datagram.from,
        credit_datagram.bytes,
        keys,
        "wt-reset-client".len,
        stop_credit.packet.packet_number + 1,
        8,
    );
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), credit.frames.len);
    try std.testing.expect(credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 16),
        credit.frames[0].max_data.maximum_data,
    );
}

test "WebTransport local unidirectional FIN requests transport retirement" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd6} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-local-client",
        .peer_connection_id = "wt-local-server",
        .initial_send_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_uni = 1, .first_local_uni = 2 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.unidirectional);
    try std.testing.expectEqual(@as(u62, 2), stream.stream_id);

    try finish(&connection, &registry, session_id, stream.stream_id);
    try std.testing.expect(!connection.localStreamClosed(stream.stream_id));
    try std.testing.expect(stream.local_fin);
    try std.testing.expect(connection.markPacketAcknowledged(1));
    try std.testing.expect(!connection.localStreamClosed(stream.stream_id));
    try std.testing.expect(connection.markPacketAcknowledged(0));
    try std.testing.expect(connection.localStreamClosed(stream.stream_id));
    try std.testing.expect(registry.get(stream.stream_id) != null);
}

test "WebTransport complete stream send batches consecutive packets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-batch-client",
        .peer_connection_id = "wt-batch-server",
        .max_datagram_size = 4096,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);

    const ObservedBatchSend =
        @import("../../../../quic/one_rtt/tests/observed_batch_send.zig")
            .ObservedBatchSend;
    var observed = ObservedBatchSend{ .delegate = sender_endpoint.io };
    var observed_vtable = sender_endpoint.io.vtable.*;
    observed_vtable.netSend = ObservedBatchSend.netSend;
    sender_endpoint.io = .{
        .userdata = &observed,
        .vtable = &observed_vtable,
    };
    defer sender_endpoint.io = observed.delegate;

    const payload = [_]u8{0xa5} ** 10_000;
    try send(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        &payload,
        false,
    );

    // One association-prefix send is followed by one three-datagram
    // application batch: 3968 + 3968 + 2064 bytes.
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try std.testing.expectEqual(@as(usize, 3), observed.last_message_count);
    try std.testing.expect(stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, payload.len), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, payload.len + 3), stream.send_offset);
    try std.testing.expectEqual(@as(u64, 4), connection.stats().packets_sent);
}

test "WebTransport complete stream batch commits only socket prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd9} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-prefix-client",
        .peer_connection_id = "wt-prefix-server",
        .max_datagram_size = 4096,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    _ = try prepare(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
    );
    try std.testing.expectEqual(@as(u64, 3), stream.send_offset);

    const ObservedBatchSend =
        @import("../../../../quic/one_rtt/tests/observed_batch_send.zig")
            .ObservedBatchSend;
    var observed = ObservedBatchSend{
        .delegate = sender_endpoint.io,
        .fail_after_prefix = 0,
    };
    var observed_vtable = sender_endpoint.io.vtable.*;
    observed_vtable.netSend = ObservedBatchSend.netSend;
    sender_endpoint.io = .{
        .userdata = &observed,
        .vtable = &observed_vtable,
    };
    defer sender_endpoint.io = observed.delegate;

    const payload = [_]u8{0x5a} ** 10_000;
    var committed: usize = 99;
    try std.testing.expectError(
        error.NetworkDown,
        sendWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &payload,
            false,
            &committed,
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 3), stream.send_offset);

    observed.fail_after_prefix = 1;
    try std.testing.expectError(
        error.NetworkDown,
        sendWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &payload,
            false,
            &committed,
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        ),
    );
    const first_packet_bytes: usize = 4096 - 128;
    try std.testing.expectEqual(first_packet_bytes, committed);
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try std.testing.expectEqual(@as(usize, 3), observed.last_message_count);
    try std.testing.expectEqual(
        @as(u64, first_packet_bytes),
        stream.bytes_sent,
    );
    try std.testing.expectEqual(
        @as(u64, first_packet_bytes + 3),
        stream.send_offset,
    );

    sender_endpoint.io = observed.delegate;
    try send(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        payload[first_packet_bytes..],
        false,
    );
    try std.testing.expectEqual(@as(u64, payload.len), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, payload.len + 3), stream.send_offset);
}

test "WebTransport stream slice batch commits only socket prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdc} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-vect-client",
        .peer_connection_id = "wt-vect-server",
        .max_datagram_size = 4096,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    _ = try prepare(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
    );

    const ObservedBatchSend =
        @import("../../../../quic/one_rtt/tests/observed_batch_send.zig")
            .ObservedBatchSend;
    var observed = ObservedBatchSend{
        .delegate = sender_endpoint.io,
        .fail_after_prefix = 1,
    };
    var observed_vtable = sender_endpoint.io.vtable.*;
    observed_vtable.netSend = ObservedBatchSend.netSend;
    sender_endpoint.io = .{
        .userdata = &observed,
        .vtable = &observed_vtable,
    };
    defer sender_endpoint.io = observed.delegate;

    const payload = [_]u8{0x5b} ** 10_000;
    const parts = [_][]const u8{ "ab", &.{}, payload[0..4000], payload[4000..] };
    var committed: usize = 99;
    try std.testing.expectError(
        error.NetworkDown,
        sendSlicesWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &parts,
            false,
            &committed,
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expect(committed > 2);
    try std.testing.expect(committed < 2 + payload.len);
    try std.testing.expectEqual(@as(usize, 1), observed.calls);
    try std.testing.expect(observed.last_message_count > 1);
    try std.testing.expectEqual(@as(u64, committed), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, committed + 3), stream.send_offset);

    sender_endpoint.io = observed.delegate;
    try sendSlices(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        &.{payload[committed - 2 ..]},
        false,
    );
    try std.testing.expectEqual(@as(u64, 2 + payload.len), stream.bytes_sent);
    try std.testing.expectEqual(
        @as(u64, 2 + payload.len + 3),
        stream.send_offset,
    );
}

test "WebTransport deadline send reports committed prefix and resumes after credit" {
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
    var silent_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer silent_peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xda} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = silent_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-deadline-client",
        .peer_connection_id = "wt-deadline-server",
        .initial_send_max_data = 8,
        .initial_send_max_stream_data_bidi_remote = 8,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    const payload = "abcdefghijkl";

    var committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        sendWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            payload,
            true,
            &committed,
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 5), committed);
    try std.testing.expectEqual(@as(u64, 5), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 8), stream.send_offset);
    try std.testing.expect(!stream.local_fin);

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .max_data = .{ .maximum_data = 64 } },
            .{ .max_stream_data = .{
                .stream_id = stream.stream_id,
                .maximum_stream_data = 64,
            } },
        },
        null,
        .not_ect,
    );
    try sendWithDeadline(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        payload[committed..],
        true,
        &committed,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    try std.testing.expectEqual(@as(usize, 7), committed);
    try std.testing.expectEqual(@as(u64, payload.len), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, payload.len + 3), stream.send_offset);
    try std.testing.expect(stream.local_fin);
}

test "WebTransport stream slices report cross-slice committed prefix" {
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
    var silent_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer silent_peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdd} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = silent_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-slices-client",
        .peer_connection_id = "wt-slices-server",
        .initial_send_max_data = 8,
        .initial_send_max_stream_data_bidi_remote = 8,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    const parts = [_][]const u8{ "ab", &.{}, "cdef", "ghijkl" };

    var committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        sendSlicesWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &parts,
            true,
            &committed,
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
        ),
    );
    // Three association bytes consume the first eight bytes of stream credit.
    // The five committed application bytes cross the "ab"/"cdef" slice
    // boundary and are reported as one logical prefix.
    try std.testing.expectEqual(@as(usize, 5), committed);
    try std.testing.expectEqual(@as(u64, 5), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 8), stream.send_offset);
    try std.testing.expect(!stream.local_fin);

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .max_data = .{ .maximum_data = 64 } },
            .{ .max_stream_data = .{
                .stream_id = stream.stream_id,
                .maximum_stream_data = 64,
            } },
        },
        null,
        .not_ect,
    );
    try sendSlicesWithDeadline(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        &.{ "f", &.{}, "ghijkl" },
        true,
        &committed,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    try std.testing.expectEqual(@as(usize, 7), committed);
    try std.testing.expectEqual(@as(u64, 12), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 15), stream.send_offset);
    try std.testing.expect(stream.local_fin);
}

test "WebTransport stream slice write fills one packet across boundaries" {
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
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdf} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-write-server",
        .peer_connection_id = "wt-write-client",
        .max_datagram_size = 512,
        .max_frames_per_packet = 4,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    const long = [_]u8{0xa5} ** 600;

    const first = try writeSlices(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        &.{ "ab", &.{}, "cdef", &long },
    );
    try std.testing.expect(first > 6);
    try std.testing.expect(first < 6 + long.len);
    try std.testing.expect(stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, first), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, first + 3), stream.send_offset);

    var committed = first;
    while (committed < 6 + long.len) {
        const remaining = committed - 6;
        const count = try writeSlicesWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &.{long[remaining..]},
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        );
        try std.testing.expect(count != 0);
        committed += count;
    }
    try std.testing.expectEqual(@as(usize, 606), committed);
    try std.testing.expectEqual(@as(u64, 606), stream.bytes_sent);
    try finish(&connection, &registry, session_id, stream.stream_id);
    try std.testing.expect(stream.local_fin);
}

test "WebTransport stream deadline rejects wrong clock without mutation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdb} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-clock-client",
        .peer_connection_id = "wt-clock-server",
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    const wrong_clock: std.Io.Clock.Timestamp = .{
        .clock = .real,
        .raw = .fromNanoseconds(std.time.ns_per_s),
    };

    var committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        sendWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            "payload",
            false,
            &committed,
            wrong_clock,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectError(
        error.Timeout,
        writeWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            "payload",
            wrong_clock,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        finishWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            wrong_clock,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        @import("../../stream_incremental.zig").resetWithDeadline(
            &connection,
            &registry,
            stream.stream_id,
            42,
            wrong_clock,
        ),
    );
    try std.testing.expect(!stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), stream.send_offset);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
    try std.testing.expect(!stream.local_fin);
    try std.testing.expectEqual(@as(?webtransport.StreamError, null), stream.send_reset);
}

test "WebTransport bounded write and finish preserve retryable stream state" {
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
    var silent_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer silent_peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdc} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = silent_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-write-client",
        .peer_connection_id = "wt-write-server",
        .initial_send_max_data = 3,
        .initial_send_max_stream_data_bidi_remote = 3,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);

    try std.testing.expectError(
        error.Timeout,
        writeWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            "payload",
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expect(stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, 3), stream.send_offset);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
    try std.testing.expect(!stream.local_fin);

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .max_data = .{ .maximum_data = 64 } },
            .{ .max_stream_data = .{
                .stream_id = stream.stream_id,
                .maximum_stream_data = 64,
            } },
        },
        null,
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(usize, 7),
        try writeWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            "payload",
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(u64, 7), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 10), stream.send_offset);
    quic.one_rtt.testing.clampCongestionWindowToBytesInFlight(&connection);
    try std.testing.expectError(
        error.Timeout,
        finishWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expect(!stream.local_fin);
    try std.testing.expectEqual(@as(u64, 10), stream.send_offset);
    quic.one_rtt.testing.acknowledgeAllInFlight(&connection);
    try finishWithDeadline(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    try std.testing.expect(stream.local_fin);
    try std.testing.expectEqual(@as(u64, 10), stream.send_offset);
}

test "WebTransport bounded reset preserves retryable stream state" {
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
    var silent_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer silent_peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdd} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = silent_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reset-client",
        .peer_connection_id = "wt-reset-server",
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    try send(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        "payload",
        false,
    );

    quic.one_rtt.testing.clampCongestionWindowToBytesInFlight(&connection);
    try std.testing.expectError(
        error.Timeout,
        @import("../../stream_incremental.zig").resetWithDeadline(
            &connection,
            &registry,
            stream.stream_id,
            42,
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(
        @as(?webtransport.StreamError, null),
        stream.send_reset,
    );

    quic.one_rtt.testing.acknowledgeAllInFlight(&connection);
    try @import("../../stream_incremental.zig").resetWithDeadline(
        &connection,
        &registry,
        stream.stream_id,
        42,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    try std.testing.expectEqual(
        @as(u32, 42),
        stream.send_reset.?.application_code,
    );
}

test "WebTransport single-attempt send atomically includes prefix payload and FIN" {
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
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-once-server",
        .peer_connection_id = "wt-once-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_local_bidi = 1, .first_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);

    try sendOnce(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        "atomic",
        true,
    );
    try std.testing.expect(stream.prefix_sent);
    try std.testing.expect(stream.local_fin);
    try std.testing.expectEqual(@as(u64, 6), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 9), stream.send_offset);

    var packet = try quic.one_rtt.receive(
        &receiver_endpoint,
        keys,
        "wt-once-client".len,
        0,
        4,
    );
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), packet.frames.len);
    try std.testing.expect(packet.frames[0] == .stream);
    try std.testing.expectEqual(@as(u64, 0), packet.frames[0].stream.offset);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x40, 0x41, 0x00 },
        packet.frames[0].stream.data,
    );
    try std.testing.expect(!packet.frames[0].stream.fin);
    try std.testing.expect(packet.frames[1] == .stream);
    try std.testing.expectEqual(@as(u64, 3), packet.frames[1].stream.offset);
    try std.testing.expectEqualStrings("atomic", packet.frames[1].stream.data);
    try std.testing.expect(packet.frames[1].stream.fin);
}

test "WebTransport single-attempt slices are atomic and preserve boundaries" {
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
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xde} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-slice-server",
        .peer_connection_id = "wt-slice-client",
        .local_endpoint = .server,
        .max_frames_per_packet = 4,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_local_bidi = 1, .first_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);

    try std.testing.expectError(
        error.DatagramTooLarge,
        sendSlicesOnce(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &.{ "a", "b", "c", "d" },
            true,
        ),
    );
    try std.testing.expect(!stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 0), stream.send_offset);
    try std.testing.expect(!stream.local_fin);
    try std.testing.expectEqual(@as(u64, 0), connection.stats().packets_sent);

    try sendSlicesOnce(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        &.{ "at", &.{}, "om", "ic" },
        true,
    );
    try std.testing.expect(stream.prefix_sent);
    try std.testing.expect(stream.local_fin);
    try std.testing.expectEqual(@as(u64, 6), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 9), stream.send_offset);

    var packet = try quic.one_rtt.receive(
        &receiver_endpoint,
        keys,
        "wt-slice-client".len,
        0,
        8,
    );
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), packet.frames.len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x40, 0x41, 0x00 },
        packet.frames[0].stream.data,
    );
    try std.testing.expectEqualStrings(
        "at",
        packet.frames[1].stream.data,
    );
    try std.testing.expectEqual(@as(u64, 3), packet.frames[1].stream.offset);
    try std.testing.expectEqualStrings(
        "om",
        packet.frames[2].stream.data,
    );
    try std.testing.expectEqual(@as(u64, 5), packet.frames[2].stream.offset);
    try std.testing.expectEqualStrings(
        "ic",
        packet.frames[3].stream.data,
    );
    try std.testing.expectEqual(@as(u64, 7), packet.frames[3].stream.offset);
    try std.testing.expect(!packet.frames[0].stream.fin);
    try std.testing.expect(!packet.frames[1].stream.fin);
    try std.testing.expect(!packet.frames[2].stream.fin);
    try std.testing.expect(packet.frames[3].stream.fin);
}
