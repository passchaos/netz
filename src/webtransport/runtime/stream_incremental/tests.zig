const std = @import("std");
const stream_incremental_root = @import("../stream_incremental.zig");

const association = @import("../stream_association.zig");
const quic = @import("../../../quic/mod.zig");
const webtransport = @import("../../mod.zig");

const poll = stream_incremental_root.poll;
const pollOnce = stream_incremental_root.pollOnce;
const pollOnceShared = stream_incremental_root.pollOnceShared;
const read = stream_incremental_root.read;
const readId = stream_incremental_root.readId;
const readIdWithDeadline = stream_incremental_root.readIdWithDeadline;
const readWithDeadline = stream_incremental_root.readWithDeadline;
const reset = stream_incremental_root.reset;
const resetReliably = stream_incremental_root.resetReliably;
const stop = stream_incremental_root.stop;

test "WebTransport shared endpoint leaves sibling Session stream for owner" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8c} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-shared-server",
        .peer_connection_id = "wt-shared-client",
        .local_endpoint = .server,
        .initial_receive_max_streams_bidi = 3,
        .enable_pacing = false,
    });
    defer connection.deinit();

    const first_id: webtransport.SessionId = .init(0);
    const second_id: webtransport.SessionId = .init(4);
    var first = try webtransport.StreamRegistry.init(
        allocator,
        first_id,
        .server,
        .{ .max_peer_bidi = 1 },
    );
    defer first.deinit();
    var second = try webtransport.StreamRegistry.init(
        allocator,
        second_id,
        .server,
        .{ .max_peer_bidi = 1 },
    );
    defer second.deinit();

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        second_id,
    );
    var bytes_storage: [32]u8 = undefined;
    const bytes = bytes_storage[0 .. prefix.len + "second".len];
    @memcpy(bytes[0..prefix.len], prefix);
    @memcpy(bytes[prefix.len..], "second");
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 8,
            .data = bytes,
            .fin = true,
        } }},
        null,
        .not_ect,
    );

    const Known = struct {
        ids: []const u62,

        fn contains(
            context: *const anyopaque,
            _: u64,
            session_id: u62,
        ) bool {
            const self: *const @This() = @ptrCast(@alignCast(context));
            return std.mem.indexOfScalar(u62, self.ids, session_id) != null;
        }
    };
    const known_ids = [_]u62{ first_id.value, second_id.value };
    const known = Known{ .ids = &known_ids };
    const lookup = association.SessionLookup{
        .context = &known,
        .scope = 0,
        .containsFn = Known.contains,
    };
    var out: [16]u8 = undefined;
    try std.testing.expect((try pollOnceShared(
        &connection,
        &first,
        first_id,
        &out,
        lookup,
    )) == null);
    try std.testing.expect(connection.sendStreamStats(8) == null or
        connection.sendStreamStats(8).?.reset == null);
    try std.testing.expect(
        connection.recvStreamStats(8).?.stop_sending_sent == null,
    );

    const event = (try pollOnceShared(
        &connection,
        &second,
        second_id,
        &out,
        lookup,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(@as(u62, 8), event.data.stream_id);
    try std.testing.expectEqualStrings("second", out[0..event.data.bytes]);
    try std.testing.expect(event.data.fin);
}

test "WebTransport incremental poll rejects wrong-session bidi before sibling" {
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
        .local_connection_id = "wt-wrong-bidi-server",
        .peer_connection_id = "wt-wrong-bidi-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 32,
        .receive_window = 32,
        .max_receive_window = 32,
        .initial_receive_max_stream_data = 12,
        .stream_receive_window = 12,
        .max_stream_receive_window = 12,
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

    var wrong_header_storage: [16]u8 = undefined;
    const wrong_header = try webtransport.BidirectionalStreamHeader.writeInto(
        &wrong_header_storage,
        .init(4),
    );
    var wrong_bytes_storage: [32]u8 = undefined;
    const wrong_bytes = wrong_bytes_storage[0 .. wrong_header.len + "wrong!".len];
    @memcpy(wrong_bytes[0..wrong_header.len], wrong_header);
    @memcpy(wrong_bytes[wrong_header.len..], "wrong!");
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
            .{ .stream = .{
                .stream_id = 4,
                .data = wrong_bytes,
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = 8,
                .data = valid_bytes,
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    var out: [8]u8 = undefined;
    try std.testing.expect((try pollOnce(
        &connection,
        &registry,
        session_id,
        &out,
    )) == null);
    const rejection_code =
        webtransport.ApplicationErrorCode.buffered_stream_rejected;
    try std.testing.expectEqual(
        rejection_code,
        connection.sendStreamStats(4).?.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        rejection_code,
        connection.recvStreamStats(4).?.stop_sending_sent.?
            .application_error_code,
    );
    var rejection_datagram = try sender.receiveBytes();
    defer rejection_datagram.deinit(allocator);
    var rejection = try quic.one_rtt.openReceivedBytes(
        &sender,
        rejection_datagram.from,
        rejection_datagram.bytes,
        keys,
        "wt-wrong-bidi-client".len,
        0,
        4,
    );
    defer rejection.deinit(allocator);
    var saw_reset = false;
    var saw_stop = false;
    for (rejection.frames) |frame| switch (frame) {
        .reset_stream => |reset_info| {
            try std.testing.expectEqual(@as(u64, 4), reset_info.stream_id);
            try std.testing.expectEqual(
                rejection_code,
                reset_info.application_error_code,
            );
            saw_reset = true;
        },
        .stop_sending => |stop_info| {
            try std.testing.expectEqual(@as(u64, 4), stop_info.stream_id);
            try std.testing.expectEqual(
                rejection_code,
                stop_info.application_error_code,
            );
            saw_stop = true;
        },
        else => {},
    };
    try std.testing.expect(saw_reset);
    try std.testing.expect(saw_stop);
    try std.testing.expectEqual(
        @as(u64, wrong_bytes.len),
        quic.one_rtt.testing.receiveDataConsumed(&connection),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        quic.one_rtt.testing.receiveStreamAvailableLen(&connection, 4).?,
    );
    try std.testing.expect(registry.get(4) == null);

    // The cancelled stream is already drained, so the next bounded turn can
    // deliver the sibling instead of spending another turn on cleanup.
    const event = (try pollOnce(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(@as(u62, 8), event.data.stream_id);
    try std.testing.expectEqualStrings("ok", out[0..event.data.bytes]);
    try std.testing.expect(event.data.fin);
}

test "WebTransport incremental read consumes one UDP GRO stream batch" {
    if (!quic.runtime.udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400, .enable_gro_receive = true },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer sender.deinit();
    if (!receiver.groReceiveEnabled() or !sender.gsoSendEnabled()) {
        return error.SkipZigTest;
    }

    const client_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const server_cid = [_]u8{ 0x65, 0x66, 0x67, 0x68 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x69} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 1 },
    );
    defer registry.deinit();

    const first_data = [_]u8{ 0x40, 0x41, 0x00 } ++
        [_]u8{0xa5} ** 999;
    const second_data = [_]u8{0x5a} ** 1000;
    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .offset = 0,
        .data = &first_data,
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .offset = first_data.len,
        .data = &second_data,
        .fin = true,
    } }};
    var out: [2048]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        readWithDeadline(
            &connection,
            &registry,
            session_id,
            &out,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromNanoseconds(0),
            }),
        ),
    );
    try quic.one_rtt.sendFramesBatch(
        &sender,
        receiver.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .first_packet_number = 0,
            .packet_number_len = 4,
            .packets = &.{ &first, &second },
        },
    );

    const event = try readWithDeadline(
        &connection,
        &registry,
        session_id,
        &out,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(@as(u62, 4), event.data.stream_id);
    try std.testing.expectEqual(@as(usize, 1999), event.data.bytes);
    try std.testing.expect(event.data.fin);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xa5} ** 999),
        out[0..999],
    );
    try std.testing.expectEqualSlices(
        u8,
        &second_data,
        out[999..1999],
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        connection.stats().packets_received,
    );
}

test "WebTransport UDP GRO batch preserves incremental stream rotation" {
    if (!quic.runtime.udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400, .enable_gro_receive = true },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer sender.deinit();
    if (!receiver.groReceiveEnabled() or !sender.gsoSendEnabled()) {
        return error.SkipZigTest;
    }

    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x79} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .max_datagram_size = 1400,
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

    const first_data = [_]u8{ 0x40, 0x41, 0x00 } ++
        [_]u8{0xa1} ** 997;
    const second_data = [_]u8{ 0x40, 0x41, 0x00 } ++
        [_]u8{0xb2} ** 997;
    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .data = &first_data,
        .fin = true,
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 8,
        .data = &second_data,
        .fin = true,
    } }};
    try quic.one_rtt.sendFramesBatch(
        &sender,
        receiver.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .first_packet_number = 0,
            .packet_number_len = 4,
            .packets = &.{ &first, &second },
        },
    );

    var out: [1024]u8 = undefined;
    const first_event = try readWithDeadline(
        &connection,
        &registry,
        session_id,
        &out,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expect(first_event == .data);
    try std.testing.expectEqual(@as(u62, 4), first_event.data.stream_id);
    try std.testing.expectEqual(@as(usize, 997), first_event.data.bytes);
    try std.testing.expect(first_event.data.fin);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xa1} ** 997),
        out[0..997],
    );

    // Stream 8 was applied by the same kernel receive. The cursor still
    // returns one stream event per call and advances past stream 4.
    const second_event = try readWithDeadline(
        &connection,
        &registry,
        session_id,
        &out,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expect(second_event == .data);
    try std.testing.expectEqual(@as(u62, 8), second_event.data.stream_id);
    try std.testing.expectEqual(@as(usize, 997), second_event.data.bytes);
    try std.testing.expect(second_event.data.fin);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xb2} ** 997),
        out[0..997],
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        connection.stats().packets_received,
    );
}

test "WebTransport incremental polling rotates across busy streams" {
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
        [_]u8{0x91} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-fair-server",
        .peer_connection_id = "wt-fair-client",
        .local_endpoint = .server,
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

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try webtransport.BidirectionalStreamHeader.write(
        &encoded,
        allocator,
        session_id,
    );
    try encoded.appendSlice(allocator, "busy");
    var idle: std.ArrayList(u8) = .empty;
    defer idle.deinit(allocator);
    try webtransport.BidirectionalStreamHeader.write(
        &idle,
        allocator,
        session_id,
    );
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            // An unrelated HTTP/3 unidirectional stream and an associated but
            // idle stream must not interfere with the ready-stream rotation.
            .{ .stream = .{ .stream_id = 2, .data = &.{0} } },
            .{ .stream = .{ .stream_id = 4, .data = encoded.items } },
            .{ .stream = .{ .stream_id = 12, .data = idle.items } },
            .{ .stream = .{ .stream_id = 8, .data = encoded.items } },
        },
        null,
        .not_ect,
    );

    var byte: [1]u8 = undefined;
    const first = (try poll(
        &connection,
        &registry,
        session_id,
        &byte,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expectEqual(@as(u62, 4), first.data.stream_id);
    try std.testing.expectEqualStrings("b", &byte);

    // Stream four still has immediately readable bytes, but the stable cursor
    // gives its equally busy sibling the next application scheduling turn.
    const second = (try poll(
        &connection,
        &registry,
        session_id,
        &byte,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(second == .data);
    try std.testing.expectEqual(@as(u62, 8), second.data.stream_id);
    try std.testing.expectEqualStrings("b", &byte);

    const wrapped = (try poll(
        &connection,
        &registry,
        session_id,
        &byte,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(wrapped == .data);
    try std.testing.expectEqual(@as(u62, 4), wrapped.data.stream_id);
    try std.testing.expectEqualStrings("u", &byte);
}

test "WebTransport stopped receive drains connection credit only" {
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
        [_]u8{0x92} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-stop-server",
        .peer_connection_id = "wt-stop-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 16,
        .receive_window = 16,
        .max_receive_window = 16,
        .initial_receive_max_stream_data = 16,
        .stream_receive_window = 16,
        .max_stream_receive_window = 16,
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

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        session_id,
    );
    var first_bytes: [16]u8 = undefined;
    @memcpy(first_bytes[0..prefix.len], prefix);
    @memset(first_bytes[prefix.len..], 0xa5);
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 4,
            .data = &first_bytes,
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    var out: [1]u8 = undefined;
    const first = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try stop(&connection, &registry, 4, 17);
    var stop_datagram = try sender.receiveBytes();
    defer stop_datagram.deinit(allocator);

    try std.testing.expect((try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        quic.one_rtt.testing.receiveStreamAvailableLen(&connection, 4).?,
    );
    try std.testing.expectEqual(
        @as(u64, 16),
        connection.recvStreamStats(4).?.receive_limit,
    );
    try std.testing.expect(registry.get(4).?.peer_fin);
    var credit_datagram = try sender.receiveBytes();
    defer credit_datagram.deinit(allocator);
    var credit = try quic.one_rtt.openReceivedBytes(
        &sender,
        credit_datagram.from,
        credit_datagram.bytes,
        keys,
        "wt-stop-client".len,
        0,
        8,
    );
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), credit.frames.len);
    try std.testing.expect(credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 32),
        credit.frames[0].max_data.maximum_data,
    );
}

test "WebTransport targeted read drains stopped sibling" {
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
        [_]u8{0x96} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-target-server",
        .peer_connection_id = "wt-target-client",
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
    var out: [8]u8 = undefined;
    const first = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expectEqualStrings("a", out[0..first.data.bytes]);
    try stop(&connection, &registry, 4, 21);
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

    const target = try readId(
        &connection,
        &registry,
        session_id,
        8,
        &out,
    );
    try std.testing.expect(target == .data);
    try std.testing.expectEqual(@as(u62, 8), target.data.stream_id);
    try std.testing.expectEqualStrings("ok", out[0..target.data.bytes]);
    try std.testing.expect(target.data.fin);
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

test "WebTransport reliable reset maps application bytes to QUIC offsets" {
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
        [_]u8{0xde} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reliable-client",
        .peer_connection_id = "wt-reliable-server",
        .reliable_reset = .{ .peer = true },
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
        error.InvalidStreamState,
        resetReliably(&connection, &registry, stream.stream_id, 42, 1),
    );
    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        session_id,
    );
    try connection.send(&.{
        .{ .stream = .{
            .stream_id = stream.stream_id,
            .data = prefix,
        } },
        .{ .stream = .{
            .stream_id = stream.stream_id,
            .offset = @intCast(prefix.len),
            .data = "payload",
        } },
    });
    stream.send_offset = prefix.len + "payload".len;
    stream.bytes_sent = "payload".len;
    stream.prefix_sent = true;
    try std.testing.expectError(
        error.InvalidStreamState,
        resetReliably(&connection, &registry, stream.stream_id, 42, 8),
    );

    const association_prefix_size = stream.send_offset - stream.bytes_sent;
    try resetReliably(&connection, &registry, stream.stream_id, 42, 4);
    const reset_info = connection.sendStreamStats(stream.stream_id).?.reset.?;
    try std.testing.expectEqual(
        association_prefix_size + 4,
        reset_info.reliable_size,
    );
    try std.testing.expectEqual(
        @as(?u32, 42),
        stream.send_reset.?.application_code,
    );
}

test "WebTransport reset event restores final-size connection credit" {
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
        [_]u8{0x97} ** quic.protection.secret_len,
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
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .data = initial[0 .. prefix.len + 1],
            } },
            .{ .reset_stream = .{
                .stream_id = 4,
                .application_error_code = webtransport.applicationErrorCodeToHttp3(24),
                .final_size = 8,
            } },
        },
        null,
        .not_ect,
    );
    var out: [8]u8 = undefined;
    const event = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .reset);
    try std.testing.expectEqual(@as(u62, 4), event.reset.stream_id);
    try std.testing.expectEqual(
        @as(?u32, 24),
        event.reset.error_info.application_code,
    );
    try std.testing.expectEqual(@as(u64, 8), event.reset.final_size);
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
        0,
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

test "WebTransport reliable reset delivers its prefix before reset" {
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
        [_]u8{0xa7} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reliable-server",
        .peer_connection_id = "wt-reliable-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 32,
        .initial_receive_max_stream_data = 32,
        .initial_receive_max_streams_bidi = 2,
        .reliable_reset = .{ .local = true },
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

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        session_id,
    );
    var first_bytes: [18]u8 = undefined;
    @memcpy(first_bytes[0..prefix.len], prefix);
    @memcpy(first_bytes[prefix.len..][0..2], "ab");
    const first_len = prefix.len + 2;
    const reliable_size: u64 = @intCast(prefix.len + 4);
    const final_size: u64 = @intCast(prefix.len + 6);
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .data = first_bytes[0..first_len],
            } },
            .{ .reset_stream_at = .{
                .stream_id = 4,
                .application_error_code = webtransport.applicationErrorCodeToHttp3(25),
                .final_size = final_size,
                .reliable_size = reliable_size,
            } },
        },
        null,
        .not_ect,
    );

    var out: [8]u8 = undefined;
    const first = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expectEqualStrings("ab", out[0..first.data.bytes]);
    try std.testing.expect(!first.data.fin);
    try std.testing.expect((try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) == null);

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{
            .stream_id = 4,
            .offset = @intCast(first_len),
            .data = "cdxx",
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    const second = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(second == .data);
    try std.testing.expectEqualStrings("cd", out[0..second.data.bytes]);
    try std.testing.expect(!second.data.fin);

    const reset_event = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(reset_event == .reset);
    try std.testing.expectEqual(@as(u62, 4), reset_event.reset.stream_id);
    try std.testing.expectEqual(
        @as(?u32, 25),
        reset_event.reset.error_info.application_code,
    );
    try std.testing.expectEqual(final_size, reset_event.reset.final_size);
}

test "WebTransport targeted sibling preserves reset after transport reclaim" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x98} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reclaim-local",
        .peer_connection_id = "wt-reclaim-peer",
        .local_endpoint = .server,
        .initial_receive_max_data = 16,
        .receive_window = 16,
        .max_receive_window = 16,
        .initial_receive_max_stream_data = 16,
        .stream_receive_window = 16,
        .max_stream_receive_window = 16,
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
        .{ .max_peer_bidi = 2, .max_peer_uni = 1 },
    );
    defer registry.deinit();

    var reset_bytes: std.ArrayList(u8) = .empty;
    defer reset_bytes.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &reset_bytes,
        allocator,
        session_id,
    );
    try reset_bytes.append(allocator, 'x');
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 2,
            .data = reset_bytes.items,
        } }},
        null,
        .not_ect,
    );
    var out: [8]u8 = undefined;
    const first = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expectEqual(@as(u62, 2), first.data.stream_id);
    try std.testing.expectEqualStrings("x", out[0..first.data.bytes]);

    var target_storage: [16]u8 = undefined;
    const target_prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &target_storage,
        session_id,
    );
    var target_bytes: [18]u8 = undefined;
    @memcpy(target_bytes[0..target_prefix.len], target_prefix);
    @memcpy(target_bytes[target_prefix.len..][0..2], "ok");
    const reset_final_size: u64 = 8;
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{
            .{ .reset_stream = .{
                .stream_id = 2,
                .application_error_code = webtransport.applicationErrorCodeToHttp3(25),
                .final_size = reset_final_size,
            } },
            .{ .stream = .{
                .stream_id = 4,
                .data = target_bytes[0 .. target_prefix.len + 2],
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    const target = try readId(
        &connection,
        &registry,
        session_id,
        4,
        &out,
    );
    try std.testing.expect(target == .data);
    try std.testing.expectEqualStrings("ok", out[0..target.data.bytes]);
    try std.testing.expect(target.data.fin);
    try std.testing.expect(connection.peerStreamClosed(2));
    try std.testing.expect(connection.recvStreamStats(2) == null);

    const reset_event = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(reset_event == .reset);
    try std.testing.expectEqual(@as(u62, 2), reset_event.reset.stream_id);
    try std.testing.expectEqual(
        @as(?u32, 25),
        reset_event.reset.error_info.application_code,
    );
    try std.testing.expectEqual(
        reset_final_size,
        reset_event.reset.final_size,
    );
    try std.testing.expect((try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) == null);
}

test "WebTransport incremental deadlines preserve buffered stream events" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x93} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-deadline-server",
        .peer_connection_id = "wt-deadline-client",
        .local_endpoint = .server,
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

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        session_id,
    );
    var encoded: [21]u8 = undefined;
    @memcpy(encoded[0..prefix.len], prefix);
    @memcpy(encoded[prefix.len..][0..5], "ready");
    const stream_bytes = encoded[0 .. prefix.len + 5];
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .data = stream_bytes,
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = 8,
                .data = stream_bytes,
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    var out = [_]u8{0xa5} ** 5;
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(4).?.bytes_read,
    );
    try std.testing.expect(registry.get(4) == null);
    try std.testing.expectError(
        error.Timeout,
        readWithDeadline(
            &connection,
            &registry,
            session_id,
            &out,
            .fromNow(io, .{
                .clock = .real,
                .raw = .fromSeconds(1),
            }),
        ),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 5), &out);
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(4).?.bytes_read,
    );
    try std.testing.expect(registry.get(4) == null);

    const first = try readWithDeadline(
        &connection,
        &registry,
        session_id,
        &out,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expect(first == .data);
    try std.testing.expectEqual(@as(u62, 4), first.data.stream_id);
    try std.testing.expectEqualStrings("ready", &out);
    try std.testing.expect(first.data.fin);

    @memset(&out, 0xa5);
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(8).?.bytes_read,
    );
    try std.testing.expect(registry.get(8) == null);
    try std.testing.expectError(
        error.Timeout,
        readIdWithDeadline(
            &connection,
            &registry,
            session_id,
            8,
            &out,
            .fromNow(io, .{
                .clock = .real,
                .raw = .fromSeconds(1),
            }),
        ),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 5), &out);
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(8).?.bytes_read,
    );
    try std.testing.expect(registry.get(8) == null);

    const second = try readIdWithDeadline(
        &connection,
        &registry,
        session_id,
        8,
        &out,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expect(second == .data);
    try std.testing.expectEqual(@as(u62, 8), second.data.stream_id);
    try std.testing.expectEqualStrings("ready", &out);
    try std.testing.expect(second.data.fin);
}
