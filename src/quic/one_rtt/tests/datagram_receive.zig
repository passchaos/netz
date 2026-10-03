const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");

test "QUIC 1-RTT caller-buffer DATAGRAM receive preserves ordering and storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const client_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const server_cid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd8 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd0} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .max_datagram_queue_items = 2,
        .enable_pacing = false,
    });
    defer server.deinit();
    var out: [16]u8 = undefined;

    try client.sendDatagram("queued");
    var queued = try server.receivePacket();
    defer queued.deinit(allocator);
    try client.sendDatagram("later");
    try std.testing.expectEqualStrings(
        "queued",
        try server.receiveDatagramWithTimeout(&out, .fromSeconds(1)),
    );
    try std.testing.expectEqualStrings(
        "later",
        try server.receiveDatagramWithTimeout(&out, .fromSeconds(1)),
    );

    try client.sendDatagram("direct");
    try std.testing.expectEqualStrings(
        "direct",
        try server.receiveDatagramWithTimeout(&out, .fromSeconds(1)),
    );
    try std.testing.expectEqual(@as(usize, 0), server.datagramReceiveQueueLen());

    // Packet/frame scratch was warmed above. A second direct fixed-size read
    // must not need a payload allocation from the receiver endpoint.
    try client.sendDatagram("steady");
    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const steady = blk: {
        server_endpoint.allocator = fail.allocator();
        defer server_endpoint.allocator = allocator;
        break :blk try server.receiveDatagramWithTimeout(
            &out,
            .fromSeconds(1),
        );
    };
    try std.testing.expectEqualStrings("steady", steady);
    try std.testing.expect(!fail.has_induced_failure);

    try client.send(&.{
        .{ .datagram = .{ .data = "first", .length_present = true } },
        .{ .datagram = .{ .data = "second", .length_present = true } },
    });
    try std.testing.expectEqualStrings(
        "first",
        try server.receiveDatagramWithTimeout(&out, .fromSeconds(1)),
    );
    try std.testing.expectEqual(@as(usize, 1), server.datagramReceiveQueueLen());
    try std.testing.expectEqualStrings(
        "second",
        (try server.popDatagram(&out)).?,
    );

    const batch = [_][]const u8{ "batch-a", "batch-b", "batch-c" };
    var sent_count: usize = 0;
    try client.sendDatagramsWithTimeout(
        &batch,
        &sent_count,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(batch.len, sent_count);
    var batch_storage: [batch.len][16]u8 = undefined;
    var batch_outputs: [batch.len][]u8 = undefined;
    for (&batch_storage, &batch_outputs) |*storage, *output| output.* = storage;
    var received_count: usize = 99;
    try server.receiveDatagramsWithTimeout(
        &batch_outputs,
        &received_count,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(batch.len, received_count);
    for (batch, batch_outputs) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }
    try std.testing.expectEqual(@as(usize, 0), server.datagramReceiveQueueLen());
    var empty_outputs: [0][]u8 = .{};
    received_count = 99;
    try server.receiveDatagrams(&empty_outputs, &received_count);
    try std.testing.expectEqual(@as(usize, 0), received_count);
    var too_many_outputs: [quic.runtime.max_receive_batch_messages + 1][]u8 = undefined;
    for (&too_many_outputs) |*output| output.* = &out;
    try std.testing.expectError(
        error.BufferTooShort,
        server.receiveDatagrams(&too_many_outputs, &received_count),
    );
    try std.testing.expectEqual(@as(usize, 0), received_count);

    try client.sendDatagram("fits");
    try client.sendDatagram("too-large");
    var short_first: [8]u8 = undefined;
    var short_second: [2]u8 = undefined;
    var short_outputs = [_][]u8{ &short_first, &short_second };
    try std.testing.expectError(
        error.DatagramBufferTooSmall,
        server.receiveDatagramsWithTimeout(
            &short_outputs,
            &received_count,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), received_count);
    try std.testing.expectEqualStrings("fits", short_outputs[0]);
    try std.testing.expectEqual(@as(usize, 0), server.datagramReceiveQueueLen());

    try std.testing.expectError(
        error.Timeout,
        server.receiveDatagramsWithTimeout(
            &batch_outputs,
            &received_count,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), received_count);

    try client.sendDatagram("large");
    try std.testing.expectError(
        error.DatagramBufferTooSmall,
        server.receiveDatagramWithTimeout(out[0..2], .fromSeconds(1)),
    );
    try std.testing.expectEqual(@as(usize, 0), server.datagramReceiveQueueLen());
    try std.testing.expectError(
        error.Timeout,
        server.receiveDatagramWithTimeout(&out, .zero),
    );

    const borrowed_payloads = [_][]const u8{
        "borrow-a",
        "borrow-b",
        "borrow-c",
    };
    sent_count = 0;
    try client.sendDatagramsWithTimeout(
        &borrowed_payloads,
        &sent_count,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(borrowed_payloads.len, sent_count);
    const BorrowedContext = struct {
        connection: *one_rtt.Connection,
        expected: []const []const u8,
        next: usize = 0,

        fn visit(self: *@This(), payload: []const u8) !void {
            if (self.next >= self.expected.len) {
                return error.UnexpectedDatagram;
            }
            try std.testing.expectEqualStrings(
                self.expected[self.next],
                payload,
            );
            var nested: [1]u8 = undefined;
            try std.testing.expectError(
                error.ConcurrencyUnavailable,
                self.connection.receiveDatagramWithTimeout(
                    &nested,
                    .fromSeconds(1),
                ),
            );
            self.next += 1;
        }
    };
    var borrowed_context: BorrowedContext = .{
        .connection = &server,
        .expected = &borrowed_payloads,
    };
    var raw_storage: [borrowed_payloads.len * 4096]u8 = undefined;
    var raw_datagrams: [borrowed_payloads.len]quic.runtime.ReceivedBytesView =
        undefined;
    while (borrowed_context.next < borrowed_payloads.len) {
        const delivered = try server
            .visitDatagramBatchIntoServicingTimersDeadline(
            &raw_storage,
            &raw_datagrams,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromSeconds(1),
            }),
            &borrowed_context,
            BorrowedContext.visit,
        );
        try std.testing.expect(delivered != 0);
    }
    try std.testing.expectEqual(
        @as(usize, 0),
        server.datagramReceiveQueueLen(),
    );

    const RejectVisitor = struct {
        fn visit(_: void, _: []const u8) !void {
            return error.StopVisitor;
        }
    };
    try client.sendDatagram("callback-error");
    try std.testing.expectError(
        error.StopVisitor,
        server.visitDatagramBatchIntoServicingTimersDeadline(
            &raw_storage,
            &raw_datagrams,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromSeconds(1),
            }),
            {},
            RejectVisitor.visit,
        ),
    );
    try client.sendDatagram("after-error");
    try std.testing.expectEqualStrings(
        "after-error",
        try server.receiveDatagramWithTimeout(&out, .fromSeconds(1)),
    );

    const no_alloc_payloads = [_][]const u8{"borrowed-steady"};
    try client.sendDatagram(no_alloc_payloads[0]);
    var no_alloc_context: BorrowedContext = .{
        .connection = &server,
        .expected = &no_alloc_payloads,
    };
    const received_before_timeout = server.datagramsReceived();
    try std.testing.expectError(
        error.Timeout,
        server.visitDatagramBatchIntoServicingTimersTimeout(
            &raw_storage,
            &raw_datagrams,
            .zero,
            &no_alloc_context,
            BorrowedContext.visit,
        ),
    );
    try std.testing.expectEqual(
        received_before_timeout,
        server.datagramsReceived(),
    );
    try std.testing.expectEqual(@as(usize, 0), no_alloc_context.next);
    var borrowed_fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const borrowed_delivered = blk: {
        server_endpoint.allocator = borrowed_fail.allocator();
        defer server_endpoint.allocator = allocator;
        break :blk try server
            .visitDatagramBatchIntoServicingTimersTimeout(
            &raw_storage,
            &raw_datagrams,
            .fromSeconds(1),
            &no_alloc_context,
            BorrowedContext.visit,
        );
    };
    try std.testing.expectEqual(@as(usize, 1), borrowed_delivered);
    try std.testing.expect(!borrowed_fail.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 0),
        server.datagramReceiveQueueLen(),
    );
}

test "QUIC 1-RTT caller-buffer DATAGRAM receive rejects disabled negotiation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer endpoint.deinit();
    const cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &cid,
        .peer_connection_id = &cid,
    });
    defer connection.deinit();
    var out: [32]u8 = undefined;
    try std.testing.expectError(
        error.DatagramsNotEnabled,
        connection.receiveDatagramWithTimeout(&out, .fromMilliseconds(1)),
    );
}

test "QUIC 1-RTT caller-buffer DATAGRAM receive bypasses disabled queue" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer receiver_endpoint.deinit();
    const sender_cid = [_]u8{ 0xdd, 0xde, 0xdf, 0xe0 };
    const receiver_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdc} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &sender_cid,
        .peer_connection_id = &receiver_cid,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer sender.deinit();
    var receiver = try one_rtt.Connection.init(&receiver_endpoint, .{
        .peer = sender_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &receiver_cid,
        .peer_connection_id = &sender_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .max_datagram_queue_items = 0,
        .enable_pacing = false,
    });
    defer receiver.deinit();

    try sender.sendDatagram("direct-only");
    var out: [32]u8 = undefined;
    try std.testing.expectEqualStrings(
        "direct-only",
        try receiver.receiveDatagramWithTimeout(&out, .fromSeconds(1)),
    );
    try std.testing.expectEqual(@as(u64, 1), receiver.datagramsReceived());
    try std.testing.expectEqual(
        @as(u64, 0),
        receiver.datagramsDroppedIncoming(),
    );
    try std.testing.expectEqual(@as(usize, 0), receiver.datagramReceiveQueueLen());
}

test "QUIC caller-buffer DATAGRAM batch accepts GRO segments" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200, .enable_gro_receive = true },
    );
    defer receiver_endpoint.deinit();
    if (!sender_endpoint.gsoSendEnabled() or
        !receiver_endpoint.groReceiveEnabled())
    {
        return error.SkipZigTest;
    }
    const sender_cid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const receiver_cid = [_]u8{ 0xf5, 0xf6, 0xf7, 0xf8 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf0} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &sender_cid,
        .peer_connection_id = &receiver_cid,
        .peer_max_datagram_frame_size = 1200,
        .max_frames_per_packet = 1,
        .enable_pacing = false,
    });
    defer sender.deinit();
    var receiver = try one_rtt.Connection.init(&receiver_endpoint, .{
        .peer = sender_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &receiver_cid,
        .peer_connection_id = &sender_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .max_datagram_queue_items = 3,
        .enable_pacing = false,
    });
    defer receiver.deinit();

    const payload_storage = [_][4]u8{ "aaaa".*, "bbbb".*, "cccc".* };
    var payloads: [payload_storage.len][]const u8 = undefined;
    for (&payload_storage, &payloads) |*storage, *payload| payload.* = storage;
    var sent_count: usize = 0;
    try sender.sendDatagramsWithTimeout(
        &payloads,
        &sent_count,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(payloads.len, sent_count);

    var output_storage: [payloads.len][8]u8 = undefined;
    var outputs: [payloads.len][]u8 = undefined;
    for (&output_storage, &outputs) |*storage, *output| output.* = storage;
    var received_count: usize = 0;
    try receiver.receiveDatagramsWithTimeout(
        &outputs,
        &received_count,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(payloads.len, received_count);
    for (payloads, outputs) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }
}

test "QUIC 1-RTT caller-buffer DATAGRAM waits for whole-packet validation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer receiver_endpoint.deinit();
    const sender_cid = [_]u8{ 0xe5, 0xe6, 0xe7, 0xe8 };
    const receiver_cid = [_]u8{ 0xe9, 0xea, 0xeb, 0xec };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe4} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &sender_cid,
        .peer_connection_id = &receiver_cid,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer sender.deinit();
    var receiver = try one_rtt.Connection.init(&receiver_endpoint, .{
        .peer = sender_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &receiver_cid,
        .peer_connection_id = &sender_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 8,
        .enable_pacing = false,
    });
    defer receiver.deinit();

    try sender.send(&.{
        .{ .datagram = .{ .data = "ok", .length_present = true } },
        .{ .datagram = .{ .data = "1234567", .length_present = true } },
    });
    var out: [16]u8 = [_]u8{0xaa} ** 16;
    try std.testing.expectError(
        error.InvalidFrame,
        receiver.receiveDatagramWithTimeout(&out, .fromSeconds(1)),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 16), &out);
    try std.testing.expectEqual(@as(u64, 0), receiver.datagramsReceived());
    try std.testing.expectEqual(@as(usize, 0), receiver.datagramReceiveQueueLen());
}
