const std = @import("std");
const webtransport = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const batch = @import("../batch.zig");

const AdvancingSendIo = struct {
    delegate: std.Io,
    now_ns: i96,
    advance_ns: i96,
    send_calls: usize = 0,

    fn now(
        userdata: ?*anyopaque,
        _: std.Io.Clock,
    ) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        return .fromNanoseconds(self.now_ns);
    }

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: std.Io.net.Socket.Handle,
        messages: []std.Io.net.OutgoingMessage,
        flags: std.Io.net.SendFlags,
    ) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        const result = self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
        self.send_calls += 1;
        self.now_ns += self.advance_ns;
        return result;
    }
};

test "WebTransport batch selects high priority streams with stable ties" {
    var registry = try webtransport.StreamRegistry.init(
        std.testing.allocator,
        .init(0),
        .client,
        .{},
    );
    defer registry.deinit();
    const low = (try registry.openLocal(.bidirectional)).stream_id;
    const high_first = (try registry.openLocal(.bidirectional)).stream_id;
    const high_second = (try registry.openLocal(.bidirectional)).stream_id;
    try registry.setPriority(low, -4);
    try registry.setPriority(high_first, 7);
    try registry.setPriority(high_second, 7);
    const writes = [_]batch.Write{
        .{ .stream_id = low, .data = "low" },
        .{ .stream_id = high_first, .data = "high-a" },
        .{ .stream_id = high_second, .data = "high-b" },
    };
    const epoch = registry.beginBatchEpoch();
    var selected: [3]usize = undefined;
    selected[0] = (try batch.testing.nextWrite(&registry, &writes, epoch)).?;
    try std.testing.expect(registry.markForBatch(
        writes[selected[0]].stream_id,
        epoch,
    ).?.first);
    selected[1] = (try batch.testing.nextWrite(&registry, &writes, epoch)).?;
    try std.testing.expect(registry.markForBatch(
        writes[selected[1]].stream_id,
        epoch,
    ).?.first);
    selected[2] = (try batch.testing.nextWrite(&registry, &writes, epoch)).?;
    try std.testing.expectEqualSlices(usize, &.{ 1, 2, 0 }, &selected);
}

test "WebTransport batch selection skips a marked high priority stream" {
    var registry = try webtransport.StreamRegistry.init(
        std.testing.allocator,
        .init(0),
        .client,
        .{},
    );
    defer registry.deinit();
    const high = (try registry.openLocal(.bidirectional)).stream_id;
    const low = (try registry.openLocal(.bidirectional)).stream_id;
    try registry.setPriority(high, 100);
    try registry.setPriority(low, -100);
    const writes = [_]batch.Write{
        .{ .stream_id = high, .data = "high" },
        .{ .stream_id = low, .data = "low" },
    };
    const epoch = registry.beginBatchEpoch();
    const first = (try batch.testing.nextWrite(&registry, &writes, epoch)).?;
    try std.testing.expectEqual(@as(usize, 0), first);
    try std.testing.expect(registry.markForBatch(high, epoch).?.first);
    try std.testing.expectEqual(
        @as(?usize, 1),
        try batch.testing.nextWrite(&registry, &writes, epoch),
    );
}

test "WebTransport steady batch keeps highest priorities with stable ties" {
    var selected: [3]batch.testing.Ordered = undefined;
    var count: usize = 0;
    for ([_]batch.testing.Ordered{
        .{ .input_index = 0, .priority = 1, .byte_count = 10, .send_offset = 20 },
        .{ .input_index = 1, .priority = 3, .byte_count = 11, .send_offset = 21 },
        .{ .input_index = 2, .priority = 3, .byte_count = 12, .send_offset = 22 },
        .{ .input_index = 3, .priority = 2, .byte_count = 13, .send_offset = 23 },
        .{ .input_index = 4, .priority = 4, .byte_count = 14, .send_offset = 24 },
    }) |candidate| {
        batch.testing.insertOrdered(
            &selected,
            &count,
            selected.len,
            candidate,
        );
    }
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 4, 1, 2 },
        &[_]usize{
            selected[0].input_index,
            selected[1].input_index,
            selected[2].input_index,
        },
    );
    try std.testing.expectEqual(@as(usize, 14), selected[0].byte_count);
    try std.testing.expectEqual(@as(u64, 24), selected[0].send_offset);
}

test "WebTransport steady batch tail insert and full rejection preserve order" {
    var selected: [3]batch.testing.Ordered = undefined;
    var count: usize = 0;
    for ([_]batch.testing.Ordered{
        .{ .input_index = 0, .priority = 4, .byte_count = 10, .send_offset = 20 },
        .{ .input_index = 1, .priority = 3, .byte_count = 11, .send_offset = 21 },
        .{ .input_index = 2, .priority = 3, .byte_count = 12, .send_offset = 22 },
    }) |candidate| {
        batch.testing.insertOrdered(
            &selected,
            &count,
            selected.len,
            candidate,
        );
    }
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 0, 1, 2 },
        &[_]usize{
            selected[0].input_index,
            selected[1].input_index,
            selected[2].input_index,
        },
    );

    batch.testing.insertOrdered(
        &selected,
        &count,
        selected.len,
        .{ .input_index = 3, .priority = 2, .byte_count = 13, .send_offset = 23 },
    );
    try std.testing.expectEqualSlices(
        usize,
        &.{ 0, 1, 2 },
        &[_]usize{
            selected[0].input_index,
            selected[1].input_index,
            selected[2].input_index,
        },
    );

    batch.testing.insertOrdered(
        &selected,
        &count,
        selected.len,
        .{ .input_index = 4, .priority = 5, .byte_count = 14, .send_offset = 24 },
    );
    try std.testing.expectEqualSlices(
        usize,
        &.{ 4, 0, 1 },
        &[_]usize{
            selected[0].input_index,
            selected[1].input_index,
            selected[2].input_index,
        },
    );
}

test "WebTransport steady batch stages offset without committing it" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x57} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-stage-client",
        .peer_connection_id = "wt-stage-server",
        .initial_send_max_streams_bidi = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    stream.prefix_sent = true;
    stream.send_offset = 123;
    const writes = [_]batch.Write{
        .{ .stream_id = stream.stream_id, .data = "payload" },
    };

    const staged = try batch.testing.stageSteady(
        &connection,
        &registry,
        &writes,
    );
    try std.testing.expectEqual(@as(usize, 1), staged.packet_count);
    try std.testing.expectEqual(
        @as(u64, stream.stream_id + 123 + 2 * "payload".len),
        staged.checksum,
    );
    try std.testing.expectEqual(@as(u64, 123), stream.send_offset);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
}

test "WebTransport batch validates duplicate beyond packet window" {
    const count = quic.one_rtt.max_batch_packets + 1;
    var registry = try webtransport.StreamRegistry.init(
        std.testing.allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = count },
    );
    defer registry.deinit();
    var writes: [count]batch.Write = undefined;
    for (&writes) |*item| {
        const stream = try registry.openLocal(.bidirectional);
        item.* = .{ .stream_id = stream.stream_id, .data = "x" };
    }
    writes[count - 1].stream_id = writes[0].stream_id;

    try std.testing.expectError(
        error.DuplicateStream,
        batch.validate(&registry, &writes),
    );
    for (registry.registered()) |stream| {
        try std.testing.expect(!stream.prefix_sent);
        try std.testing.expectEqual(@as(u64, 0), stream.send_offset);
    }
}

test "WebTransport batch deadline rejects wrong clock and clears counts" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x58} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-batch-clock-a",
        .peer_connection_id = "wt-batch-clock-b",
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    const writes = [_]batch.Write{.{
        .stream_id = stream.stream_id,
        .data = "payload",
    }};
    var counts = [_]usize{99};

    try std.testing.expectError(
        error.Timeout,
        batch.writeWithDeadline(
            &connection,
            &registry,
            .init(0),
            &writes,
            &counts,
            .{
                .clock = .real,
                .raw = .fromNanoseconds(std.time.ns_per_s),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), counts[0]);
    try std.testing.expect(!stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), stream.send_offset);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);

    counts[0] = 99;
    try std.testing.expectError(
        error.Timeout,
        batch.writeWithTimeout(
            &connection,
            &registry,
            .init(0),
            &writes,
            &counts,
            .fromNanoseconds(0),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), counts[0]);
    try std.testing.expect(!stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), stream.send_offset);
}

test "WebTransport batch deadline resumes prefix-only flow control" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer sender_endpoint.deinit();
    var silent_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer silent_peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x59} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = silent_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-batch-flow-a",
        .peer_connection_id = "wt-batch-flow-b",
        .initial_send_max_data = 6,
        .initial_send_max_stream_data_bidi_remote = 3,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = 2 },
    );
    defer registry.deinit();
    const first = try registry.openLocal(.bidirectional);
    const second = try registry.openLocal(.bidirectional);
    const writes = [_]batch.Write{
        .{ .stream_id = first.stream_id, .data = "first" },
        .{ .stream_id = second.stream_id, .data = "second" },
    };
    var counts = [_]usize{ 99, 99 };

    try std.testing.expectError(
        error.Timeout,
        batch.writeWithDeadline(
            &connection,
            &registry,
            .init(0),
            &writes,
            &counts,
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqualSlices(usize, &.{ 0, 0 }, &counts);
    try std.testing.expect(first.prefix_sent);
    try std.testing.expect(second.prefix_sent);
    try std.testing.expectEqual(@as(u64, 3), first.send_offset);
    try std.testing.expectEqual(@as(u64, 3), second.send_offset);
    try std.testing.expectEqual(@as(u64, 0), first.bytes_sent);
    try std.testing.expectEqual(@as(u64, 0), second.bytes_sent);

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .max_data = .{ .maximum_data = 64 } },
            .{ .max_stream_data = .{
                .stream_id = first.stream_id,
                .maximum_stream_data = 64,
            } },
            .{ .max_stream_data = .{
                .stream_id = second.stream_id,
                .maximum_stream_data = 64,
            } },
        },
        null,
        .not_ect,
    );
    const result = try batch.writeWithDeadline(
        &connection,
        &registry,
        .init(0),
        &writes,
        &counts,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    try std.testing.expectEqual(@as(usize, 2), result.progressed);
    try std.testing.expectEqualSlices(usize, &.{ 5, 6 }, &counts);
    try std.testing.expectEqual(@as(u64, 5), first.bytes_sent);
    try std.testing.expectEqual(@as(u64, 6), second.bytes_sent);
}

test "WebTransport batch partial socket send commits exact per-stream counts" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400, .enable_gso_send = false },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x5a} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-batch-part-a",
        .peer_connection_id = "wt-batch-part-b",
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = 2 },
    );
    defer registry.deinit();
    const first = try registry.openLocal(.bidirectional);
    const second = try registry.openLocal(.bidirectional);
    first.prefix_sent = true;
    second.prefix_sent = true;
    first.send_offset = 3;
    second.send_offset = 3;
    const writes = [_]batch.Write{
        .{ .stream_id = first.stream_id, .data = "first" },
        .{ .stream_id = second.stream_id, .data = "second" },
    };
    var counts: [2]usize = undefined;

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

    const result = try batch.writeOnce(
        &connection,
        &registry,
        .init(0),
        &writes,
        &counts,
    );
    try std.testing.expectEqual(@as(usize, 1), result.progressed);
    try std.testing.expectEqual(error.NetworkDown, result.send_error.?);
    try std.testing.expectEqualSlices(usize, &.{ 5, 0 }, &counts);
    try std.testing.expectEqual(@as(u64, 5), first.bytes_sent);
    try std.testing.expectEqual(@as(u64, 0), second.bytes_sent);
    try std.testing.expectEqual(@as(u64, 8), first.send_offset);
    try std.testing.expectEqual(@as(u64, 3), second.send_offset);
}

test "WebTransport batch deadline stops between association prefixes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x5b} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-batch-time-a",
        .peer_connection_id = "wt-batch-time-b",
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = 2 },
    );
    defer registry.deinit();
    const first = try registry.openLocal(.bidirectional);
    const second = try registry.openLocal(.bidirectional);
    const writes = [_]batch.Write{
        .{ .stream_id = first.stream_id, .data = "first" },
        .{ .stream_id = second.stream_id, .data = "second" },
    };
    var counts = [_]usize{ 99, 99 };

    var advancing = AdvancingSendIo{
        .delegate = sender_endpoint.io,
        .now_ns = 1_000_000,
        .advance_ns = 2_000_000,
    };
    var advancing_vtable = sender_endpoint.io.vtable.*;
    advancing_vtable.now = AdvancingSendIo.now;
    advancing_vtable.netSend = AdvancingSendIo.netSend;
    sender_endpoint.io = .{
        .userdata = &advancing,
        .vtable = &advancing_vtable,
    };
    defer sender_endpoint.io = advancing.delegate;

    try std.testing.expectError(
        error.Timeout,
        batch.writeWithDeadline(
            &connection,
            &registry,
            .init(0),
            &writes,
            &counts,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(2_000_000),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), advancing.send_calls);
    try std.testing.expectEqualSlices(usize, &.{ 0, 0 }, &counts);
    try std.testing.expect(first.prefix_sent);
    try std.testing.expect(!second.prefix_sent);
    try std.testing.expectEqual(@as(u64, 3), first.send_offset);
    try std.testing.expectEqual(@as(u64, 0), second.send_offset);
    try std.testing.expectEqual(@as(u64, 0), first.bytes_sent);
    try std.testing.expectEqual(@as(u64, 0), second.bytes_sent);
}
