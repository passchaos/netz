const std = @import("std");
const stream_root = @import("../stream.zig");

const quic = @import("../mod.zig");

const RecvState = stream_root.RecvState;
const SendState = stream_root.SendState;

test "QUIC send stream state writes offset STREAM frames" {
    const allocator = std.testing.allocator;
    var send = SendState.init(0);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try send.writeFrames(&encoded, allocator, "hello world", 5, true);
    var pos: usize = 0;
    const first = try quic.parseFrame(encoded.items[pos..]);
    pos += first.consumed;
    const second = try quic.parseFrame(encoded.items[pos..]);
    pos += second.consumed;
    const third = try quic.parseFrame(encoded.items[pos..]);
    pos += third.consumed;

    try std.testing.expectEqual(@as(usize, encoded.items.len), pos);
    try std.testing.expectEqual(@as(u64, 0), first.frame.stream.offset);
    try std.testing.expectEqualStrings("hello", first.frame.stream.data);
    try std.testing.expect(!first.frame.stream.fin);
    try std.testing.expectEqual(@as(u64, 5), second.frame.stream.offset);
    try std.testing.expectEqualStrings(" worl", second.frame.stream.data);
    try std.testing.expect(!second.frame.stream.fin);
    try std.testing.expectEqual(@as(u64, 10), third.frame.stream.offset);
    try std.testing.expectEqualStrings("d", third.frame.stream.data);
    try std.testing.expect(third.frame.stream.fin);
}

test "QUIC send stream state skips empty non-FIN writes" {
    const allocator = std.testing.allocator;
    var send = SendState.init(7);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try send.writeFrames(&encoded, allocator, &.{}, 0, false);
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);
    try std.testing.expectEqual(@as(u64, 0), send.next_offset);
    try std.testing.expect(!send.fin_sent);

    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    try send.appendFrames(&frames, allocator, &.{}, 0, false);
    try std.testing.expectEqual(@as(usize, 0), frames.items.len);
    try std.testing.expectEqual(@as(u64, 0), send.next_offset);
    try std.testing.expect(!send.fin_sent);

    try std.testing.expectError(
        error.InvalidStreamRange,
        send.writeFrames(&encoded, allocator, "x", 0, false),
    );
    try std.testing.expectError(
        error.InvalidStreamRange,
        send.appendFrames(&frames, allocator, "x", 0, false),
    );
}

test "QUIC receive stream state reassembles out of order and tracks FIN" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 1024);
    defer recv.deinit();

    try recv.insert(.{ .stream_id = 0, .offset = 6, .data = "world", .fin = true });
    try std.testing.expectEqual(@as(usize, 0), recv.available().len);
    try recv.insert(.{ .stream_id = 0, .offset = 0, .data = "hello ", .fin = false });
    try std.testing.expectEqualStrings("hello world", recv.available());
    try recv.consume(0);
    try std.testing.expectEqualStrings("hello world", recv.available());
    try recv.consume("hello world".len);
    try std.testing.expect(recv.complete());
    try std.testing.expect(recv.received.materializedCapacity() != 0);
}

test "QUIC ordered receive stream keeps an implicit dense prefix" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 64);
    defer recv.deinit();
    try recv.buffer.ensureTotalCapacity(allocator, 16);

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    recv.allocator = no_alloc.allocator();
    try std.testing.expectEqual(
        @as(u64, 8),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 0,
            .data = "abcdefgh",
        }),
    );
    try std.testing.expectEqual(
        @as(u64, 8),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 8,
            .data = "ijklmnop",
            .fin = true,
        }),
    );
    recv.allocator = allocator;

    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), recv.received.materializedCapacity());
    try std.testing.expectEqual(@as(usize, 16), recv.received.len());
    try std.testing.expectEqualStrings("abcdefghijklmnop", recv.available());
}

test "QUIC receive stream materializes bitmap only for a gap" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 64);
    defer recv.deinit();

    try recv.insert(.{ .stream_id = 0, .offset = 0, .data = "abcd" });
    try std.testing.expectEqual(@as(usize, 0), recv.received.materializedCapacity());
    try recv.insert(.{ .stream_id = 0, .offset = 8, .data = "ijkl" });
    try std.testing.expect(recv.received.materializedCapacity() != 0);
    try std.testing.expect(recv.received.isSet(0));
    try std.testing.expect(!recv.received.isSet(4));
    try std.testing.expect(recv.received.isSet(8));
}

test "QUIC receive stream keeps dense state after bitmap materialization failure" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 64);
    defer recv.deinit();
    try recv.buffer.ensureTotalCapacity(allocator, 16);
    try recv.insert(.{ .stream_id = 0, .offset = 0, .data = "abcd" });

    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    recv.allocator = fail.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        recv.insert(.{ .stream_id = 0, .offset = 8, .data = "ijkl" }),
    );
    recv.allocator = allocator;

    try std.testing.expect(fail.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), recv.received.materializedCapacity());
    try std.testing.expectEqual(@as(usize, 4), recv.received.len());
    try std.testing.expectEqual(@as(u64, 4), recv.receivedByteCount());
    try std.testing.expectEqualStrings("abcd", recv.available());
    try std.testing.expect(recv.final_size == null);

    try recv.insert(.{ .stream_id = 0, .offset = 8, .data = "ijkl" });
    try std.testing.expect(recv.received.materializedCapacity() != 0);
}

test "QUIC dense receive bitmap clone and compaction stay implicit" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 64);
    defer recv.deinit();
    try recv.insert(.{
        .stream_id = 0,
        .offset = 0,
        .data = "abcdefghijklmnop",
    });

    var cloned = try recv.clone(allocator);
    defer cloned.deinit();
    try std.testing.expectEqual(@as(usize, 0), cloned.received.materializedCapacity());
    try cloned.consume(16);
    try std.testing.expectEqual(@as(usize, 0), cloned.received.materializedCapacity());
    try std.testing.expectEqual(@as(usize, 0), cloned.received.len());
}

test "QUIC receive stream transfers complete buffer ownership" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 1024);
    defer recv.deinit();

    try std.testing.expectError(
        error.NothingAvailable,
        recv.takeCompleteBuffer(),
    );
    try recv.insert(.{
        .stream_id = 0,
        .offset = 6,
        .data = "world",
        .fin = true,
    });
    try std.testing.expectError(
        error.NothingAvailable,
        recv.takeCompleteBuffer(),
    );
    try recv.insert(.{
        .stream_id = 0,
        .offset = 0,
        .data = "hello ",
    });
    const bytes = try recv.takeCompleteBuffer();
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("hello world", bytes);
    try std.testing.expectEqual(@as(usize, 0), recv.buffer.items.len);
    try std.testing.expectEqual(@as(usize, 0), recv.received.len());

    try recv.insert(.{
        .stream_id = 0,
        .offset = 0,
        .data = "reused",
        .fin = true,
    });
    try std.testing.expectEqualStrings("reused", recv.available());
}

test "QUIC receive stream rejects inconsistent final size" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 4, 1024);
    defer recv.deinit();
    try recv.insert(.{ .stream_id = 4, .offset = 0, .data = "abc", .fin = true });
    try std.testing.expectError(error.FinalSizeMismatch, recv.insert(.{ .stream_id = 4, .offset = 3, .data = "d", .fin = false }));
}

test "QUIC receive stream rejects conflicting duplicate bytes" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 1024);
    defer recv.deinit();

    try recv.insert(.{ .stream_id = 0, .offset = 0, .data = "abcdef", .fin = false });
    // Identical overlap can be a benign retransmission and must not duplicate
    // bytes or regress contiguous availability.
    try std.testing.expectEqual(
        @as(u64, 0),
        try recv.insertTracked(.{ .stream_id = 0, .offset = 2, .data = "cde", .fin = false }),
    );
    try std.testing.expectEqualStrings("abcdef", recv.available());

    try std.testing.expectError(error.ConflictingStreamData, recv.insert(.{
        .stream_id = 0,
        .offset = 3,
        .data = "XYZ",
        .fin = false,
    }));
    try std.testing.expectEqualStrings("abcdef", recv.available());
}

test "QUIC receive stream keeps final size transactional on conflict" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 1024);
    defer recv.deinit();

    try recv.insert(.{ .stream_id = 0, .offset = 0, .data = "abc", .fin = false });
    try std.testing.expect(recv.final_size == null);
    try std.testing.expectError(error.ConflictingStreamData, recv.insert(.{
        .stream_id = 0,
        .offset = 1,
        .data = "Z",
        .fin = true,
    }));
    try std.testing.expect(recv.final_size == null);

    try recv.insert(.{ .stream_id = 0, .offset = 3, .data = &.{}, .fin = true });
    try std.testing.expectEqual(@as(?usize, 3), recv.final_size);
}

test "QUIC receive stream slides consumed storage across large offsets" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 16);
    defer recv.deinit();

    try recv.insert(.{
        .stream_id = 0,
        .offset = 0,
        .data = "abcdefgh",
    });
    try std.testing.expectEqualStrings("abcdefgh", recv.available());
    try recv.consume(8);
    try std.testing.expectEqual(@as(usize, 8), recv.storage_offset);
    try std.testing.expectEqual(@as(usize, 0), recv.buffer.items.len);

    // Absolute offset exceeds max_buffered, but the live retained window does
    // not. This is the key invariant needed by streaming protocol parsers.
    try recv.insert(.{
        .stream_id = 0,
        .offset = 8,
        .data = "ijklmnop",
    });
    try std.testing.expectEqualStrings("ijklmnop", recv.available());
    try recv.consume(8);
    try recv.insert(.{
        .stream_id = 0,
        .offset = 16,
        .data = "qrstuvwx",
        .fin = true,
    });
    try std.testing.expectEqualStrings("qrstuvwx", recv.available());
    try std.testing.expectEqual(@as(?usize, 24), recv.final_size);
    try recv.consume(8);
    try std.testing.expect(recv.complete());
    try std.testing.expectEqual(@as(u64, 24), recv.receivedByteCount());

    // Fully-consumed retransmissions do not regrow storage or double-count
    // flow-control bytes.
    try std.testing.expectEqual(
        @as(u64, 0),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 0,
            .data = "abcdefgh",
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), recv.buffer.items.len);
    try std.testing.expectEqual(@as(u64, 24), recv.receivedByteCount());
}

test "QUIC receive stream compacts non-word-aligned bitmap with sparse tail" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 128);
    defer recv.deinit();

    try std.testing.expectEqual(
        @as(u64, 4),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 70,
            .data = "tail",
            .fin = true,
        }),
    );
    try std.testing.expectEqual(
        @as(u64, 40),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 0,
            .data = &([_]u8{'a'} ** 40),
        }),
    );
    try std.testing.expectEqual(@as(usize, 40), recv.available().len);
    try recv.consume(40);
    try std.testing.expectEqual(@as(usize, 40), recv.storage_offset);
    try std.testing.expectEqual(@as(usize, 34), recv.buffer.items.len);

    try std.testing.expectEqual(
        @as(u64, 30),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 40,
            .data = &([_]u8{'b'} ** 30),
        }),
    );
    try std.testing.expectEqual(@as(usize, 34), recv.available().len);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{'b'} ** 30),
        recv.available()[0..30],
    );
    try std.testing.expectEqualStrings("tail", recv.available()[30..]);
    try std.testing.expectEqual(
        @as(u64, 0),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 70,
            .data = "tail",
            .fin = true,
        }),
    );
    try std.testing.expectEqual(@as(u64, 74), recv.receivedByteCount());
    try recv.consume(34);
    try std.testing.expect(recv.complete());
}

test "QUIC receive stream compacts a retained consumed prefix at its window edge" {
    const allocator = std.testing.allocator;

    var direct = RecvState.init(allocator, 0, 16);
    defer direct.deinit();
    try direct.insert(.{
        .stream_id = 0,
        .offset = 0,
        .data = "abcdefghijkl",
    });
    try direct.consume(5);
    // Five bytes is below both compaction thresholds, so storage still starts
    // at zero even though the application cursor has advanced. The new frame
    // spans only fifteen unread bytes and must fit the sixteen-byte window.
    try std.testing.expectEqual(@as(usize, 0), direct.storage_offset);
    try std.testing.expectEqual(@as(usize, 5), direct.read_offset);
    try std.testing.expectEqual(@as(u64, 0), try direct.insertTracked(.{
        .stream_id = 0,
        .offset = 3,
        .data = "XXfgh",
    }));
    try direct.insert(.{
        .stream_id = 0,
        .offset = 12,
        .data = "mnopqrst",
    });
    try std.testing.expectEqual(@as(usize, 5), direct.storage_offset);
    try std.testing.expectEqualStrings("fghijklmnopqrst", direct.available());
    try std.testing.expectError(error.StreamBufferTooLarge, direct.insert(.{
        .stream_id = 0,
        .offset = 20,
        .data = "uv",
    }));

    var validated = RecvState.init(allocator, 4, 16);
    defer validated.deinit();
    try validated.insert(.{
        .stream_id = 4,
        .offset = 0,
        .data = "abcdefghijkl",
    });
    try validated.consume(5);
    var pending_storage: [2]quic.StreamFrame = undefined;
    var pending = RecvState.PreflightFrames.init(allocator, &pending_storage);
    defer pending.deinit();
    var preflight = RecvState.Preflight.init(&validated, &pending);
    defer preflight.deinit();
    try std.testing.expectEqual(@as(u64, 8), try preflight.insertTracked(.{
        .stream_id = 4,
        .offset = 12,
        .data = "mnopqrst",
    }));
    try std.testing.expectError(
        error.StreamBufferTooLarge,
        preflight.insertTracked(.{
            .stream_id = 4,
            .offset = 20,
            .data = "uv",
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), validated.storage_offset);
    try std.testing.expectEqualStrings("fghijkl", validated.available());
}

test "QUIC receive stream clips overlap at sliding window boundary" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 16);
    defer recv.deinit();
    try recv.insert(.{
        .stream_id = 0,
        .offset = 0,
        .data = "abcdefgh",
    });
    try recv.consume(8);

    try std.testing.expectEqual(
        @as(u64, 4),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 4,
            .data = "efghijkl",
        }),
    );
    try std.testing.expectEqualStrings("ijkl", recv.available());
    try std.testing.expectEqual(@as(u64, 12), recv.receivedByteCount());
}

test "QUIC receive stream preflight validates without copying retained body" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 32);
    defer recv.deinit();
    try recv.insert(.{
        .stream_id = 0,
        .offset = 0,
        .data = "abcdefgh",
    });
    try recv.consume(4);

    var pending_storage: [4]quic.StreamFrame = undefined;
    var pending = RecvState.PreflightFrames.init(allocator, &pending_storage);
    defer pending.deinit();
    var preflight = RecvState.Preflight.init(&recv, &pending);
    defer preflight.deinit();
    try std.testing.expectEqual(
        @intFromPtr(recv.buffer.items.ptr),
        @intFromPtr(preflight.buffer.ptr),
    );
    try std.testing.expectEqual(@as(u64, 4), try preflight.insertTracked(.{
        .stream_id = 0,
        .offset = 4,
        .data = "efghijkl",
    }));
    try std.testing.expectEqual(@as(u64, 12), preflight.receivedByteCount());
    // Validation never mutates the borrowed receive state.
    try std.testing.expectEqualStrings("efgh", recv.available());
    try std.testing.expectEqual(@as(u64, 8), recv.receivedByteCount());
}

test "QUIC receive stream preflight checks packet-local overlap and FIN" {
    const allocator = std.testing.allocator;
    var pending_storage: [4]quic.StreamFrame = undefined;
    var pending = RecvState.PreflightFrames.init(allocator, &pending_storage);
    defer pending.deinit();
    var preflight = RecvState.Preflight.initEmpty(
        allocator,
        4,
        32,
        &pending,
    );
    defer preflight.deinit();

    try std.testing.expectEqual(@as(u64, 6), try preflight.insertTracked(.{
        .stream_id = 4,
        .offset = 0,
        .data = "abcdef",
    }));
    try std.testing.expectEqual(@as(u64, 2), try preflight.insertTracked(.{
        .stream_id = 4,
        .offset = 4,
        .data = "efgh",
        .fin = true,
    }));
    try std.testing.expectEqual(@as(?usize, 8), preflight.final_size);
    try std.testing.expectEqual(@as(u64, 8), preflight.receivedByteCount());

    try std.testing.expectEqual(@as(u64, 0), try preflight.insertTracked(.{
        .stream_id = 4,
        .offset = 2,
        .data = "cdef",
    }));
    try std.testing.expectError(
        error.ConflictingStreamData,
        preflight.insertTracked(.{
            .stream_id = 4,
            .offset = 3,
            .data = "XYZ",
        }),
    );
    try std.testing.expectError(
        error.FinalSizeMismatch,
        preflight.insertTracked(.{
            .stream_id = 4,
            .offset = 8,
            .data = "i",
        }),
    );
}

test "QUIC receive stream preflight fast path counts adjacent frames" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 64);
    defer recv.deinit();
    try recv.insert(.{ .stream_id = 0, .offset = 0, .data = "abcd" });

    var pending_storage: [4]quic.StreamFrame = undefined;
    var pending = RecvState.PreflightFrames.init(allocator, &pending_storage);
    defer pending.deinit();
    var preflight = RecvState.Preflight.init(&recv, &pending);
    defer preflight.deinit();

    try std.testing.expectEqual(@as(u64, 4), try preflight.insertTracked(.{
        .stream_id = 0,
        .offset = 4,
        .data = "efgh",
    }));
    try std.testing.expectEqual(@as(u64, 4), try preflight.insertTracked(.{
        .stream_id = 0,
        .offset = 8,
        .data = "ijkl",
        .fin = true,
    }));
    try std.testing.expectEqual(@as(u64, 12), preflight.receivedByteCount());
    try std.testing.expectEqual(@as(?usize, 12), preflight.final_size);
    try std.testing.expectEqual(@as(usize, 2), pending.items().len);
}

test "QUIC receive preflight frames use caller storage and spill safely" {
    const allocator = std.testing.allocator;
    var stack: [1]quic.StreamFrame = undefined;
    var frames = RecvState.PreflightFrames.init(allocator, &stack);
    defer frames.deinit();
    try frames.append(.{ .stream_id = 0, .data = "a" });
    try std.testing.expect(!frames.allocated);
    try std.testing.expectEqual(@intFromPtr(&stack), @intFromPtr(frames.storage.ptr));

    try frames.append(.{ .stream_id = 4, .data = "b" });
    try std.testing.expect(frames.allocated);
    try std.testing.expectEqual(@as(usize, 2), frames.items().len);
    try std.testing.expectEqualStrings("a", frames.items()[0].data);
    try std.testing.expectEqualStrings("b", frames.items()[1].data);
}

test "QUIC receive preflight shares packet frames across stream shadows" {
    const allocator = std.testing.allocator;
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var pending_storage: [4]quic.StreamFrame = undefined;
    var pending = RecvState.PreflightFrames.init(
        no_alloc.allocator(),
        &pending_storage,
    );
    defer pending.deinit();
    var first = RecvState.Preflight.initEmpty(
        no_alloc.allocator(),
        0,
        32,
        &pending,
    );
    var second = RecvState.Preflight.initEmpty(
        no_alloc.allocator(),
        4,
        32,
        &pending,
    );

    try std.testing.expectEqual(@as(u64, 2), try first.insertTracked(.{
        .stream_id = 0,
        .offset = 0,
        .data = "ab",
    }));
    try std.testing.expectEqual(@as(u64, 2), try second.insertTracked(.{
        .stream_id = 4,
        .offset = 0,
        .data = "xy",
    }));
    try std.testing.expectEqual(@as(u64, 2), try first.insertTracked(.{
        .stream_id = 0,
        .offset = 2,
        .data = "cd",
    }));
    try std.testing.expectEqual(@as(usize, 3), pending.items().len);
    try std.testing.expectEqual(@as(usize, 0), no_alloc.alloc_index);
}

test "QUIC receive stream advances through sparse tail after gap fill" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 24);
    defer recv.deinit();

    try std.testing.expectEqual(
        @as(u64, 4),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 8,
            .data = "ijkl",
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), recv.available().len);

    try std.testing.expectEqual(
        @as(u64, 4),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 16,
            .data = "qrst",
            .fin = true,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), recv.available().len);

    try std.testing.expectEqual(
        @as(u64, 8),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 0,
            .data = "abcdefgh",
        }),
    );
    try std.testing.expectEqualStrings("abcdefghijkl", recv.available());
    try recv.consume(12);

    try std.testing.expectEqual(
        @as(u64, 4),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 12,
            .data = "mnop",
        }),
    );
    try std.testing.expectEqualStrings("mnopqrst", recv.available());
    try std.testing.expectEqual(@as(u64, 20), recv.receivedByteCount());

    try std.testing.expectEqual(
        @as(u64, 0),
        try recv.insertTracked(.{
            .stream_id = 0,
            .offset = 16,
            .data = "qrst",
            .fin = true,
        }),
    );
    try std.testing.expectEqual(@as(u64, 20), recv.receivedByteCount());
}
