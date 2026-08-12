const std = @import("std");
const quic = @import("mod.zig");

pub const Error = error{
    WrongStream,
    InvalidStreamRange,
    FinalSizeMismatch,
    StreamBufferTooLarge,
    ConflictingStreamData,
    NothingAvailable,
} || quic.Error || std.mem.Allocator.Error;

pub const SendState = struct {
    stream_id: u64,
    next_offset: u64 = 0,
    fin_sent: bool = false,

    pub fn init(stream_id: u64) SendState {
        return .{ .stream_id = stream_id };
    }

    pub fn writeFrames(
        self: *SendState,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        data: []const u8,
        max_frame_data_len: usize,
        fin: bool,
    ) Error!void {
        if (self.fin_sent) return error.FinalSizeMismatch;
        if (data.len == 0 and !fin) return;
        if (max_frame_data_len == 0) return error.InvalidStreamRange;
        if (data.len == 0 and fin) {
            try (quic.Frame{ .stream = .{ .stream_id = self.stream_id, .offset = self.next_offset, .data = &.{}, .fin = true } }).write(list, allocator);
            self.fin_sent = true;
            return;
        }

        try list.ensureUnusedCapacity(allocator, try self.encodedFramesWireLen(data, max_frame_data_len, fin));
        var written: usize = 0;
        while (written < data.len) {
            const chunk_len = @min(max_frame_data_len, data.len - written);
            const is_last = written + chunk_len == data.len;
            try (quic.Frame{ .stream = .{
                .stream_id = self.stream_id,
                .offset = self.next_offset,
                .data = data[written .. written + chunk_len],
                .fin = fin and is_last,
            } }).write(list, allocator);
            self.next_offset += chunk_len;
            written += chunk_len;
        }
        if (fin) self.fin_sent = true;
    }

    pub fn appendFrames(
        self: *SendState,
        list: *std.ArrayList(quic.Frame),
        allocator: std.mem.Allocator,
        data: []const u8,
        max_frame_data_len: usize,
        fin: bool,
    ) Error!void {
        if (self.fin_sent) return error.FinalSizeMismatch;
        if (data.len == 0 and !fin) return;
        if (max_frame_data_len == 0) return error.InvalidStreamRange;
        if (data.len == 0 and fin) {
            try list.ensureUnusedCapacity(allocator, 1);
            list.appendAssumeCapacity(.{ .stream = .{ .stream_id = self.stream_id, .offset = self.next_offset, .data = &.{}, .fin = true } });
            self.fin_sent = true;
            return;
        }

        try list.ensureUnusedCapacity(allocator, frameCount(data.len, max_frame_data_len));
        var written: usize = 0;
        while (written < data.len) {
            const chunk_len = @min(max_frame_data_len, data.len - written);
            const is_last = written + chunk_len == data.len;
            list.appendAssumeCapacity(.{ .stream = .{
                .stream_id = self.stream_id,
                .offset = self.next_offset,
                .data = data[written .. written + chunk_len],
                .fin = fin and is_last,
            } });
            self.next_offset += chunk_len;
            written += chunk_len;
        }
        if (fin) self.fin_sent = true;
    }

    fn encodedFramesWireLen(self: SendState, data: []const u8, max_frame_data_len: usize, fin: bool) Error!usize {
        var len: usize = 0;
        var offset = self.next_offset;
        var written: usize = 0;
        while (written < data.len) {
            const chunk_len = @min(max_frame_data_len, data.len - written);
            const is_last = written + chunk_len == data.len;
            const frame_len = try (quic.Frame{ .stream = .{
                .stream_id = self.stream_id,
                .offset = offset,
                .data = data[written .. written + chunk_len],
                .fin = fin and is_last,
            } }).wireLen();
            len = std.math.add(usize, len, frame_len) catch return error.InvalidFrameLength;
            offset += chunk_len;
            written += chunk_len;
        }
        return len;
    }

    fn frameCount(data_len: usize, max_frame_data_len: usize) usize {
        return std.math.divCeil(usize, data_len, max_frame_data_len) catch unreachable;
    }
};

pub const RecvState = struct {
    allocator: std.mem.Allocator,
    stream_id: u64,
    /// Absolute stream offset represented by buffer[0].
    storage_offset: usize = 0,
    buffer: std.ArrayList(u8) = .empty,
    received: std.ArrayList(bool) = .empty,
    /// Absolute application read offset.
    read_offset: usize = 0,
    /// Absolute first not-yet-contiguous stream offset.
    contiguous_end: usize = 0,
    final_size: ?usize = null,
    received_total: u64 = 0,
    highest_received_end: usize = 0,
    max_buffered: usize,

    pub fn init(allocator: std.mem.Allocator, stream_id: u64, max_buffered: usize) RecvState {
        return .{ .allocator = allocator, .stream_id = stream_id, .max_buffered = max_buffered };
    }

    pub fn deinit(self: *RecvState) void {
        self.buffer.deinit(self.allocator);
        self.received.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn clone(self: RecvState, allocator: std.mem.Allocator) Error!RecvState {
        var copy = RecvState.init(allocator, self.stream_id, self.max_buffered);
        errdefer copy.deinit();
        try copy.buffer.appendSlice(allocator, self.buffer.items);
        try copy.received.appendSlice(allocator, self.received.items);
        copy.storage_offset = self.storage_offset;
        copy.read_offset = self.read_offset;
        copy.contiguous_end = self.contiguous_end;
        copy.final_size = self.final_size;
        copy.received_total = self.received_total;
        copy.highest_received_end = self.highest_received_end;
        return copy;
    }

    pub fn insert(self: *RecvState, frame: quic.StreamFrame) Error!void {
        _ = try self.insertTracked(frame);
    }

    pub fn insertTracked(self: *RecvState, frame: quic.StreamFrame) Error!u64 {
        if (frame.stream_id != self.stream_id) return error.WrongStream;
        const absolute_offset = std.math.cast(usize, frame.offset) orelse return error.InvalidStreamRange;
        const absolute_end = std.math.add(usize, absolute_offset, frame.data.len) catch return error.InvalidStreamRange;
        if (self.final_size) |final_size| {
            if (absolute_end > final_size) return error.FinalSizeMismatch;
            if (frame.fin and absolute_end != final_size) return error.FinalSizeMismatch;
        }
        // Bytes below storage_offset were already delivered. QUIC permits
        // retransmitting them; ignore that prefix without growing the window.
        if (absolute_end <= self.storage_offset) {
            if (frame.fin and absolute_end < self.highest_received_end) {
                return error.FinalSizeMismatch;
            }
            if (frame.fin) self.final_size = absolute_end;
            return 0;
        }
        const retained_offset = @max(absolute_offset, self.storage_offset);
        const skipped = retained_offset - absolute_offset;
        const data = frame.data[skipped..];
        const relative_offset = retained_offset - self.storage_offset;
        const relative_end = std.math.add(usize, relative_offset, data.len) catch
            return error.InvalidStreamRange;
        if (relative_end > self.max_buffered) return error.StreamBufferTooLarge;

        const old_len = self.received.items.len;
        if (relative_end <= old_len and absolute_end <= self.contiguous_end) {
            if (!std.mem.eql(u8, self.buffer.items[relative_offset..relative_end], data)) {
                return error.ConflictingStreamData;
            }
            if (frame.fin and absolute_end < self.highest_received_end) {
                return error.FinalSizeMismatch;
            }
            if (frame.fin) self.final_size = absolute_end;
            return 0;
        }
        var newly_received: u64 = 0;
        if (relative_offset >= old_len) {
            newly_received = data.len;
        } else {
            const overlap_end = @min(relative_end, old_len);
            var relative = relative_offset;
            while (relative < overlap_end) : (relative += 1) {
                if (self.received.items[relative]) {
                    const data_index = relative - relative_offset;
                    if (self.buffer.items[relative] != data[data_index]) {
                        return error.ConflictingStreamData;
                    }
                } else {
                    newly_received += 1;
                }
            }
            if (relative_end > old_len) newly_received += relative_end - old_len;
        }
        // Preserve the existing conflict-first error classification when a
        // FIN both overlaps inconsistent buffered bytes and shrinks the known
        // stream extent. Neither final_size nor storage mutates on failure.
        if (frame.fin and absolute_end < self.highest_received_end) {
            return error.FinalSizeMismatch;
        }

        if (relative_end > self.buffer.items.len) {
            try self.buffer.resize(self.allocator, relative_end);
            try self.received.resize(self.allocator, relative_end);
            if (relative_offset > old_len) {
                @memset(self.buffer.items[old_len..relative_offset], 0);
                @memset(self.received.items[old_len..relative_offset], false);
            }
        }
        @memcpy(self.buffer.items[relative_offset..relative_end], data);
        @memset(self.received.items[relative_offset..relative_end], true);
        var contiguous_relative = self.contiguous_end - self.storage_offset;
        if (relative_offset <= contiguous_relative and contiguous_relative < relative_end) {
            self.contiguous_end = self.storage_offset + relative_end;
            contiguous_relative = relative_end;
        }
        while (contiguous_relative < self.received.items.len and
            self.received.items[contiguous_relative])
        {
            contiguous_relative += 1;
            self.contiguous_end += 1;
        }
        self.highest_received_end = @max(
            self.highest_received_end,
            absolute_end,
        );
        self.received_total = std.math.add(
            u64,
            self.received_total,
            newly_received,
        ) catch std.math.maxInt(u64);
        if (frame.fin) self.final_size = absolute_end;
        return newly_received;
    }

    pub fn receivedByteCount(self: RecvState) u64 {
        return self.received_total;
    }

    pub fn available(self: RecvState) []const u8 {
        const relative_start = self.read_offset - self.storage_offset;
        const relative_end = self.contiguous_end - self.storage_offset;
        return self.buffer.items[relative_start..relative_end];
    }

    pub fn consume(self: *RecvState, len: usize) Error!void {
        if (len == 0) return;
        if (len > self.available().len) return error.NothingAvailable;
        self.read_offset += len;
        self.compactConsumedPrefix();
    }

    pub fn complete(self: RecvState) bool {
        const final_size = self.final_size orelse return false;
        return self.contiguous_end >= final_size and self.read_offset >= final_size;
    }

    fn compactConsumedPrefix(self: *RecvState) void {
        const consumed = self.read_offset - self.storage_offset;
        if (consumed == 0) return;
        // Avoid memmove on tiny reads, but never retain more than max_buffered
        // behind the application cursor.
        if (consumed < self.buffer.items.len / 2 and
            consumed < self.max_buffered / 2)
        {
            return;
        }
        const remaining = self.buffer.items.len - consumed;
        @memmove(
            self.buffer.items[0..remaining],
            self.buffer.items[consumed..],
        );
        @memmove(
            self.received.items[0..remaining],
            self.received.items[consumed..],
        );
        self.buffer.items.len = remaining;
        self.received.items.len = remaining;
        self.storage_offset = self.read_offset;
    }
};

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
