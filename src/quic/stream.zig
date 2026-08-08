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
        if (max_frame_data_len == 0) return error.InvalidStreamRange;
        if (data.len == 0 and fin) {
            try (quic.Frame{ .stream = .{ .stream_id = self.stream_id, .offset = self.next_offset, .data = &.{}, .fin = true } }).write(list, allocator);
            self.fin_sent = true;
            return;
        }

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
        if (max_frame_data_len == 0) return error.InvalidStreamRange;
        if (data.len == 0 and fin) {
            try list.append(allocator, .{ .stream = .{ .stream_id = self.stream_id, .offset = self.next_offset, .data = &.{}, .fin = true } });
            self.fin_sent = true;
            return;
        }

        var written: usize = 0;
        while (written < data.len) {
            const chunk_len = @min(max_frame_data_len, data.len - written);
            const is_last = written + chunk_len == data.len;
            try list.append(allocator, .{ .stream = .{
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
};

pub const RecvState = struct {
    allocator: std.mem.Allocator,
    stream_id: u64,
    buffer: std.ArrayList(u8) = .empty,
    received: std.ArrayList(bool) = .empty,
    read_offset: usize = 0,
    contiguous_end: usize = 0,
    final_size: ?usize = null,
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
        copy.read_offset = self.read_offset;
        copy.contiguous_end = self.contiguous_end;
        copy.final_size = self.final_size;
        return copy;
    }

    pub fn insert(self: *RecvState, frame: quic.StreamFrame) Error!void {
        _ = try self.insertTracked(frame);
    }

    pub fn insertTracked(self: *RecvState, frame: quic.StreamFrame) Error!u64 {
        if (frame.stream_id != self.stream_id) return error.WrongStream;
        const offset = std.math.cast(usize, frame.offset) orelse return error.InvalidStreamRange;
        const end = std.math.add(usize, offset, frame.data.len) catch return error.InvalidStreamRange;
        if (end > self.max_buffered) return error.StreamBufferTooLarge;
        if (self.final_size) |final_size| {
            if (end > final_size) return error.FinalSizeMismatch;
            if (frame.fin and end != final_size) return error.FinalSizeMismatch;
        }

        var newly_received: u64 = 0;
        for (frame.data, 0..) |byte, i| {
            const absolute = offset + i;
            if (absolute < self.received.items.len and self.received.items[absolute]) {
                if (self.buffer.items[absolute] != byte) return error.ConflictingStreamData;
            } else {
                newly_received += 1;
            }
        }

        if (end > self.buffer.items.len) {
            const old_len = self.buffer.items.len;
            try self.buffer.resize(self.allocator, end);
            @memset(self.buffer.items[old_len..end], 0);
            try self.received.resize(self.allocator, end);
            @memset(self.received.items[old_len..end], false);
        }
        @memcpy(self.buffer.items[offset..end], frame.data);
        @memset(self.received.items[offset..end], true);
        while (self.contiguous_end < self.received.items.len and self.received.items[self.contiguous_end]) {
            self.contiguous_end += 1;
        }
        if (frame.fin) self.final_size = end;
        return newly_received;
    }

    pub fn receivedByteCount(self: RecvState) u64 {
        var count: u64 = 0;
        for (self.received.items) |received| {
            if (received) count += 1;
        }
        return count;
    }

    pub fn available(self: RecvState) []const u8 {
        return self.buffer.items[self.read_offset..self.contiguous_end];
    }

    pub fn consume(self: *RecvState, len: usize) Error!void {
        if (len > self.available().len) return error.NothingAvailable;
        self.read_offset += len;
    }

    pub fn complete(self: RecvState) bool {
        const final_size = self.final_size orelse return false;
        return self.contiguous_end >= final_size and self.read_offset >= final_size;
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

test "QUIC receive stream state reassembles out of order and tracks FIN" {
    const allocator = std.testing.allocator;
    var recv = RecvState.init(allocator, 0, 1024);
    defer recv.deinit();

    try recv.insert(.{ .stream_id = 0, .offset = 6, .data = "world", .fin = true });
    try std.testing.expectEqual(@as(usize, 0), recv.available().len);
    try recv.insert(.{ .stream_id = 0, .offset = 0, .data = "hello ", .fin = false });
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
    try recv.insert(.{ .stream_id = 0, .offset = 2, .data = "cde", .fin = false });
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
