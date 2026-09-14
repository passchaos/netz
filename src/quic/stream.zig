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

const ReceivedBitmap = struct {
    const Word = usize;
    const word_bits = @bitSizeOf(Word);
    const Shift = std.math.Log2Int(Word);

    words: std.ArrayList(Word) = .empty,
    bit_len: usize = 0,

    const View = struct {
        words: []const Word = &.{},
        bit_len: usize = 0,

        fn isSet(self: View, index: usize) bool {
            std.debug.assert(index < self.bit_len);
            return (self.words[wordIndex(index)] & bitMask(index)) != 0;
        }

        fn anySetInRange(
            self: View,
            range: std.bit_set.Range,
        ) bool {
            std.debug.assert(range.start <= range.end);
            std.debug.assert(range.end <= self.bit_len);
            if (range.start == range.end) return false;

            const first_word = wordIndex(range.start);
            const last_word = wordIndex(range.end - 1);
            const start_bit: Shift = @truncate(range.start);
            const start_mask = @as(Word, std.math.maxInt(Word)) << start_bit;
            const end_bit: Shift = @truncate(range.end);
            const end_mask = if (end_bit == 0)
                std.math.maxInt(Word)
            else
                (@as(Word, 1) << end_bit) - 1;

            if (first_word == last_word) {
                return (self.words[first_word] & start_mask & end_mask) != 0;
            }
            if ((self.words[first_word] & start_mask) != 0) return true;
            for (self.words[first_word + 1 .. last_word]) |word| {
                if (word != 0) return true;
            }
            return (self.words[last_word] & end_mask) != 0;
        }
    };

    fn deinit(self: *ReceivedBitmap, allocator: std.mem.Allocator) void {
        self.words.deinit(allocator);
        self.* = undefined;
    }

    fn clone(
        self: ReceivedBitmap,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!ReceivedBitmap {
        var copy: ReceivedBitmap = .{};
        try copy.words.ensureUnusedCapacity(allocator, self.words.items.len);
        copy.words.appendSliceAssumeCapacity(self.words.items);
        copy.bit_len = self.bit_len;
        return copy;
    }

    fn len(self: ReceivedBitmap) usize {
        return self.bit_len;
    }

    fn view(self: ReceivedBitmap) View {
        return .{ .words = self.words.items, .bit_len = self.bit_len };
    }

    fn resize(
        self: *ReceivedBitmap,
        allocator: std.mem.Allocator,
        new_len: usize,
        fill: bool,
    ) std.mem.Allocator.Error!void {
        const old_len = self.bit_len;
        const old_word_len = self.words.items.len;
        const new_word_len = wordCount(new_len);
        if (new_word_len > old_word_len) {
            try self.words.resize(allocator, new_word_len);
            @memset(
                self.words.items[old_word_len..],
                std.math.boolMask(Word, fill),
            );
        } else {
            self.words.items.len = new_word_len;
        }
        self.bit_len = new_len;
        if (new_len > old_len) {
            const old_word_end = @min(
                new_len,
                old_word_len * word_bits,
            );
            if (old_len < old_word_end) {
                self.setRangeValue(
                    .{ .start = old_len, .end = old_word_end },
                    fill,
                );
            }
        }
        self.clearPadding();
    }

    fn isSet(self: ReceivedBitmap, index: usize) bool {
        return self.view().isSet(index);
    }

    fn anySetInRange(
        self: ReceivedBitmap,
        range: std.bit_set.Range,
    ) bool {
        return self.view().anySetInRange(range);
    }

    fn setRangeValue(
        self: *ReceivedBitmap,
        range: std.bit_set.Range,
        value: bool,
    ) void {
        std.debug.assert(range.end <= self.bit_len);
        std.debug.assert(range.start <= range.end);
        if (range.start == range.end) return;

        const start_word = wordIndex(range.start);
        const start_bit: Shift = @truncate(range.start);
        const end_word = wordIndex(range.end);
        const end_bit: Shift = @truncate(range.end);
        const fill_word = std.math.boolMask(Word, value);

        if (start_word == end_word) {
            const low = @as(Word, std.math.maxInt(Word)) << start_bit;
            const high = @as(Word, std.math.maxInt(Word)) >>
                ((word_bits - 1) - (end_bit - 1));
            const mask = low & high;
            self.words.items[start_word] =
                (self.words.items[start_word] & ~mask) |
                (fill_word & mask);
            return;
        }

        var current = start_word;
        if (start_bit != 0) {
            const mask = @as(Word, std.math.maxInt(Word)) << start_bit;
            self.words.items[current] =
                (self.words.items[current] & ~mask) |
                (fill_word & mask);
            current += 1;
        }
        @memset(self.words.items[current..end_word], fill_word);
        if (end_bit != 0) {
            const mask = @as(Word, std.math.maxInt(Word)) >>
                ((word_bits - 1) - (end_bit - 1));
            self.words.items[end_word] =
                (self.words.items[end_word] & ~mask) |
                (fill_word & mask);
        }
    }

    fn firstUnsetFrom(self: ReceivedBitmap, start: usize) usize {
        std.debug.assert(start <= self.bit_len);
        if (start == self.bit_len) return start;

        var word_index = wordIndex(start);
        var word = self.words.items[word_index];
        const start_bit: Shift = @truncate(start);
        if (start_bit != 0) {
            word |= (@as(Word, 1) << start_bit) - 1;
        }
        while (true) {
            const unset = ~word;
            if (unset != 0) {
                const candidate = word_index * word_bits + @ctz(unset);
                return @min(candidate, self.bit_len);
            }
            word_index += 1;
            if (word_index == self.words.items.len) return self.bit_len;
            word = self.words.items[word_index];
        }
    }

    fn removePrefix(self: *ReceivedBitmap, prefix_len: usize) void {
        std.debug.assert(prefix_len <= self.bit_len);
        const remaining = self.bit_len - prefix_len;
        if (remaining == 0) {
            self.words.items.len = 0;
            self.bit_len = 0;
            return;
        }

        const word_shift = prefix_len / word_bits;
        const bit_shift: Shift = @truncate(prefix_len);
        const old_word_len = self.words.items.len;
        const new_word_len = wordCount(remaining);
        for (0..new_word_len) |destination| {
            const source = destination + word_shift;
            var word = self.words.items[source] >> bit_shift;
            if (bit_shift != 0 and source + 1 < old_word_len) {
                const inverse_shift: Shift = @intCast(
                    word_bits - @as(usize, bit_shift),
                );
                word |= self.words.items[source + 1] <<
                    inverse_shift;
            }
            self.words.items[destination] = word;
        }
        self.words.items.len = new_word_len;
        self.bit_len = remaining;
        self.clearPadding();
    }

    fn clearPadding(self: *ReceivedBitmap) void {
        if (self.bit_len == 0) return;
        const used_bits = self.bit_len % word_bits;
        if (used_bits == 0) return;
        self.words.items[self.words.items.len - 1] &=
            (@as(Word, 1) << @as(Shift, @intCast(used_bits))) - 1;
    }

    fn wordCount(bit_len: usize) usize {
        return bit_len / word_bits + @intFromBool(bit_len % word_bits != 0);
    }

    fn wordIndex(index: usize) usize {
        return index / word_bits;
    }

    fn bitMask(index: usize) Word {
        return @as(Word, 1) << @as(Shift, @truncate(index));
    }
};

pub const RecvState = struct {
    allocator: std.mem.Allocator,
    stream_id: u64,
    /// Absolute stream offset represented by buffer[0].
    storage_offset: usize = 0,
    buffer: std.ArrayList(u8) = .empty,
    received: ReceivedBitmap = .{},
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
        try copy.buffer.ensureUnusedCapacity(allocator, self.buffer.items.len);
        copy.buffer.appendSliceAssumeCapacity(self.buffer.items);
        copy.received = try self.received.clone(allocator);
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
        // Bytes below read_offset were already delivered. Some of that prefix
        // can remain in storage to amortize compaction, but it no longer counts
        // against the live reassembly window and need not be conflict-checked.
        if (absolute_end <= self.read_offset) {
            if (frame.fin and absolute_end < self.highest_received_end) {
                return error.FinalSizeMismatch;
            }
            if (frame.fin) self.final_size = absolute_end;
            return 0;
        }
        var retained_offset = @max(absolute_offset, self.read_offset);
        const skipped = retained_offset - absolute_offset;
        const data = frame.data[skipped..];
        var relative_offset = retained_offset - self.storage_offset;
        var relative_end = std.math.add(usize, relative_offset, data.len) catch
            return error.InvalidStreamRange;
        if (relative_end > self.max_buffered) {
            const live_end = absolute_end - self.read_offset;
            if (live_end > self.max_buffered) {
                return error.StreamBufferTooLarge;
            }
            self.compactConsumedPrefixNow();
            retained_offset = @max(absolute_offset, self.storage_offset);
            relative_offset = retained_offset - self.storage_offset;
            relative_end = std.math.add(
                usize,
                relative_offset,
                absolute_end - retained_offset,
            ) catch return error.InvalidStreamRange;
            std.debug.assert(relative_end <= self.max_buffered);
        }

        const old_len = self.received.len();
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
            if (!self.received.anySetInRange(.{
                .start = relative_offset,
                .end = overlap_end,
            })) {
                newly_received = overlap_end - relative_offset;
            } else {
                var relative = relative_offset;
                while (relative < overlap_end) : (relative += 1) {
                    if (self.received.isSet(relative)) {
                        const data_index = relative - relative_offset;
                        if (self.buffer.items[relative] != data[data_index]) {
                            return error.ConflictingStreamData;
                        }
                    } else {
                        newly_received += 1;
                    }
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
            try self.received.resize(
                self.allocator,
                relative_end,
                relative_offset == old_len,
            );
            if (relative_offset > old_len) {
                @memset(self.buffer.items[old_len..relative_offset], 0);
            }
        }
        @memcpy(self.buffer.items[relative_offset..relative_end], data);
        if (relative_offset != old_len or relative_end <= old_len) {
            self.received.setRangeValue(
                .{ .start = relative_offset, .end = relative_end },
                true,
            );
        }
        var contiguous_relative = self.contiguous_end - self.storage_offset;
        if (relative_offset <= contiguous_relative and
            contiguous_relative < relative_end)
        {
            self.contiguous_end = self.storage_offset + relative_end;
            contiguous_relative = relative_end;
        }
        contiguous_relative = self.received.firstUnsetFrom(
            contiguous_relative,
        );
        self.contiguous_end = self.storage_offset + contiguous_relative;
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

    /// Transfer a complete, unread stream buffer to the caller. This keeps
    /// protocol adapters independent of the receive-gap representation while
    /// preserving the existing zero-copy ownership handoff.
    pub fn takeCompleteBuffer(self: *RecvState) Error![]u8 {
        const final_size = self.final_size orelse return error.NothingAvailable;
        if (self.storage_offset != 0 or
            self.read_offset != 0 or
            self.contiguous_end < final_size)
        {
            return error.NothingAvailable;
        }
        self.buffer.items.len = final_size;
        const bytes = try self.buffer.toOwnedSlice(self.allocator);
        const allocator = self.allocator;
        const stream_id = self.stream_id;
        const max_buffered = self.max_buffered;
        self.received.deinit(self.allocator);
        self.* = RecvState.init(allocator, stream_id, max_buffered);
        return bytes;
    }

    pub fn consume(self: *RecvState, len: usize) Error!void {
        if (len == 0) return;
        if (len > self.available().len) return error.NothingAvailable;
        self.read_offset += len;
        self.compactConsumedPrefix();
    }

    pub fn complete(self: RecvState) bool {
        return self.receivedComplete() and
            self.read_offset >= self.final_size.?;
    }

    /// Whether FIN and every byte through its final size have arrived. This
    /// deliberately does not require the application cursor to reach FIN; an
    /// upper protocol that has copied or otherwise committed the complete
    /// message can explicitly relinquish the retained transport bytes.
    pub fn receivedComplete(self: RecvState) bool {
        const final_size = self.final_size orelse return false;
        return self.contiguous_end >= final_size;
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
        self.compactConsumedPrefixNow();
    }

    fn compactConsumedPrefixNow(self: *RecvState) void {
        const consumed = self.read_offset - self.storage_offset;
        if (consumed == 0) return;
        const remaining = self.buffer.items.len - consumed;
        @memmove(
            self.buffer.items[0..remaining],
            self.buffer.items[consumed..],
        );
        self.buffer.items.len = remaining;
        self.received.removePrefix(consumed);
        self.storage_offset = self.read_offset;
    }

    /// Transactional, non-owning validation state for the STREAM frames in
    /// one packet.
    ///
    /// QUIC packets are validated before any frame mutates connection state.
    /// Cloning the full receive buffer to provide that guarantee makes a GRO
    /// batch quadratic in buffered STREAM bytes. This shadow instead borrows
    /// the existing bytes and retains only the packet's small frame metadata;
    /// overlap checks consult both sources without copying payload data.
    pub const PreflightFrames = struct {
        allocator: std.mem.Allocator,
        storage: []quic.StreamFrame,
        len: usize = 0,
        allocated: bool = false,

        pub fn init(
            allocator: std.mem.Allocator,
            storage: []quic.StreamFrame,
        ) PreflightFrames {
            return .{ .allocator = allocator, .storage = storage };
        }

        pub fn deinit(self: *PreflightFrames) void {
            if (self.allocated) self.allocator.free(self.storage);
            self.* = undefined;
        }

        fn items(self: *const PreflightFrames) []const quic.StreamFrame {
            return self.storage[0..self.len];
        }

        fn append(
            self: *PreflightFrames,
            frame: quic.StreamFrame,
        ) std.mem.Allocator.Error!void {
            if (self.len == self.storage.len) {
                const new_capacity = @max(@as(usize, 1), self.storage.len * 2);
                if (self.allocated) {
                    self.storage = try self.allocator.realloc(
                        self.storage,
                        new_capacity,
                    );
                } else {
                    const grown = try self.allocator.alloc(
                        quic.StreamFrame,
                        new_capacity,
                    );
                    @memcpy(grown[0..self.len], self.storage[0..self.len]);
                    self.storage = grown;
                    self.allocated = true;
                }
            }
            self.storage[self.len] = frame;
            self.len += 1;
        }
    };

    pub const Preflight = struct {
        stream_id: u64,
        storage_offset: usize,
        read_offset: usize,
        buffer: []const u8,
        received: ReceivedBitmap.View,
        final_size: ?usize,
        received_total: u64,
        highest_received_end: usize,
        max_buffered: usize,
        pending: *PreflightFrames,

        pub fn init(
            state: *const RecvState,
            pending: *PreflightFrames,
        ) Preflight {
            return .{
                .stream_id = state.stream_id,
                .storage_offset = state.storage_offset,
                .read_offset = state.read_offset,
                .buffer = state.buffer.items,
                .received = state.received.view(),
                .final_size = state.final_size,
                .received_total = state.received_total,
                .highest_received_end = state.highest_received_end,
                .max_buffered = state.max_buffered,
                .pending = pending,
            };
        }

        pub fn initEmpty(
            allocator: std.mem.Allocator,
            stream_id: u64,
            max_buffered: usize,
            pending: *PreflightFrames,
        ) Preflight {
            _ = allocator;
            return .{
                .stream_id = stream_id,
                .storage_offset = 0,
                .read_offset = 0,
                .buffer = &.{},
                .received = .{},
                .final_size = null,
                .received_total = 0,
                .highest_received_end = 0,
                .max_buffered = max_buffered,
                .pending = pending,
            };
        }

        pub fn deinit(self: *Preflight) void {
            self.* = undefined;
        }

        pub fn receivedByteCount(self: Preflight) u64 {
            return self.received_total;
        }

        pub fn applyFinalSize(
            self: *Preflight,
            final_size: u64,
            final: bool,
        ) Error!void {
            const size = std.math.cast(usize, final_size) orelse
                return error.InvalidStreamRange;
            if (final and size < self.highest_received_end) {
                return error.FinalSizeMismatch;
            }
            if (self.final_size) |known| {
                if (size > known) return error.FinalSizeMismatch;
                if (final and size != known) {
                    return error.FinalSizeMismatch;
                }
                return;
            }
            if (final) self.final_size = size;
        }

        pub fn insertTracked(
            self: *Preflight,
            frame: quic.StreamFrame,
        ) Error!u64 {
            if (frame.stream_id != self.stream_id) return error.WrongStream;
            const absolute_offset = std.math.cast(
                usize,
                frame.offset,
            ) orelse return error.InvalidStreamRange;
            const absolute_end = std.math.add(
                usize,
                absolute_offset,
                frame.data.len,
            ) catch return error.InvalidStreamRange;
            if (self.final_size) |known| {
                if (absolute_end > known) return error.FinalSizeMismatch;
                if (frame.fin and absolute_end != known) {
                    return error.FinalSizeMismatch;
                }
            }
            if (absolute_end <= self.read_offset) {
                if (frame.fin and
                    absolute_end < self.highest_received_end)
                {
                    return error.FinalSizeMismatch;
                }
                if (frame.fin) self.final_size = absolute_end;
                return 0;
            }

            const retained_offset = @max(
                absolute_offset,
                self.read_offset,
            );
            const relative_offset = retained_offset - self.storage_offset;
            const relative_end = absolute_end - self.storage_offset;
            if (absolute_end - self.read_offset > self.max_buffered) {
                return error.StreamBufferTooLarge;
            }

            const buffer_overlap_end = @min(
                relative_end,
                self.received.bit_len,
            );
            const overlaps_received = relative_offset < buffer_overlap_end and
                self.received.anySetInRange(.{
                    .start = relative_offset,
                    .end = buffer_overlap_end,
                });
            var overlaps_pending = false;
            for (self.pending.items()) |prior| {
                if (prior.stream_id != self.stream_id) continue;
                const prior_offset = std.math.cast(
                    usize,
                    prior.offset,
                ) orelse return error.InvalidStreamRange;
                const prior_end = std.math.add(
                    usize,
                    prior_offset,
                    prior.data.len,
                ) catch return error.InvalidStreamRange;
                if (retained_offset < prior_end and
                    prior_offset < absolute_end)
                {
                    overlaps_pending = true;
                    break;
                }
            }

            // Ordered STREAM traffic overwhelmingly appends beyond both the
            // retained receive buffer and this packet's earlier frames. Avoid
            // the old byte-by-byte duplicate scan in that hot case. Complex
            // retransmission overlap retains the exact conflict/count logic.
            var newly_received: u64 = @intCast(
                absolute_end - retained_offset,
            );
            if (overlaps_received or overlaps_pending) {
                newly_received = 0;
                var absolute = retained_offset;
                while (absolute < absolute_end) : (absolute += 1) {
                    const incoming = frame.data[absolute - absolute_offset];
                    const relative = absolute - self.storage_offset;
                    if (relative < self.received.bit_len and
                        self.received.isSet(relative))
                    {
                        if (self.buffer[relative] != incoming) {
                            return error.ConflictingStreamData;
                        }
                        continue;
                    }

                    var covered_by_pending = false;
                    for (self.pending.items()) |prior| {
                        if (prior.stream_id != self.stream_id) continue;
                        const prior_offset = std.math.cast(
                            usize,
                            prior.offset,
                        ) orelse return error.InvalidStreamRange;
                        const prior_end = std.math.add(
                            usize,
                            prior_offset,
                            prior.data.len,
                        ) catch return error.InvalidStreamRange;
                        if (absolute < prior_offset or
                            absolute >= prior_end) continue;
                        if (prior.data[absolute - prior_offset] != incoming) {
                            return error.ConflictingStreamData;
                        }
                        covered_by_pending = true;
                        break;
                    }
                    if (!covered_by_pending) newly_received += 1;
                }
            }

            // Match RecvState's conflict-first classification: an overlapping
            // bad retransmission remains ConflictingStreamData even when that
            // frame also carries an inconsistent FIN.
            if (frame.fin and absolute_end < self.highest_received_end) {
                return error.FinalSizeMismatch;
            }
            try self.pending.append(frame);
            self.received_total = std.math.add(
                u64,
                self.received_total,
                newly_received,
            ) catch std.math.maxInt(u64);
            self.highest_received_end = @max(
                self.highest_received_end,
                absolute_end,
            );
            if (frame.fin) self.final_size = absolute_end;
            return newly_received;
        }
    };
};

test "QUIC receive bitmap matches byte model across range and prefix operations" {
    const allocator = std.testing.allocator;
    var bitmap: ReceivedBitmap = .{};
    defer bitmap.deinit(allocator);
    var model = [_]bool{false} ** 192;

    try bitmap.resize(allocator, 130, false);
    bitmap.setRangeValue(.{ .start = 3, .end = 127 }, true);
    @memset(model[3..127], true);
    bitmap.setRangeValue(.{ .start = 17, .end = 73 }, false);
    @memset(model[17..73], false);
    try std.testing.expect(bitmap.anySetInRange(.{ .start = 3, .end = 17 }));
    try std.testing.expect(!bitmap.anySetInRange(.{ .start = 17, .end = 73 }));
    try std.testing.expect(bitmap.anySetInRange(.{ .start = 72, .end = 128 }));
    try std.testing.expect(!bitmap.anySetInRange(.{ .start = 130, .end = 130 }));
    for (model[0..130], 0..) |expected, index| {
        try std.testing.expectEqual(expected, bitmap.isSet(index));
    }

    try bitmap.resize(allocator, 191, true);
    @memset(model[130..191], true);
    try std.testing.expect(bitmap.anySetInRange(.{ .start = 127, .end = 191 }));
    for (model[0..191], 0..) |expected, index| {
        try std.testing.expectEqual(expected, bitmap.isSet(index));
    }
    for (0..192) |start| {
        var expected = start;
        while (expected < 191 and model[expected]) : (expected += 1) {}
        try std.testing.expectEqual(expected, bitmap.firstUnsetFrom(start));
    }

    var cloned = try bitmap.clone(allocator);
    defer cloned.deinit(allocator);
    for (0..131) |prefix_len| {
        var shifted = try cloned.clone(allocator);
        defer shifted.deinit(allocator);
        shifted.removePrefix(prefix_len);
        for (model[prefix_len..191], 0..) |expected, index| {
            try std.testing.expectEqual(expected, shifted.isSet(index));
        }
    }

    bitmap.removePrefix(13);
    for (model[13..191], 0..) |expected, index| {
        try std.testing.expectEqual(expected, bitmap.isSet(index));
        try std.testing.expectEqual(model[index], cloned.isSet(index));
    }
    for (0..179) |start| {
        var expected = start;
        while (expected < 178 and model[13 + expected]) : (expected += 1) {}
        try std.testing.expectEqual(expected, bitmap.firstUnsetFrom(start));
    }
    try bitmap.resize(allocator, 65, false);
    for (model[13..78], 0..) |expected, index| {
        try std.testing.expectEqual(expected, bitmap.isSet(index));
    }
    bitmap.removePrefix(65);
    try std.testing.expectEqual(@as(usize, 0), bitmap.len());
    try std.testing.expectEqual(@as(usize, 0), bitmap.words.items.len);
    try std.testing.expectEqual(
        std.math.maxInt(usize) / ReceivedBitmap.word_bits + 1,
        ReceivedBitmap.wordCount(std.math.maxInt(usize)),
    );
}

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
