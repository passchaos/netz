const std = @import("std");
const quic = @import("mod.zig");
const ReceivedBitmap = @import("stream/received_bitmap.zig").Bitmap;

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
            const fill_received = relative_offset == old_len;
            // Reserve both allocations before changing either logical length.
            // A first gap can require bitmap materialization even when the
            // byte buffer already has spare capacity; OOM must leave both
            // halves retryable and aligned.
            try self.buffer.ensureTotalCapacity(self.allocator, relative_end);
            try self.received.ensureResizeCapacity(
                self.allocator,
                relative_end,
                fill_received,
            );
            self.buffer.items.len = relative_end;
            self.received.resizeAssumeCapacity(
                relative_end,
                fill_received,
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
        if (try self.prepareCompleteBufferTransfer()) {
            return self.takePreparedCompleteBuffer();
        }
        const bytes = try self.buffer.toOwnedSlice(self.allocator);
        const allocator = self.allocator;
        const stream_id = self.stream_id;
        const max_buffered = self.max_buffered;
        self.received.deinit(self.allocator);
        self.* = RecvState.init(allocator, stream_id, max_buffered);
        return bytes;
    }

    /// Prepare a complete unread buffer for an allocation-free ownership
    /// transfer. A successful in-place shrink preserves every existing slice
    /// into the message; false leaves the complete message readable so a
    /// caller can allocate a fallback copy before committing.
    pub fn prepareCompleteBufferTransfer(self: *RecvState) Error!bool {
        const final_size = self.final_size orelse
            return error.NothingAvailable;
        if (self.storage_offset != 0 or
            self.read_offset != 0 or
            self.contiguous_end < final_size)
        {
            return error.NothingAvailable;
        }
        self.buffer.items.len = final_size;
        if (self.buffer.capacity == final_size) return true;
        if (final_size == 0) return false;
        if (!self.allocator.resize(
            self.buffer.allocatedSlice(),
            final_size,
        )) return false;
        self.buffer.capacity = final_size;
        return true;
    }

    /// Finish a transfer prepared by `prepareCompleteBufferTransfer`.
    /// No allocation or pointer movement occurs.
    pub fn takePreparedCompleteBuffer(self: *RecvState) []u8 {
        const final_size = self.final_size orelse unreachable;
        std.debug.assert(self.storage_offset == 0);
        std.debug.assert(self.read_offset == 0);
        std.debug.assert(self.contiguous_end >= final_size);
        std.debug.assert(self.buffer.items.len == final_size);
        std.debug.assert(self.buffer.capacity == final_size);
        const bytes = self.buffer.toOwnedSliceAssert();
        const allocator = self.allocator;
        const stream_id = self.stream_id;
        const max_buffered = self.max_buffered;
        self.received.deinit(allocator);
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
        pub fn items(self: *const PreflightFrames) []const quic.StreamFrame {
            return self.storage[0..self.len];
        }
        pub fn append(
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

test {
    _ = @import("stream/tests.zig");
}
