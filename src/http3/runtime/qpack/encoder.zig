//! Connection-scoped QPACK encoding and peer-owned field-section references.

const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const Error = @import("../error.zig").Error;

pub const QpackEncodeState = struct {
    const PendingSection = struct {
        sequence: u64,
        stream_id: u64,
        required_insert_count: u64,
        references: []u64,

        fn deinit(self: *PendingSection, allocator: std.mem.Allocator) void {
            allocator.free(self.references);
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    table: http3.Qpack.DynamicTable,
    known_received_count: u64 = 0,
    pending_sections: std.ArrayList(PendingSection) = .empty,
    /// Bound retained descriptors and reference arrays by max_stream_buffer.
    /// Once full, use static indices/literals until peer feedback frees it.
    pending_section_bytes: usize = 0,
    next_section_sequence: u64 = 0,
    /// First pending field section per stream. QPACK decoder feedback names
    /// streams rather than individual sections, and sections on the same stream
    /// must be acknowledged/cancelled in FIFO order, so this index points at
    /// the earliest retained section for each stream.
    pending_section_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    reference_counts: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    /// Number of not-yet-decodable field sections on each request/push stream.
    /// QPACK limits potentially blocked streams, not individual sections, so
    /// multiple interim/final/trailer sections share one budget slot.
    blocked_section_counts: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    encoder_instructions: std.ArrayList(u8) = .empty,
    decoder_stream: ?quic.stream_state.RecvState = null,
    decoder_stream_type_received: bool = false,
    peer_max_capacity: ?usize = null,
    peer_max_blocked_streams: ?u64 = null,
    max_stream_buffer: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        peer_max_capacity: usize,
        max_stream_buffer: usize,
    ) QpackEncodeState {
        return .{
            .allocator = allocator,
            .table = .init(allocator, peer_max_capacity),
            .peer_max_capacity = peer_max_capacity,
            .peer_max_blocked_streams = 0,
            .max_stream_buffer = max_stream_buffer,
        };
    }

    /// Create an encoder before the peer's SETTINGS frame is available.
    ///
    /// The zero-capacity table cannot queue inserts until
    /// `configurePeerCapacity` binds it to the immutable advertised limit.
    pub fn initAwaitingPeerSettings(
        allocator: std.mem.Allocator,
        max_stream_buffer: usize,
    ) QpackEncodeState {
        return .{
            .allocator = allocator,
            .table = .init(allocator, 0),
            .max_stream_buffer = max_stream_buffer,
        };
    }

    pub fn deinit(self: *QpackEncodeState) void {
        if (self.decoder_stream) |*stream| stream.deinit();
        for (self.pending_sections.items) |*section| section.deinit(self.allocator);
        self.pending_sections.deinit(self.allocator);
        self.pending_section_index.deinit(self.allocator);
        self.reference_counts.deinit(self.allocator);
        self.blocked_section_counts.deinit(self.allocator);
        self.encoder_instructions.deinit(self.allocator);
        self.table.deinit();
        self.* = undefined;
    }

    pub fn setCapacity(
        self: *QpackEncodeState,
        capacity: usize,
    ) http3.Error!void {
        try self.ensureEvictableForCapacity(capacity);
        const original_len = self.encoder_instructions.items.len;
        errdefer self.encoder_instructions.shrinkRetainingCapacity(original_len);
        try http3.Qpack.writeEncoderInstruction(
            &self.encoder_instructions,
            self.allocator,
            .{ .set_capacity = capacity },
        );
        try self.table.setCapacity(capacity);
    }

    pub fn configurePeerCapacity(
        self: *QpackEncodeState,
        capacity: usize,
    ) http3.Error!void {
        return self.configurePeerLimits(capacity, 0);
    }

    /// Bind the encoder once to the peer's immutable QPACK SETTINGS.
    ///
    /// Before SETTINGS arrives the encoder uses literals. Afterwards it may
    /// reference unacknowledged inserts only while doing so keeps the number of
    /// potentially blocked streams within the peer-advertised limit.
    pub fn configurePeerLimits(
        self: *QpackEncodeState,
        capacity: usize,
        max_blocked_streams: u64,
    ) http3.Error!void {
        if (max_blocked_streams >
            http3.Settings.max_supported_qpack_blocked_streams)
        {
            return error.QpackEncoderStreamError;
        }
        if (self.peer_max_capacity) |configured_capacity| {
            if (configured_capacity != capacity or
                self.peer_max_blocked_streams.? != max_blocked_streams)
            {
                return error.QpackEncoderStreamError;
            }
            return;
        }
        if (self.table.insert_count != 0 or self.table.entryCount() != 0) {
            return error.QpackEncoderStreamError;
        }
        const previous_max_capacity = self.table.max_capacity;
        errdefer self.table.max_capacity = previous_max_capacity;
        self.table.max_capacity = capacity;
        if (capacity != 0) try self.setCapacity(capacity);
        self.peer_max_capacity = capacity;
        self.peer_max_blocked_streams = max_blocked_streams;
    }

    pub fn insertField(
        self: *QpackEncodeState,
        name: []const u8,
        value: []const u8,
    ) http3.Error!?u64 {
        const entry_size = std.math.add(
            usize,
            std.math.add(usize, name.len, value.len) catch
                return error.QpackEncoderStreamError,
            http3.Qpack.dynamic_entry_overhead,
        ) catch return error.QpackEncoderStreamError;
        if (entry_size > self.table.capacity) return null;
        if (!self.canEvictForInsert(entry_size)) return null;

        var instruction: http3.Qpack.EncoderInstruction = undefined;
        if (findQpackStaticName(name)) |index| {
            instruction = .{ .insert_name_reference = .{
                .static = true,
                .name_index = index,
                .value = value,
            } };
        } else if (self.table.findName(name)) |absolute_index| {
            const relative = self.table.insert_count - absolute_index - 1;
            instruction = .{ .insert_name_reference = .{
                .static = false,
                .name_index = relative,
                .value = value,
            } };
        } else {
            instruction = .{ .insert_literal = .{ .name = name, .value = value } };
        }
        const original_len = self.encoder_instructions.items.len;
        errdefer self.encoder_instructions.shrinkRetainingCapacity(original_len);
        try http3.Qpack.writeEncoderInstruction(
            &self.encoder_instructions,
            self.allocator,
            instruction,
        );
        return try self.table.insert(name, value);
    }

    pub fn encodeFieldSection(
        self: *QpackEncodeState,
        list: *std.ArrayList(u8),
        stream_id: u64,
        fields: []const http3.Qpack.HeaderField,
    ) http3.Error!void {
        const original_len = list.items.len;
        errdefer list.shrinkRetainingCapacity(original_len);
        var references: std.ArrayList(u64) = .empty;
        errdefer references.deinit(self.allocator);
        const can_track_section = self.max_stream_buffer -| self.pending_section_bytes >= @sizeOf(PendingSection) + @sizeOf(u64);
        const reference_limit = if (!can_track_section)
            0
        else if (self.mayRiskBlockedStream(stream_id))
            self.table.insert_count
        else
            self.known_received_count;
        try http3.Qpack.encodeDynamicBlockWithReferenceLimit(
            list,
            self.allocator,
            fields,
            self.table,
            reference_limit,
            &references,
        );
        if (references.items.len == 0) {
            references.deinit(self.allocator);
            return;
        }

        const reference_bytes = std.math.mul(usize, references.items.len, @sizeOf(u64)) catch return error.QpackEncoderStreamError;
        const section_bytes = std.math.add(usize, @sizeOf(PendingSection), reference_bytes) catch return error.QpackEncoderStreamError;
        if (section_bytes > self.max_stream_buffer -| self.pending_section_bytes) {
            // Keep existing entries pinned while bounding newly retained
            // references. Literal encoding preserves request admission.
            list.shrinkRetainingCapacity(original_len);
            references.deinit(self.allocator);
            references = .empty;
            try http3.Qpack.encodeDynamicBlockWithReferenceLimit(list, self.allocator, fields, self.table, 0, &references);
            references.deinit(self.allocator);
            return;
        }
        const next_sequence = std.math.add(u64, self.next_section_sequence, 1) catch return error.QpackEncoderStreamError;

        const owned = try references.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(owned);
        const required_insert_count = maxReferencedInsertCount(owned);
        const potentially_blocked =
            required_insert_count > self.known_received_count;
        try self.pending_sections.ensureUnusedCapacity(self.allocator, 1);
        const pending_slot = try self.pending_section_index.getOrPut(
            self.allocator,
            stream_id,
        );
        errdefer if (!pending_slot.found_existing) {
            _ = self.pending_section_index.remove(stream_id);
        };
        // `encodeDynamicBlockKnownReceived` already deduplicates references
        // within this field section. Reserve the section's full reference
        // count as a safe upper bound and update counts in one hash-map pass
        // instead of probing once with `contains` and again with `getOrPut`.
        try self.reference_counts.ensureUnusedCapacity(
            self.allocator,
            std.math.cast(u32, owned.len) orelse
                return error.OutOfMemory,
        );
        if (potentially_blocked and
            !self.blocked_section_counts.contains(stream_id))
        {
            // At most one new map slot is needed for a new blocked stream,
            // even when several sections on that stream reference inserts.
            try self.blocked_section_counts.ensureUnusedCapacity(
                self.allocator,
                1,
            );
        }
        for (owned) |absolute_index| {
            const entry = self.reference_counts.getOrPutAssumeCapacity(
                absolute_index,
            );
            if (!entry.found_existing) entry.value_ptr.* = 0;
            entry.value_ptr.* += 1;
        }
        const pending_index = self.pending_sections.items.len;
        self.pending_sections.appendAssumeCapacity(.{
            .sequence = self.next_section_sequence,
            .stream_id = stream_id,
            .required_insert_count = required_insert_count,
            .references = owned,
        });
        self.next_section_sequence = next_sequence;
        self.pending_section_bytes += section_bytes;
        if (!pending_slot.found_existing) {
            pending_slot.value_ptr.* = pending_index;
        }
        if (potentially_blocked) {
            const blocked = self.blocked_section_counts
                .getOrPutAssumeCapacity(stream_id);
            if (!blocked.found_existing) blocked.value_ptr.* = 0;
            blocked.value_ptr.* += 1;
        }
    }

    pub fn applyDecoderStreamFrame(
        self: *QpackEncodeState,
        control: *http3.ControlState,
        stream: quic.StreamFrame,
    ) Error!void {
        if (self.decoder_stream) |receive| {
            if (receive.stream_id != stream.stream_id) {
                return error.StreamCreationError;
            }
        }
        if (stream.fin) return error.ClosedCriticalStream;
        if (self.decoder_stream == null) {
            self.decoder_stream = quic.stream_state.RecvState.init(
                self.allocator,
                stream.stream_id,
                self.max_stream_buffer,
            );
        }
        const receive = &self.decoder_stream.?;
        try receive.insert(stream);
        if (!self.decoder_stream_type_received) {
            const available = receive.available();
            if (available.len == 0) return;
            const prefix = quic.varint.decodeSlice(available) catch |err| switch (err) {
                error.BufferTooShort => return,
                else => return error.QpackDecoderStreamError,
            };
            if (@as(http3.StreamType, @enumFromInt(prefix.value)) != .qpack_decoder) {
                return error.InvalidStreamType;
            }
            try control.registerQpackStream(.qpack_decoder, stream.stream_id);
            try receive.consume(prefix.len);
            self.decoder_stream_type_received = true;
        }

        while (receive.available().len != 0) {
            const decoded = http3.Qpack.decodeDecoderInstruction(
                receive.available(),
            ) catch |err| switch (err) {
                error.BufferTooShort => break,
                else => return error.QpackDecoderStreamError,
            };
            try self.applyDecoderInstruction(decoded.instruction);
            try receive.consume(decoded.consumed);
        }
    }

    pub fn pendingEncoderInstructions(self: QpackEncodeState) []const u8 {
        return self.encoder_instructions.items;
    }

    pub fn clearEncoderInstructions(self: *QpackEncodeState) void {
        self.encoder_instructions.clearRetainingCapacity();
    }

    /// Discard sections proven not to have reached the wire. Local FIN/RESET
    /// does not justify this: transmitted references wait for decoder feedback.
    pub fn abandonStream(self: *QpackEncodeState, stream_id: u64) void {
        _ = self.releaseSectionsForStream(stream_id);
    }

    pub fn checkpoint(self: *const QpackEncodeState) u64 {
        return self.next_section_sequence;
    }

    /// Peer feedback can remove earlier entries during transport waits.
    /// Use immutable sequence numbers to roll back only this operation.
    pub fn rollbackAfter(self: *QpackEncodeState, sequence: u64) void {
        while (self.pending_sections.items.len != 0) {
            const index = self.pending_sections.items.len - 1;
            if (self.pending_sections.items[index].sequence < sequence) return;
            self.releaseSection(index);
        }
    }

    pub fn hasPendingSections(self: QpackEncodeState, stream_id: u64) bool {
        return self.pending_section_index.count() != 0 and
            self.pending_section_index.contains(stream_id);
    }

    pub fn rollbackPendingSections(self: *QpackEncodeState, original_len: usize) void {
        while (self.pending_sections.items.len > original_len) {
            self.releaseSection(self.pending_sections.items.len - 1);
        }
    }

    fn applyDecoderInstruction(
        self: *QpackEncodeState,
        instruction: http3.Qpack.DecoderInstruction,
    ) Error!void {
        switch (instruction) {
            .insert_count_increment => |increment| {
                const next = std.math.add(
                    u64,
                    self.known_received_count,
                    increment,
                ) catch return error.QpackDecoderStreamError;
                if (next > self.table.insert_count) return error.QpackDecoderStreamError;
                self.known_received_count = next;
                self.rebuildBlockedSectionCounts();
            },
            .section_acknowledgment => |stream_id| {
                const index = self.findPendingSection(stream_id) orelse
                    return error.QpackDecoderStreamError;
                const required_insert_count =
                    self.pending_sections.items[index].required_insert_count;
                self.releaseSection(index);
                // Section Ack implicitly acknowledges all inserts up to RIC.
                self.known_received_count = @max(
                    self.known_received_count,
                    required_insert_count,
                );
                self.rebuildBlockedSectionCounts();
            },
            .stream_cancellation => |stream_id| {
                // RFC 9204 §2.2.2.2 requires a decoder to emit this whenever
                // it abandons a stream (unless its maximum table capacity is
                // zero). The stream might not actually contain a dynamic
                // reference, so an empty release is a valid idempotent no-op.
                _ = self.releaseSectionsForStream(stream_id);
            },
        }
    }

    fn findPendingSection(self: QpackEncodeState, stream_id: u64) ?usize {
        if (self.pending_section_index.count() == 0) return null;
        return self.pending_section_index.get(stream_id);
    }

    fn releaseSection(self: *QpackEncodeState, index: usize) void {
        var section = if (index == self.pending_sections.items.len - 1)
            self.pending_sections.pop().?
        else
            self.pending_sections.orderedRemove(index);
        const removed_stream_id = section.stream_id;
        const removed_was_first =
            self.pending_section_index.get(removed_stream_id) == index;
        if (removed_was_first) {
            _ = self.pending_section_index.remove(removed_stream_id);
        }
        if (index < self.pending_sections.items.len) {
            self.repairPendingSectionIndexFrom(index);
        }
        self.releaseSectionReferences(&section);
    }

    fn releaseSectionReferences(
        self: *QpackEncodeState,
        section: *PendingSection,
    ) void {
        self.pending_section_bytes -= @sizeOf(PendingSection) + section.references.len * @sizeOf(u64);
        if (section.required_insert_count > self.known_received_count) {
            const blocked = self.blocked_section_counts
                .getPtr(section.stream_id).?;
            blocked.* -= 1;
            if (blocked.* == 0) {
                _ = self.blocked_section_counts.remove(section.stream_id);
            }
        }
        for (section.references) |absolute_index| {
            const count = self.reference_counts.getPtr(absolute_index).?;
            count.* -= 1;
            if (count.* == 0) _ = self.reference_counts.remove(absolute_index);
        }
        section.deinit(self.allocator);
    }

    pub fn releaseSectionsForStream(
        self: *QpackEncodeState,
        stream_id: u64,
    ) usize {
        if (self.pending_section_index.count() == 0) return 0;
        const start_index = self.pending_section_index.get(stream_id) orelse return 0;
        var write_index: usize = start_index;
        var released: usize = 0;
        for (self.pending_sections.items[start_index..], start_index..) |section, read_index| {
            if (section.stream_id == stream_id) {
                // QPACK Section Acknowledgment identifies only the stream, so
                // multiple outstanding header/trailer sections on the same
                // stream must retain FIFO order.  Compact in one stable pass
                // instead of repeated `orderedRemove` memmoves or
                // `swapRemove`-based reordering.
                var removed = section;
                self.releaseSectionReferences(&removed);
                released += 1;
                continue;
            }
            if (write_index != read_index) {
                self.pending_sections.items[write_index] = section;
            }
            write_index += 1;
        }
        self.pending_sections.items.len = write_index;
        _ = self.pending_section_index.remove(stream_id);
        self.repairPendingSectionIndexFrom(start_index);
        return released;
    }

    fn rebuildPendingSectionIndexAssumeCapacity(self: *QpackEncodeState) void {
        self.pending_section_index.clearRetainingCapacity();
        for (self.pending_sections.items, 0..) |section, index| {
            if (!self.pending_section_index.contains(section.stream_id)) {
                self.pending_section_index.putAssumeCapacityNoClobber(
                    section.stream_id,
                    index,
                );
            }
        }
    }

    fn repairPendingSectionIndexFrom(
        self: *QpackEncodeState,
        start_index: usize,
    ) void {
        var index = start_index;
        while (index < self.pending_sections.items.len) : (index += 1) {
            const stream_id = self.pending_sections.items[index].stream_id;
            if (self.pending_section_index.getPtr(stream_id)) |mapped| {
                if (mapped.* > index) mapped.* = index;
            } else {
                self.pending_section_index.putAssumeCapacityNoClobber(
                    stream_id,
                    index,
                );
            }
        }
    }

    fn canEvictForInsert(
        self: QpackEncodeState,
        incoming_size: usize,
    ) bool {
        var simulated_size = self.table.current_size;
        var index = self.table.head;
        while (simulated_size > self.table.capacity or
            incoming_size > self.table.capacity - simulated_size)
        {
            if (index >= self.table.entries.items.len) return false;
            const entry = self.table.entries.items[index];
            if (!self.entryEvictable(entry.absolute_index)) return false;
            simulated_size -= entry.size();
            index += 1;
        }
        return true;
    }

    fn ensureEvictableForCapacity(
        self: QpackEncodeState,
        capacity: usize,
    ) http3.Error!void {
        if (capacity > self.table.max_capacity) return error.QpackEncoderStreamError;
        var simulated_size = self.table.current_size;
        var index = self.table.head;
        while (simulated_size > capacity) {
            const entry = self.table.entries.items[index];
            if (!self.entryEvictable(entry.absolute_index)) return error.QpackEncoderStreamError;
            simulated_size -= entry.size();
            index += 1;
        }
    }

    fn entryEvictable(self: QpackEncodeState, absolute_index: u64) bool {
        if (absolute_index >= self.known_received_count) return false;
        return self.reference_counts.count() == 0 or
            !self.reference_counts.contains(absolute_index);
    }

    fn mayRiskBlockedStream(
        self: QpackEncodeState,
        stream_id: u64,
    ) bool {
        if (self.known_received_count >= self.table.insert_count) return false;
        const limit = self.peer_max_blocked_streams orelse return false;
        if (limit == 0) return false;
        if (self.blocked_section_counts.contains(stream_id)) return true;
        return self.blocked_section_counts.count() < limit;
    }

    fn rebuildBlockedSectionCounts(self: *QpackEncodeState) void {
        self.blocked_section_counts.clearRetainingCapacity();
        for (self.pending_sections.items) |section| {
            if (section.required_insert_count <= self.known_received_count) {
                continue;
            }
            const blocked = self.blocked_section_counts
                .getOrPutAssumeCapacity(section.stream_id);
            if (!blocked.found_existing) blocked.value_ptr.* = 0;
            blocked.value_ptr.* += 1;
        }
    }

    fn maxReferencedInsertCount(references: []const u64) u64 {
        var required_insert_count: u64 = 0;
        for (references) |absolute_index| {
            required_insert_count = @max(
                required_insert_count,
                absolute_index + 1,
            );
        }
        return required_insert_count;
    }
};

fn findQpackStaticName(name: []const u8) ?u64 {
    return http3.Qpack.findStaticName(name);
}

test {
    _ = @import("tests/encoder_lifecycle.zig");
}
