const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");

const Error = runtime_error.Error;

pub const PeerUniStreamType = enum {
    control,
    qpack_encoder,
    qpack_decoder,
    push,
    unknown,
};

pub const ClassifiedPeerUniFrame = struct {
    frame: quic.StreamFrame,
    stream_type: PeerUniStreamType,
};

const PeerUniStream = struct {
    receive: quic.stream_state.RecvState,
    stream_type: ?PeerUniStreamType = null,
    fin_delivered: bool = false,

    fn deinit(self: *PeerUniStream) void {
        self.receive.deinit();
        self.* = undefined;
    }
};

const max_pending_peer_uni_streams: usize = 256;

fn peerUniStreamType(value: u64) PeerUniStreamType {
    return switch (@as(http3.StreamType, @enumFromInt(value))) {
        .control => .control,
        .qpack_encoder => .qpack_encoder,
        .qpack_decoder => .qpack_decoder,
        .push => .push,
        else => .unknown,
    };
}

/// Connection-scoped receive side of QPACK. It also owns bounded temporary
/// reassembly for peer unidirectional streams until their offset-zero type can
/// be classified without relying on stream-number allocation order.
///
/// Encoder-stream bytes are QUIC stream data, so instructions can be split,
/// duplicated, or delivered out of order. This state reassembles that stream,
/// applies only complete instructions, and coalesces decoder feedback without
/// losing the trailing partial instruction.
pub const QpackDecodeState = struct {
    allocator: std.mem.Allocator,
    table: http3.Qpack.DynamicTable,
    encoder_stream: ?quic.stream_state.RecvState = null,
    encoder_stream_type_received: bool = false,
    decoder_instructions: std.ArrayList(u8) = .empty,
    acknowledged_insert_count: u64 = 0,
    max_stream_buffer: usize,
    peer_uni_streams: std.ArrayList(PeerUniStream) = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        max_table_capacity: usize,
        max_stream_buffer: usize,
    ) QpackDecodeState {
        return .{
            .allocator = allocator,
            .table = .init(allocator, max_table_capacity),
            .max_stream_buffer = max_stream_buffer,
        };
    }

    pub fn deinit(self: *QpackDecodeState) void {
        if (self.encoder_stream) |*stream| stream.deinit();
        for (self.peer_uni_streams.items) |*stream| stream.deinit();
        self.peer_uni_streams.deinit(self.allocator);
        self.table.deinit();
        self.decoder_instructions.deinit(self.allocator);
        self.* = undefined;
    }

    /// Reassemble a peer unidirectional stream until its offset-zero type is
    /// available. Returned bytes are contiguous and remain borrowed until the
    /// matching `commitPeerUniFrame` call.
    pub fn classifyPeerUniFrame(
        self: *QpackDecodeState,
        frame: quic.StreamFrame,
    ) Error!?ClassifiedPeerUniFrame {
        if ((frame.stream_id & 0x02) == 0) return null;
        const entry = self.findPeerUniStream(frame.stream_id) orelse blk: {
            if (self.peer_uni_streams.items.len >=
                max_pending_peer_uni_streams)
            {
                return error.ExcessiveLoad;
            }
            try self.peer_uni_streams.append(self.allocator, .{
                .receive = .init(
                    self.allocator,
                    frame.stream_id,
                    self.max_stream_buffer,
                ),
            });
            break :blk &self.peer_uni_streams.items[
                self.peer_uni_streams.items.len - 1
            ];
        };
        try entry.receive.insert(frame);
        if (entry.stream_type == null) {
            entry.stream_type = classify: {
                const prefix = quic.varint.decodeSlice(
                    entry.receive.available(),
                ) catch |err| switch (err) {
                    error.BufferTooShort => {
                        // FIN can arrive before offset zero. Wait until the
                        // complete stream is contiguous before deciding that
                        // its type prefix was truncated. A zero-byte stream has
                        // no declared critical type, so treat it like an
                        // unknown extension stream and let the router retire
                        // its QUIC stream credit normally.
                        if (!entry.receive.receivedComplete()) return null;
                        if (entry.receive.final_size.? != 0) {
                            return error.InvalidStreamType;
                        }
                        break :classify .unknown;
                    },
                    else => return err,
                };
                break :classify peerUniStreamType(prefix.value);
            };
        }
        const available = entry.receive.available();
        const at_final = entry.receive.final_size != null and
            entry.receive.contiguous_end == entry.receive.final_size.?;
        if (available.len == 0 and (!at_final or entry.fin_delivered)) {
            return null;
        }
        return .{
            .frame = .{
                .stream_id = frame.stream_id,
                .offset = entry.receive.read_offset,
                .data = available,
                .fin = at_final and !entry.fin_delivered,
            },
            .stream_type = entry.stream_type.?,
        };
    }

    pub fn commitPeerUniFrame(
        self: *QpackDecodeState,
        frame: quic.StreamFrame,
    ) void {
        const entry = self.findPeerUniStream(frame.stream_id) orelse
            unreachable;
        entry.receive.consume(frame.data.len) catch unreachable;
        if (frame.fin) entry.fin_delivered = true;
        if (entry.fin_delivered) self.removePeerUniStream(frame.stream_id);
    }

    pub fn discardPeerUniStream(
        self: *QpackDecodeState,
        stream_id: u64,
    ) void {
        self.removePeerUniStream(stream_id);
    }

    pub fn classifiedPeerUniStreamType(
        self: *const QpackDecodeState,
        stream_id: u64,
    ) ?PeerUniStreamType {
        for (self.peer_uni_streams.items) |entry| {
            if (entry.receive.stream_id == stream_id) return entry.stream_type;
        }
        return null;
    }

    fn findPeerUniStream(
        self: *QpackDecodeState,
        stream_id: u64,
    ) ?*PeerUniStream {
        for (self.peer_uni_streams.items) |*entry| {
            if (entry.receive.stream_id == stream_id) return entry;
        }
        return null;
    }

    fn removePeerUniStream(
        self: *QpackDecodeState,
        stream_id: u64,
    ) void {
        for (self.peer_uni_streams.items, 0..) |*entry, index| {
            if (entry.receive.stream_id != stream_id) continue;
            entry.deinit();
            _ = self.peer_uni_streams.swapRemove(index);
            return;
        }
    }

    pub fn applyEncoderStreamFrame(
        self: *QpackDecodeState,
        control: *http3.ControlState,
        stream: quic.StreamFrame,
    ) Error!void {
        if (self.encoder_stream) |receive| {
            if (receive.stream_id != stream.stream_id) {
                return error.StreamCreationError;
            }
        }
        if (stream.fin) return error.ClosedCriticalStream;
        if (self.encoder_stream == null) {
            self.encoder_stream = quic.stream_state.RecvState.init(
                self.allocator,
                stream.stream_id,
                self.max_stream_buffer,
            );
        }
        const receive = &self.encoder_stream.?;
        try receive.insert(stream);

        // Consume and validate the stream type independently from instruction
        // framing. It can itself be split across retransmitted STREAM frames.
        if (!self.encoder_stream_type_received) {
            const available = receive.available();
            if (available.len == 0) return;
            const prefix = quic.varint.decodeSlice(available) catch |err| switch (err) {
                error.BufferTooShort => return,
                else => return error.QpackEncoderStreamError,
            };
            if (@as(http3.StreamType, @enumFromInt(prefix.value)) != .qpack_encoder) {
                return error.InvalidStreamType;
            }
            try control.registerQpackStream(.qpack_encoder, stream.stream_id);
            try receive.consume(prefix.len);
            self.encoder_stream_type_received = true;
        }

        // One Insert Count Increment encoded with a 6-bit prefix needs at
        // most 11 bytes for a u64. Reserve before mutating the dynamic table so
        // allocation failure leaves both stream consumption and table state
        // retryable.
        try self.decoder_instructions.ensureUnusedCapacity(self.allocator, 11);
        var inserted_total: u64 = 0;
        while (receive.available().len != 0) {
            const available = receive.available();
            var decoded = http3.Qpack.decodeEncoderInstruction(
                self.allocator,
                available,
            ) catch |err| switch (err) {
                error.BufferTooShort => break,
                error.OutOfMemory => return err,
                else => return error.QpackEncoderStreamError,
            };
            defer decoded.deinit(self.allocator);
            const before = self.table.insert_count;
            applyDecodedEncoderInstruction(&self.table, decoded.instruction) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return error.QpackEncoderStreamError,
            };
            try receive.consume(decoded.consumed);
            inserted_total = std.math.add(
                u64,
                inserted_total,
                self.table.insert_count - before,
            ) catch return error.QpackDecoderStreamError;
        }
        if (inserted_total != 0) try self.recordInsertCount(inserted_total);
    }

    pub fn decodeFieldSection(
        self: *QpackDecodeState,
        allocator: std.mem.Allocator,
        stream_id: u64,
        block: []const u8,
    ) Error!http3.Qpack.DynamicBlockDecode {
        // Section Acknowledgment uses a 7-bit prefix and has the same 11-byte
        // worst case. Reserve before allocating/decoding the field section so
        // an OOM cannot strand a successfully decoded result without feedback.
        try self.decoder_instructions.ensureUnusedCapacity(self.allocator, 11);
        const decoded = try http3.Qpack.decodeDynamicBlock(
            allocator,
            block,
            self.table,
        );
        if (decoded.required_insert_count != 0) {
            try http3.Qpack.writeDecoderInstruction(
                &self.decoder_instructions,
                self.allocator,
                .{ .section_acknowledgment = stream_id },
            );
        }
        return decoded;
    }

    /// Transfer pending decoder instructions to the caller. Ownership is
    /// explicit because returning a borrowed slice and then clearing the
    /// ArrayList would let later appends overwrite bytes before the transport
    /// sends them.
    pub fn takeDecoderInstructions(self: *QpackDecodeState) std.mem.Allocator.Error![]u8 {
        return self.decoder_instructions.toOwnedSlice(self.allocator);
    }

    pub fn pendingDecoderInstructions(self: QpackDecodeState) []const u8 {
        return self.decoder_instructions.items;
    }

    pub fn clearDecoderInstructions(self: *QpackDecodeState) void {
        self.decoder_instructions.clearRetainingCapacity();
    }

    pub fn consumeDecoderInstructions(
        self: *QpackDecodeState,
        count: usize,
    ) void {
        std.debug.assert(count <= self.decoder_instructions.items.len);
        const remaining = self.decoder_instructions.items.len - count;
        std.mem.copyForwards(
            u8,
            self.decoder_instructions.items[0..remaining],
            self.decoder_instructions.items[count..],
        );
        self.decoder_instructions.items.len = remaining;
    }

    pub fn acknowledgeSections(
        self: *QpackDecodeState,
        stream_id: u64,
        count: usize,
    ) Error!void {
        try self.prepareSectionAcknowledgments(count);
        self.acknowledgeSectionsAssumeCapacity(stream_id, count);
    }

    pub fn prepareSectionAcknowledgments(
        self: *QpackDecodeState,
        count: usize,
    ) std.mem.Allocator.Error!void {
        try self.decoder_instructions.ensureUnusedCapacity(
            self.allocator,
            11 *| count,
        );
    }

    pub fn acknowledgeSectionsAssumeCapacity(
        self: *QpackDecodeState,
        stream_id: u64,
        count: usize,
    ) void {
        for (0..count) |_| {
            http3.Qpack.writeDecoderInstruction(
                &self.decoder_instructions,
                self.allocator,
                .{ .section_acknowledgment = stream_id },
            ) catch unreachable;
        }
    }

    pub fn recordStreamCancellation(
        self: *QpackDecodeState,
        stream_id: u64,
    ) Error!void {
        try self.prepareStreamCancellation();
        self.recordStreamCancellationAssumeCapacity(stream_id);
    }

    pub fn prepareStreamCancellation(
        self: *QpackDecodeState,
    ) std.mem.Allocator.Error!void {
        try self.decoder_instructions.ensureUnusedCapacity(
            self.allocator,
            11,
        );
    }

    pub fn recordStreamCancellationAssumeCapacity(
        self: *QpackDecodeState,
        stream_id: u64,
    ) void {
        http3.Qpack.writeDecoderInstruction(
            &self.decoder_instructions,
            self.allocator,
            .{ .stream_cancellation = stream_id },
        ) catch unreachable;
    }

    fn recordInsertCount(self: *QpackDecodeState, inserted: u64) Error!void {
        const next = std.math.add(u64, self.acknowledged_insert_count, inserted) catch
            return error.QpackDecoderStreamError;
        try http3.Qpack.writeDecoderInstruction(
            &self.decoder_instructions,
            self.allocator,
            .{ .insert_count_increment = inserted },
        );
        self.acknowledged_insert_count = next;
    }
};

fn applyDecodedEncoderInstruction(
    table: *http3.Qpack.DynamicTable,
    instruction: http3.Qpack.EncoderInstruction,
) Error!void {
    switch (instruction) {
        .set_capacity => |capacity| try table.setCapacity(
            std.math.cast(usize, capacity) orelse return error.QpackEncoderStreamError,
        ),
        .duplicate => |index| _ = try table.duplicate(index),
        .insert_literal => |literal| _ = try table.insert(literal.name, literal.value),
        .insert_name_reference => |reference| {
            const name = if (reference.static) blk: {
                const entry = http3.Qpack.staticEntry(
                    std.math.cast(usize, reference.name_index) orelse
                        return error.QpackEncoderStreamError,
                ) orelse return error.QpackEncoderStreamError;
                break :blk entry.name;
            } else blk: {
                const entry = table.relative(reference.name_index) orelse
                    return error.QpackEncoderStreamError;
                break :blk entry.name;
            };
            _ = try table.insert(name, reference.value);
        },
    }
}

pub const QpackEncodeState = struct {
    const PendingSection = struct {
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
        const reference_limit = if (self.mayRiskBlockedStream(stream_id))
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
            .stream_id = stream_id,
            .required_insert_count = required_insert_count,
            .references = owned,
        });
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

    pub fn abandonStream(self: *QpackEncodeState, stream_id: u64) void {
        _ = self.releaseSectionsForStream(stream_id);
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
