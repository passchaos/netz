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
        const starting_insert_count = self.table.insert_count;
        // Earlier instructions remain committed when a later decode or
        // insertion fails. Their feedback must survive that return as well.
        defer if (self.table.insert_count != starting_insert_count) {
            self.recordInsertCountAssumeCapacity(self.table.insert_count - starting_insert_count);
        };
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
            applyDecodedEncoderInstruction(&self.table, decoded.instruction) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return error.QpackEncoderStreamError,
            };
            try receive.consume(decoded.consumed);
        }
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

    fn recordInsertCountAssumeCapacity(self: *QpackDecodeState, inserted: u64) void {
        const next = std.math.add(u64, self.acknowledged_insert_count, inserted) catch
            unreachable;
        http3.Qpack.writeDecoderInstruction(
            &self.decoder_instructions,
            self.allocator,
            .{ .insert_count_increment = inserted },
        ) catch unreachable;
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

pub const QpackEncodeState = @import("encoder.zig").QpackEncodeState;
