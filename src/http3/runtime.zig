const std = @import("std");
const http3 = @import("mod.zig");
const quic = @import("../quic/mod.zig");

const net = std.Io.net;

pub const Error = http3.Error || quic.runtime.Error || quic.handshake.Error || quic.one_rtt.Error || quic.stream_state.Error || error{
    MissingStreamFrame,
    UnexpectedStream,
    GoAwayReceived,
    RequestRejected,
    ClosedCriticalStream,
};

const client_control_stream_id: u62 = 2;
const client_qpack_encoder_stream_id: u62 = 6;
const client_qpack_decoder_stream_id: u62 = 10;
const server_control_stream_id: u62 = 3;
const server_qpack_encoder_stream_id: u62 = 7;
const server_qpack_decoder_stream_id: u62 = 11;

pub const Limits = struct {
    quic: quic.runtime.Limits = .{},
    /// Maximum bytes buffered while reassembling one HTTP/3 request/response
    /// stream in the cleartext development runtime.  Protected/handshake
    /// runtimes already expose this via their session options; keeping the
    /// cleartext path explicit prevents large STREAM offsets from turning the
    /// UDP frame endpoint into an unbounded message buffer.
    max_stream_buffer: usize = 64 * 1024,
    /// Maximum payload bytes per QUIC STREAM frame emitted by the cleartext
    /// development runtime.  Keeping this separate from UDP datagram size lets
    /// tests and callers exercise normal HTTP/3 body fragmentation like tquic's
    /// `send_body` path instead of requiring one whole message to fit in a
    /// single UDP frame datagram.
    max_stream_frame_data: usize = 1200,
};

/// Connection-scoped receive side of QPACK.
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
        self.table.deinit();
        self.decoder_instructions.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn applyEncoderStreamFrame(
        self: *QpackDecodeState,
        control: *http3.ControlState,
        stream: quic.StreamFrame,
    ) Error!void {
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

    pub fn acknowledgeSections(
        self: *QpackDecodeState,
        stream_id: u64,
        count: usize,
    ) Error!void {
        try self.decoder_instructions.ensureUnusedCapacity(
            self.allocator,
            11 *| count,
        );
        for (0..count) |_| {
            try http3.Qpack.writeDecoderInstruction(
                &self.decoder_instructions,
                self.allocator,
                .{ .section_acknowledgment = stream_id },
            );
        }
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
    reference_counts: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    encoder_instructions: std.ArrayList(u8) = .empty,
    decoder_stream: ?quic.stream_state.RecvState = null,
    decoder_stream_type_received: bool = false,
    max_stream_buffer: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        peer_max_capacity: usize,
        max_stream_buffer: usize,
    ) QpackEncodeState {
        return .{
            .allocator = allocator,
            .table = .init(allocator, peer_max_capacity),
            .max_stream_buffer = max_stream_buffer,
        };
    }

    pub fn deinit(self: *QpackEncodeState) void {
        if (self.decoder_stream) |*stream| stream.deinit();
        for (self.pending_sections.items) |*section| section.deinit(self.allocator);
        self.pending_sections.deinit(self.allocator);
        self.reference_counts.deinit(self.allocator);
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
        try http3.Qpack.encodeDynamicBlockKnownReceived(
            list,
            self.allocator,
            fields,
            self.table,
            self.known_received_count,
            &references,
        );
        if (references.items.len == 0) {
            references.deinit(self.allocator);
            return;
        }

        const owned = try references.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(owned);
        try self.pending_sections.ensureUnusedCapacity(self.allocator, 1);
        var new_reference_count_entries: usize = 0;
        for (owned) |absolute_index| {
            if (!self.reference_counts.contains(absolute_index)) {
                new_reference_count_entries += 1;
            }
        }
        try self.reference_counts.ensureUnusedCapacity(
            self.allocator,
            std.math.cast(u32, new_reference_count_entries) orelse
                return error.OutOfMemory,
        );
        for (owned) |absolute_index| {
            const entry = self.reference_counts.getOrPutAssumeCapacity(
                absolute_index,
            );
            if (!entry.found_existing) entry.value_ptr.* = 0;
            entry.value_ptr.* += 1;
        }
        self.pending_sections.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .required_insert_count = maxReferencedInsertCount(owned),
            .references = owned,
        });
    }

    pub fn applyDecoderStreamFrame(
        self: *QpackEncodeState,
        control: *http3.ControlState,
        stream: quic.StreamFrame,
    ) Error!void {
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
            },
            .stream_cancellation => |stream_id| {
                var index: usize = 0;
                var found = false;
                while (index < self.pending_sections.items.len) {
                    if (self.pending_sections.items[index].stream_id != stream_id) {
                        index += 1;
                        continue;
                    }
                    self.releaseSection(index);
                    found = true;
                }
                if (!found) return error.QpackDecoderStreamError;
            },
        }
    }

    fn findPendingSection(self: QpackEncodeState, stream_id: u64) ?usize {
        for (self.pending_sections.items, 0..) |section, index| {
            if (section.stream_id == stream_id) return index;
        }
        return null;
    }

    fn releaseSection(self: *QpackEncodeState, index: usize) void {
        var section = self.pending_sections.orderedRemove(index);
        for (section.references) |absolute_index| {
            const count = self.reference_counts.getPtr(absolute_index).?;
            count.* -= 1;
            if (count.* == 0) _ = self.reference_counts.remove(absolute_index);
        }
        section.deinit(self.allocator);
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
        return absolute_index < self.known_received_count and
            !self.reference_counts.contains(absolute_index);
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
    for (http3.Qpack.static_table, 0..) |entry, index| {
        if (std.mem.eql(u8, entry.name, name)) return @intCast(index);
    }
    return null;
}

pub const Server = struct {
    quic_server: quic.runtime.Server,
    limits: Limits = .{},

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{ .quic_server = try .bind(allocator, io, bind_address, limits.quic), .limits = limits };
    }

    pub fn deinit(self: *Server) void {
        self.quic_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn receiveRequest(self: *Server) Error!OwnedRequest {
        var assembled = try receiveRuntimeStreamBytes(&self.quic_server.endpoint, null, self.limits.max_stream_buffer);
        errdefer assembled.deinit(self.quic_server.endpoint.allocator);
        var request = try http3.decodeRequest(self.quic_server.endpoint.allocator, assembled.bytes);
        errdefer request.deinit(self.quic_server.endpoint.allocator);
        const owned_parts = try assembled.intoOwnedParts(self.quic_server.endpoint.allocator);
        return .{
            .from = assembled.from,
            .stream_id = assembled.stream_id,
            .datagram = owned_parts.datagram,
            .extra_datagrams = owned_parts.extra_datagrams,
            .bytes = owned_parts.bytes,
            .request = request,
        };
    }

    pub fn receiveRequestsConcurrent(self: *Server, count: usize) Error!OwnedRequestBatch {
        var group: std.Io.Group = .init;
        const requests = try self.quic_server.endpoint.allocator.alloc(?OwnedRequest, count);
        errdefer self.quic_server.endpoint.allocator.free(requests);
        @memset(requests, null);
        const errors = try self.quic_server.endpoint.allocator.alloc(?anyerror, count);
        errdefer self.quic_server.endpoint.allocator.free(errors);
        @memset(errors, null);

        for (requests, errors) |*request, *err_slot| {
            const task = RequestTask{
                .server = self,
                .request = request,
                .err = err_slot,
            };
            group.async(self.quic_server.endpoint.io, RequestTask.run, .{task});
        }

        try group.await(self.quic_server.endpoint.io);
        return .{ .allocator = self.quic_server.endpoint.allocator, .requests = requests, .errors = errors };
    }

    pub fn sendResponse(self: *Server, to: net.IpAddress, stream_id: u62, response: http3.Response) Error!void {
        try self.sendResponseWithInformational(to, stream_id, &.{}, response);
    }

    pub fn sendResponseWithInformational(
        self: *Server,
        to: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
    ) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_server.endpoint.allocator);
        try http3.writeResponseSequence(&encoded, self.quic_server.endpoint.allocator, informational, response);
        try sendRuntimeStreamMessage(&self.quic_server.endpoint, to, stream_id, encoded.items, self.limits.max_stream_frame_data);
    }
};

const RequestTask = struct {
    server: *Server,
    request: *?OwnedRequest,
    err: *?anyerror,

    fn run(task: RequestTask) std.Io.Cancelable!void {
        task.request.* = task.server.receiveRequest() catch |err| {
            task.err.* = err;
            return;
        };
        task.err.* = null;
    }
};

pub const Client = struct {
    quic_client: quic.runtime.Client,
    limits: Limits = .{},
    next_stream_id: u62 = 0,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits) Error!Client {
        return .{ .quic_client = try .connect(allocator, io, local_address, server, limits.quic), .limits = limits };
    }

    pub fn deinit(self: *Client) void {
        self.quic_client.deinit();
        self.* = undefined;
    }

    pub fn address(self: Client) net.IpAddress {
        return self.quic_client.address();
    }

    pub fn request(self: *Client, request_options: http3.Request) Error!OwnedResponse {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 4; // client-initiated bidirectional stream ids.

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_client.endpoint.allocator);
        try request_options.write(&encoded, self.quic_client.endpoint.allocator);

        try sendRuntimeStreamMessage(&self.quic_client.endpoint, self.quic_client.peer, stream_id, encoded.items, self.limits.max_stream_frame_data);

        var assembled = try receiveRuntimeStreamBytes(&self.quic_client.endpoint, stream_id, self.limits.max_stream_buffer);
        errdefer assembled.deinit(self.quic_client.endpoint.allocator);
        try http3.validateResponsePushPromises(.{}, assembled.bytes);
        var response = try http3.decodeResponse(self.quic_client.endpoint.allocator, assembled.bytes);
        errdefer response.deinit(self.quic_client.endpoint.allocator);
        const owned_parts = try assembled.intoOwnedParts(self.quic_client.endpoint.allocator);
        return .{
            .datagram = owned_parts.datagram,
            .extra_datagrams = owned_parts.extra_datagrams,
            .bytes = owned_parts.bytes,
            .response = response,
        };
    }
};

const RuntimeAssembledStream = struct {
    from: net.IpAddress,
    stream_id: u62,
    bytes: []u8,
    datagrams: []quic.runtime.OwnedDatagram,

    fn deinit(self: *RuntimeAssembledStream, allocator: std.mem.Allocator) void {
        for (self.datagrams) |*datagram| datagram.deinit(allocator);
        allocator.free(self.datagrams);
        allocator.free(self.bytes);
        self.* = undefined;
    }

    fn intoOwnedParts(self: *RuntimeAssembledStream, allocator: std.mem.Allocator) std.mem.Allocator.Error!struct {
        datagram: quic.runtime.OwnedDatagram,
        extra_datagrams: []quic.runtime.OwnedDatagram,
        bytes: []u8,
    } {
        std.debug.assert(self.datagrams.len != 0);
        const extra_datagrams = try allocator.alloc(quic.runtime.OwnedDatagram, self.datagrams.len - 1);
        @memcpy(extra_datagrams, self.datagrams[1..]);
        const datagram = self.datagrams[0];
        allocator.free(self.datagrams);
        self.datagrams = &.{};
        const bytes = self.bytes;
        self.bytes = &.{};
        return .{ .datagram = datagram, .extra_datagrams = extra_datagrams, .bytes = bytes };
    }
};

fn sendRuntimeStreamMessage(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    stream_id: u62,
    bytes: []const u8,
    max_stream_frame_data: usize,
) Error!void {
    var send_state = quic.stream_state.SendState.init(stream_id);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try send_state.appendFrames(&frames, endpoint.allocator, bytes, max_stream_frame_data, true);
    for (frames.items) |frame| {
        try endpoint.sendFrames(to, &.{frame});
    }
}

fn receiveRuntimeStreamBytes(endpoint: *quic.runtime.Endpoint, expected_stream_id: ?u62, max_stream_buffer: usize) Error!RuntimeAssembledStream {
    var recv: ?quic.stream_state.RecvState = null;
    defer if (recv) |*state| state.deinit();
    var datagrams: std.ArrayList(quic.runtime.OwnedDatagram) = .empty;
    errdefer {
        for (datagrams.items) |*datagram| datagram.deinit(endpoint.allocator);
        datagrams.deinit(endpoint.allocator);
    }
    var from: ?net.IpAddress = null;
    var stream_id: ?u62 = expected_stream_id;

    while (true) {
        var datagram = try endpoint.receive();
        var datagram_owned = true;
        errdefer if (datagram_owned) datagram.deinit(endpoint.allocator);
        if (from == null) from = datagram.from;

        var consumed = false;
        for (datagram.frames) |frame| {
            if (frame != .stream) continue;
            switch (try messageStreamDisposition(frame.stream.stream_id)) {
                .ignore => continue,
                .request_response => {},
            }
            const incoming_id: u62 = @intCast(frame.stream.stream_id);
            if (stream_id) |id| {
                if (incoming_id != id) {
                    if (expected_stream_id != null) return error.UnexpectedStream;
                    continue;
                }
            } else {
                stream_id = incoming_id;
            }
            if (recv == null) recv = quic.stream_state.RecvState.init(endpoint.allocator, incoming_id, max_stream_buffer);
            if (recv) |*state| {
                try state.insert(frame.stream);
                consumed = true;
                if (state.final_size != null and state.contiguous_end >= state.final_size.?) {
                    const bytes = try endpoint.allocator.dupe(u8, state.buffer.items[0..state.final_size.?]);
                    errdefer endpoint.allocator.free(bytes);
                    try datagrams.append(endpoint.allocator, datagram);
                    datagram_owned = false;
                    return .{
                        .from = from.?,
                        .stream_id = stream_id.?,
                        .bytes = bytes,
                        .datagrams = try datagrams.toOwnedSlice(endpoint.allocator),
                    };
                }
            }
        }

        if (consumed) {
            try datagrams.append(endpoint.allocator, datagram);
            datagram_owned = false;
        } else {
            datagram.deinit(endpoint.allocator);
            datagram_owned = false;
        }
    }
}

pub const OwnedRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    datagram: quic.runtime.OwnedDatagram,
    extra_datagrams: []quic.runtime.OwnedDatagram = &.{},
    bytes: []u8 = &.{},
    request: http3.DecodedRequest,

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.datagram.deinit(allocator);
        for (self.extra_datagrams) |*datagram| datagram.deinit(allocator);
        allocator.free(self.extra_datagrams);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const OwnedRequestBatch = struct {
    allocator: std.mem.Allocator,
    requests: []?OwnedRequest,
    errors: []?anyerror,

    pub fn deinit(self: *OwnedRequestBatch) void {
        for (self.requests) |*request| {
            if (request.*) |*owned| owned.deinit(self.allocator);
        }
        self.allocator.free(self.requests);
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: OwnedRequestBatch) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn receivedCount(self: OwnedRequestBatch) usize {
        var count: usize = 0;
        for (self.requests) |request| {
            if (request != null) count += 1;
        }
        return count;
    }
};

pub const OwnedResponse = struct {
    datagram: quic.runtime.OwnedDatagram,
    extra_datagrams: []quic.runtime.OwnedDatagram = &.{},
    bytes: []u8 = &.{},
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        self.datagram.deinit(allocator);
        for (self.extra_datagrams) |*datagram| datagram.deinit(allocator);
        allocator.free(self.extra_datagrams);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const ProtectedConfig = struct {
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    local_settings: http3.Settings = .{},
    max_frames_per_packet: usize = 8,
    max_stream_buffer: usize = 64 * 1024,
    max_stream_frame_data: usize = 1200,
};

pub const HandshakeSessionOptions = struct {
    local_settings: http3.Settings = .{},
    max_frames_per_packet: usize = 8,
    max_stream_buffer: usize = 64 * 1024,
    max_stream_frame_data: usize = 1200,
};

pub const HandshakeServerOptions = struct {
    handshake: quic.handshake.ServerOptions,
    session: HandshakeSessionOptions = .{},
};

pub const HandshakeClientOptions = struct {
    handshake: quic.handshake.ClientOptions,
    session: HandshakeSessionOptions = .{},
};

pub const HandshakeServer = struct {
    quic_server: quic.runtime.Server,
    allocator: std.mem.Allocator,
    handshake_options: quic.handshake.ServerOptions,
    session_options: HandshakeSessionOptions,
    local_connection_id: []u8,
    alpn_protocol: []u8,
    transport_parameters: []u8,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits, options: HandshakeServerOptions) Error!HandshakeServer {
        var quic_server = try quic.runtime.Server.bind(allocator, io, bind_address, limits.quic);
        errdefer quic_server.deinit();

        const local_connection_id = try allocator.dupe(u8, options.handshake.local_connection_id);
        errdefer allocator.free(local_connection_id);
        const alpn_protocol = try allocator.dupe(u8, options.handshake.alpn_protocol);
        errdefer allocator.free(alpn_protocol);
        const transport_parameters = try allocator.dupe(u8, options.handshake.transport_parameters);
        errdefer allocator.free(transport_parameters);

        var handshake_options = options.handshake;
        handshake_options.local_connection_id = local_connection_id;
        handshake_options.alpn_protocol = alpn_protocol;
        handshake_options.transport_parameters = transport_parameters;

        return .{
            .quic_server = quic_server,
            .allocator = allocator,
            .handshake_options = handshake_options,
            .session_options = options.session,
            .local_connection_id = local_connection_id,
            .alpn_protocol = alpn_protocol,
            .transport_parameters = transport_parameters,
        };
    }

    pub fn deinit(self: *HandshakeServer) void {
        self.quic_server.deinit();
        self.allocator.free(self.local_connection_id);
        self.allocator.free(self.alpn_protocol);
        self.allocator.free(self.transport_parameters);
        self.* = undefined;
    }

    pub fn address(self: HandshakeServer) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn accept(self: *HandshakeServer) Error!HandshakeServerSession {
        var established = try quic.handshake.accept(&self.quic_server.endpoint, self.handshake_options);
        errdefer established.deinit();
        const max_capacity = std.math.cast(
            usize,
            self.session_options.local_settings.qpack_max_table_capacity,
        ) orelse return error.InvalidSetting;
        return .{
            .established = established,
            .options = self.session_options,
            .qpack_decode = .init(
                established.connection.endpoint.allocator,
                max_capacity,
                self.session_options.max_stream_buffer,
            ),
        };
    }
};

pub const HandshakeServerSession = struct {
    established: quic.handshake.EstablishedConnection,
    options: HandshakeSessionOptions,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,

    pub fn deinit(self: *HandshakeServerSession) void {
        self.qpack_decode.deinit();
        self.established.deinit();
        self.* = undefined;
    }

    pub fn receiveRequest(self: *HandshakeServerSession) Error!OwnedHandshakeRequest {
        const assembled = try receiveConnectionStreamBytes(
            &self.established.connection,
            null,
            self.options,
            &self.control,
            &self.qpack_decode,
            .server,
        );
        errdefer self.established.connection.endpoint.allocator.free(assembled.bytes);
        var request = try http3.decodeRequestWithDynamicTable(
            self.established.connection.endpoint.allocator,
            assembled.bytes,
            self.options.local_settings,
            self.qpack_decode.table,
        );
        errdefer request.deinit(self.established.connection.endpoint.allocator);
        try self.qpack_decode.acknowledgeSections(
            assembled.stream_id,
            request.qpack_section_acknowledgments,
        );
        try self.sendQpackFeedback();
        return .{
            .from = assembled.from,
            .stream_id = assembled.stream_id,
            .stream_bytes = assembled.bytes,
            .request = request,
        };
    }

    pub fn sendResponse(self: *HandshakeServerSession, stream_id: u62, response: http3.Response) Error!void {
        try self.sendResponseWithInformational(stream_id, &.{}, response);
    }

    pub fn sendResponseWithInformational(
        self: *HandshakeServerSession,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
    ) Error!void {
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            server_control_stream_id,
        );
        try sendConnectionResponseSequence(&self.established.connection, stream_id, informational, response, self.options, self.control.settings.peer);
    }

    pub fn sendGoAway(self: *HandshakeServerSession, stream_id: u64) Error!void {
        try validateServerGoAwayStreamId(stream_id);
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            server_control_stream_id,
        );
        try sendConnectionControlFrame(&self.established.connection, &self.control, &self.control_send, self.options, .goaway, stream_id);
    }

    fn sendQpackFeedback(self: *HandshakeServerSession) Error!void {
        try sendConnectionQpackFeedback(
            &self.established.connection,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options.max_frames_per_packet,
        );
    }
};

pub const HandshakeClient = struct {
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    allocator: std.mem.Allocator,
    established: quic.handshake.EstablishedConnection,
    options: HandshakeSessionOptions,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,
    next_stream_id: u62 = 0,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits, options: HandshakeClientOptions) Error!HandshakeClient {
        const endpoint = try allocator.create(quic.runtime.Endpoint);
        errdefer allocator.destroy(endpoint);
        endpoint.* = try quic.runtime.Endpoint.bind(allocator, io, local_address, limits.quic);
        errdefer endpoint.deinit();

        var established = try quic.handshake.connect(endpoint, server, options.handshake);
        errdefer established.deinit();
        const max_capacity = std.math.cast(
            usize,
            options.session.local_settings.qpack_max_table_capacity,
        ) orelse return error.InvalidSetting;
        return .{
            .endpoint = endpoint,
            .peer = server,
            .allocator = allocator,
            .established = established,
            .options = options.session,
            .qpack_decode = .init(
                allocator,
                max_capacity,
                options.session.max_stream_buffer,
            ),
        };
    }

    pub fn deinit(self: *HandshakeClient) void {
        self.qpack_decode.deinit();
        self.established.deinit();
        self.endpoint.deinit();
        self.allocator.destroy(self.endpoint);
        self.* = undefined;
    }

    pub fn address(self: HandshakeClient) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn request(self: *HandshakeClient, request_options: http3.Request) Error!OwnedHandshakeResponse {
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) return error.GoAwayReceived;
        self.next_stream_id += 4;

        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
        try sendConnectionMessage(&self.established.connection, stream_id, request_options, self.options, self.control.settings.peer);
        const assembled = try receiveConnectionStreamBytes(
            &self.established.connection,
            stream_id,
            self.options,
            &self.control,
            &self.qpack_decode,
            .client,
        );
        errdefer self.established.connection.endpoint.allocator.free(assembled.bytes);
        try http3.validateResponsePushPromises(self.control, assembled.bytes);
        var response = try http3.decodeResponseWithDynamicTable(
            self.established.connection.endpoint.allocator,
            assembled.bytes,
            self.control.settings.local,
            self.qpack_decode.table,
        );
        errdefer response.deinit(self.established.connection.endpoint.allocator);
        try self.qpack_decode.acknowledgeSections(
            assembled.stream_id,
            response.qpack_section_acknowledgments,
        );
        try self.sendQpackFeedback();
        return .{ .stream_bytes = assembled.bytes, .response = response };
    }

    pub fn sendGoAway(self: *HandshakeClient, stream_id: u64) Error!void {
        try validateClientGoAwayPushId(stream_id);
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
        try sendConnectionControlFrame(&self.established.connection, &self.control, &self.control_send, self.options, .goaway, stream_id);
    }

    fn sendQpackFeedback(self: *HandshakeClient) Error!void {
        try sendConnectionQpackFeedback(
            &self.established.connection,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options.max_frames_per_packet,
        );
    }
};

pub const OwnedHandshakeRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    stream_bytes: []u8,
    request: http3.DecodedRequest,

    pub fn deinit(self: *OwnedHandshakeRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedHandshakeResponse = struct {
    stream_bytes: []u8,
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedHandshakeResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const ProtectedServer = struct {
    quic_server: quic.runtime.Server,
    config: ProtectedConfig,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits, config: ProtectedConfig) Error!ProtectedServer {
        var quic_server = try quic.runtime.Server.bind(allocator, io, bind_address, limits.quic);
        errdefer quic_server.deinit();
        const max_capacity = std.math.cast(usize, config.local_settings.qpack_max_table_capacity) orelse
            return error.InvalidSetting;
        return .{
            .quic_server = quic_server,
            .config = config,
            .qpack_decode = .init(allocator, max_capacity, config.max_stream_buffer),
        };
    }

    pub fn deinit(self: *ProtectedServer) void {
        self.qpack_decode.deinit();
        self.quic_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: ProtectedServer) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn receiveRequest(self: *ProtectedServer) Error!OwnedProtectedRequest {
        const assembled = try self.receiveStreamBytes(null);
        errdefer self.quic_server.endpoint.allocator.free(assembled.bytes);
        var request = try http3.decodeRequestWithDynamicTable(
            self.quic_server.endpoint.allocator,
            assembled.bytes,
            self.config.local_settings,
            self.qpack_decode.table,
        );
        errdefer request.deinit(self.quic_server.endpoint.allocator);
        try self.qpack_decode.acknowledgeSections(
            assembled.stream_id,
            request.qpack_section_acknowledgments,
        );
        try self.sendQpackFeedback(assembled.from);
        return .{
            .from = assembled.from,
            .stream_id = assembled.stream_id,
            .stream_bytes = assembled.bytes,
            .request = request,
        };
    }

    pub fn sendResponse(self: *ProtectedServer, to: net.IpAddress, stream_id: u62, response: http3.Response) Error!void {
        try self.sendResponseWithInformational(to, stream_id, &.{}, response);
    }

    pub fn sendResponseWithInformational(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
    ) Error!void {
        try sendProtectedSettings(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            server_control_stream_id,
        );
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_server.endpoint.allocator);
        try http3.writeResponseSequenceWithSettings(&encoded, self.quic_server.endpoint.allocator, informational, response, self.control.settings.peer);
        var send_state = quic.stream_state.SendState.init(stream_id);
        var frames: std.ArrayList(quic.Frame) = .empty;
        defer frames.deinit(self.quic_server.endpoint.allocator);
        try send_state.appendFrames(&frames, self.quic_server.endpoint.allocator, encoded.items, self.config.max_stream_frame_data, true);
        try sendProtectedFrames(
            &self.quic_server.endpoint,
            to,
            self.config.send_keys,
            self.config.peer_connection_id,
            &self.next_packet_number,
            frames.items,
            self.config.max_frames_per_packet,
        );
    }

    pub fn sendGoAway(self: *ProtectedServer, to: net.IpAddress, stream_id: u64) Error!void {
        try validateServerGoAwayStreamId(stream_id);
        try sendProtectedSettings(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            server_control_stream_id,
        );
        try sendProtectedControlFrame(&self.quic_server.endpoint, to, self.config, &self.control, &self.control_send, &self.next_packet_number, .goaway, stream_id);
    }

    fn receiveStreamBytes(self: *ProtectedServer, expected_stream_id: ?u62) Error!AssembledStream {
        var recv: ?quic.stream_state.RecvState = null;
        defer if (recv) |*state| state.deinit();
        var from: ?net.IpAddress = null;
        var stream_id: ?u62 = expected_stream_id;

        while (true) {
            var packet = try quic.one_rtt.receive(
                &self.quic_server.endpoint,
                self.config.receive_keys,
                self.config.local_connection_id.len,
                self.expected_packet_number,
                self.config.max_frames_per_packet,
            );
            defer packet.deinit(self.quic_server.endpoint.allocator);
            self.expected_packet_number = packet.packet.packet_number + 1;
            if (from == null) from = packet.from;

            for (packet.frames) |frame| {
                try rejectCriticalStreamClosureFrame(self.control, frame, .server);
                if (frame != .stream) continue;
                if ((frame.stream.stream_id & 0x02) != 0 and
                    ((self.qpack_decode.encoder_stream != null and
                        self.qpack_decode.encoder_stream.?.stream_id ==
                            frame.stream.stream_id) or
                        frame.stream.stream_id == client_qpack_encoder_stream_id or
                        (frame.stream.offset == 0 and
                            peekUniStreamType(frame.stream) == .qpack_encoder)))
                {
                    try self.qpack_decode.applyEncoderStreamFrame(
                        &self.control,
                        frame.stream,
                    );
                    continue;
                }
                if (try applyControlStreamFrameForRole(&self.control, self.quic_server.endpoint.allocator, frame.stream, .server)) continue;
                if ((try messageStreamDisposition(frame.stream.stream_id)) == .ignore) continue;
                const incoming_id: u62 = @intCast(frame.stream.stream_id);
                if (!self.control.acceptsLocalRequestStream(incoming_id)) return error.RequestRejected;
                if (stream_id) |id| {
                    if (incoming_id != id) continue;
                } else {
                    stream_id = incoming_id;
                    recv = quic.stream_state.RecvState.init(self.quic_server.endpoint.allocator, incoming_id, self.config.max_stream_buffer);
                }
                if (recv == null) recv = quic.stream_state.RecvState.init(self.quic_server.endpoint.allocator, incoming_id, self.config.max_stream_buffer);
                if (recv) |*state| {
                    try state.insert(frame.stream);
                    if (state.final_size != null and state.contiguous_end >= state.final_size.?) {
                        const bytes = try self.quic_server.endpoint.allocator.dupe(u8, state.buffer.items[0..state.final_size.?]);
                        return .{ .from = from.?, .stream_id = stream_id.?, .bytes = bytes };
                    }
                }
            }
        }
    }

    fn sendQpackFeedback(self: *ProtectedServer, to: net.IpAddress) Error!void {
        try sendProtectedQpackFeedback(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
        );
    }
};

pub const ProtectedClient = struct {
    quic_client: quic.runtime.Client,
    config: ProtectedConfig,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,
    next_stream_id: u62 = 0,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits, config: ProtectedConfig) Error!ProtectedClient {
        var quic_client = try quic.runtime.Client.connect(allocator, io, local_address, server, limits.quic);
        errdefer quic_client.deinit();
        const max_capacity = std.math.cast(usize, config.local_settings.qpack_max_table_capacity) orelse
            return error.InvalidSetting;
        return .{
            .quic_client = quic_client,
            .config = config,
            .qpack_decode = .init(allocator, max_capacity, config.max_stream_buffer),
        };
    }

    pub fn deinit(self: *ProtectedClient) void {
        self.qpack_decode.deinit();
        self.quic_client.deinit();
        self.* = undefined;
    }

    pub fn request(self: *ProtectedClient, request_options: http3.Request) Error!OwnedProtectedResponse {
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) return error.GoAwayReceived;
        self.next_stream_id += 4;

        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            client_control_stream_id,
        );
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_client.endpoint.allocator);
        try request_options.writeWithSettings(&encoded, self.quic_client.endpoint.allocator, self.control.settings.peer);
        var send_state = quic.stream_state.SendState.init(stream_id);
        var frames: std.ArrayList(quic.Frame) = .empty;
        defer frames.deinit(self.quic_client.endpoint.allocator);
        try send_state.appendFrames(&frames, self.quic_client.endpoint.allocator, encoded.items, self.config.max_stream_frame_data, true);
        try sendProtectedFrames(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config.send_keys,
            self.config.peer_connection_id,
            &self.next_packet_number,
            frames.items,
            self.config.max_frames_per_packet,
        );

        const assembled = try self.receiveStreamBytes(stream_id);
        errdefer self.quic_client.endpoint.allocator.free(assembled.bytes);
        try http3.validateResponsePushPromises(self.control, assembled.bytes);
        var response = try http3.decodeResponseWithDynamicTable(
            self.quic_client.endpoint.allocator,
            assembled.bytes,
            self.control.settings.local,
            self.qpack_decode.table,
        );
        errdefer response.deinit(self.quic_client.endpoint.allocator);
        try self.qpack_decode.acknowledgeSections(
            assembled.stream_id,
            response.qpack_section_acknowledgments,
        );
        try self.sendQpackFeedback();
        return .{ .stream_bytes = assembled.bytes, .response = response };
    }

    pub fn sendGoAway(self: *ProtectedClient, stream_id: u64) Error!void {
        try validateClientGoAwayPushId(stream_id);
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            client_control_stream_id,
        );
        try sendProtectedControlFrame(&self.quic_client.endpoint, self.quic_client.peer, self.config, &self.control, &self.control_send, &self.next_packet_number, .goaway, stream_id);
    }

    fn receiveStreamBytes(self: *ProtectedClient, expected_stream_id: u62) Error!AssembledStream {
        var recv = quic.stream_state.RecvState.init(self.quic_client.endpoint.allocator, expected_stream_id, self.config.max_stream_buffer);
        defer recv.deinit();
        var from: ?net.IpAddress = null;
        while (true) {
            var packet = try quic.one_rtt.receive(
                &self.quic_client.endpoint,
                self.config.receive_keys,
                self.config.local_connection_id.len,
                self.expected_packet_number,
                self.config.max_frames_per_packet,
            );
            defer packet.deinit(self.quic_client.endpoint.allocator);
            self.expected_packet_number = packet.packet.packet_number + 1;
            if (from == null) from = packet.from;
            for (packet.frames) |frame| {
                try rejectCriticalStreamClosureFrame(self.control, frame, .client);
                if (frame == .stream and
                    (frame.stream.stream_id & 0x02) != 0 and
                    ((self.qpack_decode.encoder_stream != null and
                        self.qpack_decode.encoder_stream.?.stream_id ==
                            frame.stream.stream_id) or
                        frame.stream.stream_id == server_qpack_encoder_stream_id or
                        (frame.stream.offset == 0 and
                            peekUniStreamType(frame.stream) == .qpack_encoder)))
                {
                    try self.qpack_decode.applyEncoderStreamFrame(
                        &self.control,
                        frame.stream,
                    );
                    continue;
                }
                if (frame == .stream and try applyControlStreamFrameForRole(&self.control, self.quic_client.endpoint.allocator, frame.stream, .client)) continue;
                if (frame == .stream and (try messageStreamDisposition(frame.stream.stream_id)) == .ignore) continue;
                if (frame != .stream or frame.stream.stream_id != expected_stream_id) continue;
                try recv.insert(frame.stream);
                if (recv.final_size != null and recv.contiguous_end >= recv.final_size.?) {
                    const bytes = try self.quic_client.endpoint.allocator.dupe(u8, recv.buffer.items[0..recv.final_size.?]);
                    return .{ .from = from.?, .stream_id = expected_stream_id, .bytes = bytes };
                }
            }
        }
    }

    fn sendQpackFeedback(self: *ProtectedClient) Error!void {
        try sendProtectedQpackFeedback(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
        );
    }
};

pub const OwnedProtectedRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    stream_bytes: []u8,
    request: http3.DecodedRequest,

    pub fn deinit(self: *OwnedProtectedRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedProtectedResponse = struct {
    stream_bytes: []u8,
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedProtectedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

const AssembledStream = struct {
    from: net.IpAddress,
    stream_id: u62,
    bytes: []u8,
};

fn sendConnectionMessage(connection: *quic.one_rtt.Connection, stream_id: u62, request: http3.Request, options: HandshakeSessionOptions, peer_settings: http3.Settings) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(connection.endpoint.allocator);
    try request.writeWithSettings(&encoded, connection.endpoint.allocator, peer_settings);

    var send_state = quic.stream_state.SendState.init(stream_id);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try send_state.appendFrames(&frames, connection.endpoint.allocator, encoded.items, options.max_stream_frame_data, true);
    try sendConnectionFrames(connection, frames.items, options.max_frames_per_packet);
}

fn sendConnectionResponseSequence(
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
    informational: []const http3.InformationalResponse,
    response: http3.Response,
    options: HandshakeSessionOptions,
    peer_settings: http3.Settings,
) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(connection.endpoint.allocator);
    try http3.writeResponseSequenceWithSettings(&encoded, connection.endpoint.allocator, informational, response, peer_settings);

    var send_state = quic.stream_state.SendState.init(stream_id);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try send_state.appendFrames(&frames, connection.endpoint.allocator, encoded.items, options.max_stream_frame_data, true);
    try sendConnectionFrames(connection, frames.items, options.max_frames_per_packet);
}

fn sendConnectionFrames(connection: *quic.one_rtt.Connection, frames: []const quic.Frame, max_frames_per_packet: usize) Error!void {
    const chunk_size = @max(@as(usize, 1), max_frames_per_packet);
    var offset: usize = 0;
    while (offset < frames.len) {
        const end = @min(frames.len, offset + chunk_size);
        try connection.send(frames[offset..end]);
        offset = end;
    }
}

fn receiveConnectionStreamBytes(
    connection: *quic.one_rtt.Connection,
    expected_stream_id: ?u62,
    options: HandshakeSessionOptions,
    control: *http3.ControlState,
    qpack: *QpackDecodeState,
    role: ControlStreamRole,
) Error!AssembledStream {
    var recv: ?quic.stream_state.RecvState = null;
    defer if (recv) |*state| state.deinit();
    var from: ?net.IpAddress = null;
    var stream_id: ?u62 = expected_stream_id;

    while (true) {
        var packet = try connection.receivePacket();
        defer packet.deinit(connection.endpoint.allocator);
        if (from == null) from = packet.from;

        for (packet.frames) |frame| {
            try rejectCriticalStreamClosureFrame(control.*, frame, role);
            if (frame != .stream) continue;
            const peer_encoder_stream_id: u64 = switch (role) {
                .server => client_qpack_encoder_stream_id,
                .client => server_qpack_encoder_stream_id,
            };
            if ((frame.stream.stream_id & 0x02) != 0 and
                ((qpack.encoder_stream != null and
                    qpack.encoder_stream.?.stream_id ==
                        frame.stream.stream_id) or
                    frame.stream.stream_id == peer_encoder_stream_id or
                    (frame.stream.offset == 0 and
                        peekUniStreamType(frame.stream) == .qpack_encoder)))
            {
                try qpack.applyEncoderStreamFrame(control, frame.stream);
                continue;
            }
            if (try applyControlStreamFrameForRole(control, connection.endpoint.allocator, frame.stream, role)) continue;
            if ((try messageStreamDisposition(frame.stream.stream_id)) == .ignore) continue;
            const incoming_id: u62 = @intCast(frame.stream.stream_id);
            if (rejectByLocalGoAway(control.*, role, incoming_id)) return error.RequestRejected;
            if (stream_id) |id| {
                if (incoming_id != id) continue;
            } else {
                stream_id = incoming_id;
                recv = quic.stream_state.RecvState.init(connection.endpoint.allocator, incoming_id, options.max_stream_buffer);
            }
            if (recv == null) recv = quic.stream_state.RecvState.init(connection.endpoint.allocator, incoming_id, options.max_stream_buffer);
            if (recv) |*state| {
                try state.insert(frame.stream);
                if (state.final_size != null and state.contiguous_end >= state.final_size.?) {
                    const bytes = try connection.endpoint.allocator.dupe(u8, state.buffer.items[0..state.final_size.?]);
                    return .{ .from = from.?, .stream_id = stream_id.?, .bytes = bytes };
                }
            }
        }
    }
}

const ControlFrameKind = enum { goaway };

fn validateServerGoAwayStreamId(stream_id: u64) Error!void {
    // RFC 9114 requires a server GOAWAY identifier to be a client-initiated
    // bidirectional request stream ID.  Client-initiated bidirectional stream
    // IDs are exactly the multiples of four.
    if ((stream_id & 0x3) != 0) return error.InvalidFrame;
}

fn validateClientGoAwayPushId(push_id: u64) Error!void {
    // This runtime does not implement the server-push lifecycle, mirroring the
    // tquic behavior of sending client GOAWAY with push ID 0.  Accepting larger
    // IDs would imply outstanding pushes can be retried or drained correctly.
    if (push_id != 0) return error.InvalidFrame;
}

fn rejectByLocalGoAway(control: http3.ControlState, role: ControlStreamRole, stream_id: u64) bool {
    return switch (role) {
        // A server GOAWAY carries the largest client-initiated request stream
        // ID that can still be processed, so server receive paths must reject
        // newer request streams after sending GOAWAY.  A client GOAWAY carries
        // a push ID instead (RFC 9114 §5.2), not a response stream ID; using it
        // to filter server responses would incorrectly reject the in-flight
        // response on stream 0 after a client sends GOAWAY(0).
        .server => !control.acceptsLocalRequestStream(stream_id),
        .client => false,
    };
}

fn controlFramePayload(
    control: *http3.ControlState,
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    kind: ControlFrameKind,
    value: u64,
) Error!void {
    switch (kind) {
        .goaway => try control.writeGoAway(list, allocator, value),
    }
}

fn sendConnectionControlFrame(
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    options: HandshakeSessionOptions,
    kind: ControlFrameKind,
    value: u64,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(connection.endpoint.allocator);
    try controlFramePayload(control, &payload, connection.endpoint.allocator, kind, value);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try control_send.appendFrames(&frames, connection.endpoint.allocator, payload.items, payload.items.len, false);
    try sendConnectionFrames(connection, frames.items, options.max_frames_per_packet);
}

fn sendProtectedControlFrame(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    next_packet_number: *u64,
    kind: ControlFrameKind,
    value: u64,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    try controlFramePayload(control, &payload, endpoint.allocator, kind, value);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try control_send.appendFrames(&frames, endpoint.allocator, payload.items, payload.items.len, false);
    try sendProtectedFrames(endpoint, to, config.send_keys, config.peer_connection_id, next_packet_number, frames.items, config.max_frames_per_packet);
}

fn sendConnectionSettings(
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    qpack_decoder_send: *quic.stream_state.SendState,
    qpack_decoder_prefix_sent: *bool,
    options: HandshakeSessionOptions,
    stream_id: u62,
) Error!void {
    if (control.settings.sent) return;

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(connection.endpoint.allocator);
    const previous_settings = control.settings;
    errdefer control.settings = previous_settings;
    try control.writeSettingsStream(&payload, connection.endpoint.allocator, options.local_settings);

    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    if (control_send.stream_id != stream_id) control_send.* = quic.stream_state.SendState.init(stream_id);
    try control_send.appendFrames(&frames, connection.endpoint.allocator, payload.items, payload.items.len, false);

    var qpack_encoder: std.ArrayList(u8) = .empty;
    defer qpack_encoder.deinit(connection.endpoint.allocator);
    var qpack_decoder: std.ArrayList(u8) = .empty;
    defer qpack_decoder.deinit(connection.endpoint.allocator);
    const is_client = stream_id == client_control_stream_id;
    try http3.writeQpackEncoderStreamPrefix(&qpack_encoder, connection.endpoint.allocator);
    if (!qpack_decoder_prefix_sent.*) {
        try http3.writeQpackDecoderStreamPrefix(
            &qpack_decoder,
            connection.endpoint.allocator,
        );
    }
    var encoder_state = quic.stream_state.SendState.init(if (is_client) client_qpack_encoder_stream_id else server_qpack_encoder_stream_id);
    try encoder_state.appendFrames(&frames, connection.endpoint.allocator, qpack_encoder.items, qpack_encoder.items.len, false);
    if (qpack_decoder_send.stream_id != (if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id)) {
        qpack_decoder_send.* = quic.stream_state.SendState.init(
            if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id,
        );
    }
    if (qpack_decoder.items.len != 0) {
        try qpack_decoder_send.appendFrames(
            &frames,
            connection.endpoint.allocator,
            qpack_decoder.items,
            qpack_decoder.items.len,
            false,
        );
    }
    try sendConnectionFrames(connection, frames.items, options.max_frames_per_packet);
    if (qpack_decoder.items.len != 0) qpack_decoder_prefix_sent.* = true;
}

fn sendConnectionQpackFeedback(
    connection: *quic.one_rtt.Connection,
    qpack: *QpackDecodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    max_frames_per_packet: usize,
) Error!void {
    const pending = qpack.pendingDecoderInstructions();
    if (pending.len == 0) return;

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(connection.endpoint.allocator);
    if (!prefix_sent.*) try http3.writeQpackDecoderStreamPrefix(
        &payload,
        connection.endpoint.allocator,
    );
    try payload.appendSlice(connection.endpoint.allocator, pending);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try send_state.appendFrames(
        &frames,
        connection.endpoint.allocator,
        payload.items,
        payload.items.len,
        false,
    );
    try sendConnectionFrames(connection, frames.items, max_frames_per_packet);
    prefix_sent.* = true;
    qpack.clearDecoderInstructions();
}

fn sendProtectedSettings(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    qpack_decoder_send: *quic.stream_state.SendState,
    qpack_decoder_prefix_sent: *bool,
    next_packet_number: *u64,
    stream_id: u62,
) Error!void {
    if (control.settings.sent) return;

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    const previous_settings = control.settings;
    errdefer control.settings = previous_settings;
    try control.writeSettingsStream(&payload, endpoint.allocator, config.local_settings);

    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    if (control_send.stream_id != stream_id) control_send.* = quic.stream_state.SendState.init(stream_id);
    try control_send.appendFrames(&frames, endpoint.allocator, payload.items, payload.items.len, false);

    var qpack_encoder: std.ArrayList(u8) = .empty;
    defer qpack_encoder.deinit(endpoint.allocator);
    var qpack_decoder: std.ArrayList(u8) = .empty;
    defer qpack_decoder.deinit(endpoint.allocator);
    const is_client = stream_id == client_control_stream_id;
    try http3.writeQpackEncoderStreamPrefix(&qpack_encoder, endpoint.allocator);
    if (!qpack_decoder_prefix_sent.*) {
        try http3.writeQpackDecoderStreamPrefix(&qpack_decoder, endpoint.allocator);
    }
    var encoder_state = quic.stream_state.SendState.init(if (is_client) client_qpack_encoder_stream_id else server_qpack_encoder_stream_id);
    try encoder_state.appendFrames(&frames, endpoint.allocator, qpack_encoder.items, qpack_encoder.items.len, false);
    if (qpack_decoder_send.stream_id != (if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id)) {
        qpack_decoder_send.* = quic.stream_state.SendState.init(
            if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id,
        );
    }
    if (qpack_decoder.items.len != 0) {
        try qpack_decoder_send.appendFrames(
            &frames,
            endpoint.allocator,
            qpack_decoder.items,
            qpack_decoder.items.len,
            false,
        );
    }
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
    );
    if (qpack_decoder.items.len != 0) qpack_decoder_prefix_sent.* = true;
}

fn sendProtectedQpackFeedback(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    qpack: *QpackDecodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    next_packet_number: *u64,
) Error!void {
    const pending = qpack.pendingDecoderInstructions();
    if (pending.len == 0) return;

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    if (!prefix_sent.*) try http3.writeQpackDecoderStreamPrefix(
        &payload,
        endpoint.allocator,
    );
    const instruction_offset = payload.items.len;
    try payload.appendSlice(endpoint.allocator, pending);

    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try send_state.appendFrames(
        &frames,
        endpoint.allocator,
        payload.items,
        config.max_stream_frame_data,
        false,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
    );
    prefix_sent.* = true;
    _ = instruction_offset;
    qpack.clearDecoderInstructions();
}

const ControlStreamRole = enum {
    client,
    server,
};

fn applyControlStreamFrameForRole(control: *http3.ControlState, allocator: std.mem.Allocator, stream: quic.StreamFrame, role: ControlStreamRole) Error!bool {
    if (role == .server and (stream.stream_id & 0x02) != 0 and stream.offset == 0) {
        if (peekUniStreamType(stream) == .push) return error.StreamCreationError;
    }
    const previous = control.*;
    const previous_priority_present = previous.latest_priority_update != null;
    const handled = try applyControlStreamFrame(control, allocator, stream);
    if (handled and role == .client) {
        if (control.peer_goaway_id != previous.peer_goaway_id) {
            validateServerGoAwayStreamId(control.peer_goaway_id.?) catch |err| {
                control.* = previous;
                return err;
            };
        }
        // MAX_PUSH_ID and PRIORITY_UPDATE are client-to-server control frames.
        // A client receiving them from a server must treat the frame as
        // unexpected; restore state so callers can recover or close cleanly.
        if (control.peer_max_push_id != previous.peer_max_push_id or (control.latest_priority_update != null) != previous_priority_present) {
            control.* = previous;
            return error.UnexpectedFrame;
        }
    }
    if (handled and role == .server and control.peer_goaway_id != previous.peer_goaway_id) {
        validateClientGoAwayPushId(control.peer_goaway_id.?) catch |err| {
            control.* = previous;
            return err;
        };
    }
    return handled;
}

fn peekUniStreamType(stream: quic.StreamFrame) ?http3.StreamType {
    var prefix_cursor = @import("../internal/wire.zig").Cursor.init(stream.data);
    return @enumFromInt(quic.varint.decode(&prefix_cursor) catch return null);
}

fn applyControlStreamFrame(control: *http3.ControlState, allocator: std.mem.Allocator, stream: quic.StreamFrame) Error!bool {
    // HTTP/3 control and QPACK streams are unidirectional QUIC streams.  Offset
    // zero carries the stream type varint; subsequent frames on an already
    // registered critical stream contain only that stream's payload.
    if ((stream.stream_id & 0x02) == 0) return false;
    if (isRegisteredCriticalStream(control.*, stream.stream_id)) {
        try rejectClosedCriticalStream(stream);
    }
    if (stream.offset != 0) {
        if (control.peer_control_stream_id != null and control.peer_control_stream_id.? == stream.stream_id) {
            try control.applyControlPayload(allocator, stream.data);
            return true;
        }
        if ((control.peer_qpack_encoder_stream_id != null and control.peer_qpack_encoder_stream_id.? == stream.stream_id) or
            (control.peer_qpack_decoder_stream_id != null and control.peer_qpack_decoder_stream_id.? == stream.stream_id))
        {
            return error.QpackDynamicTableUnsupported;
        }
        return false;
    }

    if (stream.data.len == 0) return false;
    var prefix_cursor = @import("../internal/wire.zig").Cursor.init(stream.data);
    const stream_type = peekUniStreamType(stream) orelse return false;
    _ = quic.varint.decode(&prefix_cursor) catch unreachable;
    switch (stream_type) {
        .control => {
            try rejectClosedCriticalStream(stream);
            try control.registerControlStream(stream.stream_id);
            try control.applyControlPayload(allocator, stream.data[prefix_cursor.pos..]);
        },
        .qpack_encoder, .qpack_decoder => {
            try rejectClosedCriticalStream(stream);
            try control.registerQpackStream(stream_type, stream.stream_id);
            if (stream.data[prefix_cursor.pos..].len != 0) return error.QpackDynamicTableUnsupported;
        },
        else => return false,
    }
    return true;
}

fn isRegisteredCriticalStream(control: http3.ControlState, stream_id: u64) bool {
    return (control.peer_control_stream_id != null and control.peer_control_stream_id.? == stream_id) or
        (control.peer_qpack_encoder_stream_id != null and control.peer_qpack_encoder_stream_id.? == stream_id) or
        (control.peer_qpack_decoder_stream_id != null and control.peer_qpack_decoder_stream_id.? == stream_id);
}

fn isLocalCriticalStream(role: ControlStreamRole, stream_id: u64) bool {
    return switch (role) {
        .client => stream_id == client_control_stream_id or stream_id == client_qpack_encoder_stream_id or stream_id == client_qpack_decoder_stream_id,
        .server => stream_id == server_control_stream_id or stream_id == server_qpack_encoder_stream_id or stream_id == server_qpack_decoder_stream_id,
    };
}

fn rejectCriticalStreamClosureFrame(control: http3.ControlState, frame: quic.Frame, role: ControlStreamRole) Error!void {
    switch (frame) {
        .reset_stream => |reset| {
            if (isRegisteredCriticalStream(control, reset.stream_id)) return error.ClosedCriticalStream;
        },
        .stop_sending => |stop| {
            // RFC 9204 §4.2 also forbids requesting closure of the peer's
            // QPACK streams.  Treat STOP_SENDING for our locally-created
            // critical streams the same way tquic/quic-zig treat reset/FIN:
            // as H3_CLOSED_CRITICAL_STREAM at the HTTP/3 layer.
            if (isLocalCriticalStream(role, stop.stream_id)) return error.ClosedCriticalStream;
        },
        else => {},
    }
}

fn rejectClosedCriticalStream(stream: quic.StreamFrame) Error!void {
    // RFC 9114 §6.2.1 and RFC 9204 §4.2 make the control stream and both
    // QPACK streams connection-long-lived critical streams.  Mature stacks
    // (tquic, quic-zig) surface a FIN on any of these streams as
    // H3_CLOSED_CRITICAL_STREAM instead of silently accepting a truncated
    // control/QPACK context.
    if (stream.fin) return error.ClosedCriticalStream;
}

fn sendProtectedFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    next_packet_number: *u64,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
) Error!void {
    const chunk_size = @max(@as(usize, 1), max_frames_per_packet);
    var offset: usize = 0;
    while (offset < frames.len) {
        const end = @min(frames.len, offset + chunk_size);
        try quic.one_rtt.sendFrames(endpoint, to, keys, .{
            .destination_connection_id = destination_connection_id,
            .packet_number = next_packet_number.*,
            .frames = frames[offset..end],
        });
        next_packet_number.* += 1;
        offset = end;
    }
}

const MessageStreamDisposition = enum {
    request_response,
    ignore,
};

fn messageStreamDisposition(stream_id: u64) Error!MessageStreamDisposition {
    if ((stream_id & 0x02) != 0) return .ignore;
    // HTTP/3 request/response streams are always client-initiated
    // bidirectional streams.  Without a negotiated extension, a server-initiated
    // bidirectional stream is a connection-level H3_STREAM_CREATION_ERROR.
    if ((stream_id & 0x01) != 0) return error.StreamCreationError;
    return .request_response;
}

fn findMessageStreamFrame(frames: []const quic.Frame) Error!?quic.StreamFrame {
    for (frames) |frame| {
        if (frame != .stream) continue;
        switch (try messageStreamDisposition(frame.stream.stream_id)) {
            .request_response => return frame.stream,
            .ignore => continue,
        }
    }
    return null;
}

fn findStreamFrame(frames: []const quic.Frame) ?quic.StreamFrame {
    for (frames) |frame| {
        if (frame == .stream) return frame.stream;
    }
    return null;
}

test "HTTP/3 server GOAWAY validates request stream ids" {
    try validateServerGoAwayStreamId(0);
    try validateServerGoAwayStreamId(4);
    try validateServerGoAwayStreamId(128);
    try std.testing.expectError(error.InvalidFrame, validateServerGoAwayStreamId(1));
    try std.testing.expectError(error.InvalidFrame, validateServerGoAwayStreamId(2));
    try std.testing.expectError(error.InvalidFrame, validateServerGoAwayStreamId(3));
    try validateClientGoAwayPushId(0);
    try std.testing.expectError(error.InvalidFrame, validateClientGoAwayPushId(1));

    try std.testing.expect(!rejectByLocalGoAway(.{ .local_goaway_id = 0 }, .client, 0));
    try std.testing.expect(!rejectByLocalGoAway(.{ .local_goaway_id = 0 }, .client, 4));
    try std.testing.expect(!rejectByLocalGoAway(.{ .local_goaway_id = 4 }, .server, 0));
    try std.testing.expect(rejectByLocalGoAway(.{ .local_goaway_id = 4 }, .server, 4));
}

test "HTTP/3 client rejects server-only control frames" {
    const allocator = std.testing.allocator;

    var stream_bytes: std.ArrayList(u8) = .empty;
    defer stream_bytes.deinit(allocator);
    var goaway_payload: std.ArrayList(u8) = .empty;
    defer goaway_payload.deinit(allocator);

    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try quic.varint.encode(&goaway_payload, allocator, 1);
    try (http3.Frame{ .frame_type = http3.FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&stream_bytes, allocator);

    var client_control = http3.ControlState{};
    try std.testing.expectError(error.InvalidFrame, applyControlStreamFrameForRole(&client_control, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));
    try std.testing.expect(client_control.peer_goaway_id == null);

    stream_bytes.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try http3.writeMaxPushIdFrame(&stream_bytes, allocator, 4);

    client_control = .{};
    try std.testing.expectError(error.UnexpectedFrame, applyControlStreamFrameForRole(&client_control, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));
    try std.testing.expect(client_control.peer_max_push_id == null);

    stream_bytes.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try http3.writePriorityUpdateFrame(&stream_bytes, allocator, 0, .{ .urgency = 1 });
    client_control = .{};
    try std.testing.expectError(error.UnexpectedFrame, applyControlStreamFrameForRole(&client_control, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));
    try std.testing.expect(client_control.latest_priority_update == null);

    stream_bytes.clearRetainingCapacity();
    goaway_payload.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try quic.varint.encode(&goaway_payload, allocator, 1);
    try (http3.Frame{ .frame_type = http3.FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&stream_bytes, allocator);

    var server_control = http3.ControlState{};
    try std.testing.expectError(error.InvalidFrame, applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));
    try std.testing.expect(server_control.peer_goaway_id == null);

    stream_bytes.clearRetainingCapacity();
    goaway_payload.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try quic.varint.encode(&goaway_payload, allocator, 0);
    try (http3.Frame{ .frame_type = http3.FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&stream_bytes, allocator);
    try std.testing.expect(try applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));
    try std.testing.expectEqual(@as(?u64, 0), server_control.peer_goaway_id);

    stream_bytes.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try http3.writePriorityUpdateFrame(&stream_bytes, allocator, 0, .{ .urgency = 1 });

    server_control = .{};
    try std.testing.expect(try applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));
    try std.testing.expect(server_control.latest_priority_update != null);

    stream_bytes.clearRetainingCapacity();
    try quic.varint.encode(&stream_bytes, allocator, @intFromEnum(http3.StreamType.push));
    server_control = .{};
    try std.testing.expectError(error.StreamCreationError, applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));

    var client_control_for_push = http3.ControlState{};
    try std.testing.expect(!try applyControlStreamFrameForRole(&client_control_for_push, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));
}

test "HTTP/3 connection control frames advance control stream offset" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const server_cid = [_]u8{ 0xf5, 0xf6, 0xf7, 0xf8 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xf1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xf2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    try client.sendGoAway(0);
    var first = try quic.one_rtt.receive(&server.quic_server.endpoint, client_keys, server_cid.len, 0, 8);
    defer first.deinit(allocator);
    const first_stream = findStreamFrame(first.frames) orelse return error.MissingStreamFrame;
    try std.testing.expectEqual(@as(u64, 0), first_stream.offset);
    try std.testing.expect(try applyControlStreamFrame(&server.control, allocator, first_stream));

    var second = try quic.one_rtt.receive(&server.quic_server.endpoint, client_keys, server_cid.len, 1, 8);
    defer second.deinit(allocator);
    const second_stream = findStreamFrame(second.frames) orelse return error.MissingStreamFrame;
    try std.testing.expect(second_stream.offset > 0);
    try std.testing.expect(try applyControlStreamFrame(&server.control, allocator, second_stream));
    try std.testing.expectEqual(@as(?u64, 0), server.control.peer_goaway_id);

    try client.sendGoAway(0);
    var third = try quic.one_rtt.receive(&server.quic_server.endpoint, client_keys, server_cid.len, 2, 8);
    defer third.deinit(allocator);
    const third_stream = findStreamFrame(third.frames) orelse return error.MissingStreamFrame;
    try std.testing.expect(third_stream.offset > second_stream.offset);
    try std.testing.expect(try applyControlStreamFrame(&server.control, allocator, third_stream));
    try std.testing.expectEqual(@as(?u64, 0), server.control.peer_goaway_id);
}

test "HTTP/3 runtime rejects non-empty QPACK critical streams" {
    const allocator = std.testing.allocator;
    var control = http3.ControlState{};
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&payload, allocator);
    try payload.append(allocator, 0x3f); // Set Dynamic Table Capacity prefix/instruction byte.

    try std.testing.expectError(error.QpackDynamicTableUnsupported, applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .data = payload.items,
    }));
    try std.testing.expectEqual(@as(?u64, client_qpack_encoder_stream_id), control.peer_qpack_encoder_stream_id);
}

test "HTTP/3 QPACK decoder state reassembles split and reordered encoder instructions" {
    const allocator = std.testing.allocator;
    var state = QpackDecodeState.init(allocator, 256, 4096);
    defer state.deinit();
    var control = http3.ControlState{};

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .set_capacity = 256 });
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .insert_literal = .{
        .name = "x-runtime",
        .value = "split-across-stream-frames",
    } });
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .insert_name_reference = .{
        .static = true,
        .name_index = 1,
        .value = "/dynamic",
    } });
    const split = bytes.items.len / 2;

    // Deliver the suffix first. Nothing is contiguous from offset zero, so no
    // stream registration, table mutation, or decoder feedback is possible.
    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = split,
        .data = bytes.items[split..],
    });
    try std.testing.expect(control.peer_qpack_encoder_stream_id == null);
    try std.testing.expectEqual(@as(usize, 0), state.table.entryCount());
    try std.testing.expectEqual(@as(usize, 0), state.decoder_instructions.items.len);

    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .data = bytes.items[0..split],
    });
    try std.testing.expectEqual(
        @as(?u64, client_qpack_encoder_stream_id),
        control.peer_qpack_encoder_stream_id,
    );
    try std.testing.expectEqual(@as(usize, 256), state.table.capacity);
    try std.testing.expectEqual(@as(u64, 2), state.table.insert_count);
    try std.testing.expectEqualStrings("x-runtime", state.table.absolute(0).?.name);
    try std.testing.expectEqualStrings(":path", state.table.absolute(1).?.name);
    try std.testing.expectEqualStrings("/dynamic", state.table.absolute(1).?.value);

    const feedback = try state.takeDecoderInstructions();
    defer allocator.free(feedback);
    const increment = try http3.Qpack.decodeDecoderInstruction(feedback);
    try std.testing.expectEqual(@as(usize, feedback.len), increment.consumed);
    try std.testing.expectEqual(
        @as(u64, 2),
        increment.instruction.insert_count_increment,
    );
    try std.testing.expectEqual(@as(u64, 2), state.acknowledged_insert_count);

    // An identical retransmission is accepted by RecvState and cannot apply
    // instructions or acknowledgments a second time.
    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .data = bytes.items,
    });
    try std.testing.expectEqual(@as(u64, 2), state.table.insert_count);
    try std.testing.expectEqual(@as(usize, 0), state.decoder_instructions.items.len);
}

test "HTTP/3 QPACK decoder state retains a partial instruction and acknowledges field section" {
    const allocator = std.testing.allocator;
    var state = QpackDecodeState.init(allocator, 256, 4096);
    defer state.deinit();
    var control = http3.ControlState{};

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .set_capacity = 256 });
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .insert_literal = .{
        .name = "x-partial",
        .value = "value-that-needs-the-second-frame",
    } });
    const split = bytes.items.len - 3;
    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .data = bytes.items[0..split],
    });
    try std.testing.expectEqual(@as(u64, 0), state.table.insert_count);
    try std.testing.expect(state.encoder_stream.?.available().len != 0);

    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = split,
        .data = bytes.items[split..],
    });
    try std.testing.expectEqual(@as(u64, 1), state.table.insert_count);
    try std.testing.expectEqual(@as(usize, 0), state.encoder_stream.?.available().len);

    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&field_section, allocator, &.{
        .{ .name = "x-partial", .value = "value-that-needs-the-second-frame" },
    }, state.table);
    var decoded = try state.decodeFieldSection(allocator, 12, field_section.items);
    defer http3.Qpack.freeDynamicBlock(allocator, &decoded);
    try std.testing.expectEqual(@as(usize, 1), decoded.fields.len);
    try std.testing.expectEqualStrings("x-partial", decoded.fields[0].name);

    const feedback = try state.takeDecoderInstructions();
    defer allocator.free(feedback);
    const increment = try http3.Qpack.decodeDecoderInstruction(feedback);
    const acknowledgment = try http3.Qpack.decodeDecoderInstruction(
        feedback[increment.consumed..],
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        increment.instruction.insert_count_increment,
    );
    try std.testing.expectEqual(
        @as(u64, 12),
        acknowledgment.instruction.section_acknowledgment,
    );
}

test "HTTP/3 QPACK decoder state rejects capacity overflow and critical stream FIN" {
    const allocator = std.testing.allocator;
    var state = QpackDecodeState.init(allocator, 64, 4096);
    defer state.deinit();
    var control = http3.ControlState{};

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .set_capacity = 65 });
    try std.testing.expectError(error.QpackEncoderStreamError, state.applyEncoderStreamFrame(
        &control,
        .{
            .stream_id = client_qpack_encoder_stream_id,
            .offset = 0,
            .data = bytes.items,
        },
    ));

    var fin_state = QpackDecodeState.init(allocator, 64, 4096);
    defer fin_state.deinit();
    try std.testing.expectError(error.ClosedCriticalStream, fin_state.applyEncoderStreamFrame(
        &control,
        .{
            .stream_id = client_qpack_encoder_stream_id,
            .offset = 0,
            .data = &.{@intFromEnum(http3.StreamType.qpack_encoder)},
            .fin = true,
        },
    ));
}

test "HTTP/3 QPACK encoder state waits for insert acknowledgment before dynamic reference" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 256, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(256);
    try std.testing.expectEqual(
        @as(?u64, 0),
        try encoder.insertField("x-encode", "reused"),
    );

    const fields = [_]http3.Qpack.HeaderField{
        .{ .name = "x-encode", .value = "reused" },
    };
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 0, &fields);
    var first_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        first.items,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &first_decoded);
    try std.testing.expectEqual(@as(u64, 0), first_decoded.required_insert_count);
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);

    var decoder_bytes: std.ArrayList(u8) = .empty;
    defer decoder_bytes.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&decoder_bytes, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &decoder_bytes,
        allocator,
        .{ .insert_count_increment = 1 },
    );
    var control = http3.ControlState{};
    const split = decoder_bytes.items.len - 1;
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = split,
        .data = decoder_bytes.items[split..],
    });
    try std.testing.expectEqual(@as(u64, 0), encoder.known_received_count);
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = decoder_bytes.items[0..split],
    });
    try std.testing.expectEqual(@as(u64, 1), encoder.known_received_count);
    try std.testing.expectEqual(
        @as(?u64, client_qpack_decoder_stream_id),
        control.peer_qpack_decoder_stream_id,
    );

    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try encoder.encodeFieldSection(&second, 4, &fields);
    var second_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        second.items,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &second_decoded);
    try std.testing.expectEqual(@as(u64, 1), second_decoded.required_insert_count);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(0));

    var acknowledgment: std.ArrayList(u8) = .empty;
    defer acknowledgment.deinit(allocator);
    try http3.Qpack.writeDecoderInstruction(
        &acknowledgment,
        allocator,
        .{ .section_acknowledgment = 4 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = decoder_bytes.items.len,
        .data = acknowledgment.items,
    });
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);
    try std.testing.expect(!encoder.reference_counts.contains(0));

    // Retransmitting the same decoder bytes cannot acknowledge twice.
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = decoder_bytes.items,
    });
    try std.testing.expectEqual(@as(u64, 1), encoder.known_received_count);
}

test "HTTP/3 QPACK encoder state protects referenced entries from eviction" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 34, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(34);
    _ = try encoder.insertField("a", "1");

    var control = http3.ControlState{};
    const decoder_stream = [_]u8{
        @intFromEnum(http3.StreamType.qpack_decoder),
        0x01, // Insert Count Increment = 1.
    };
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = &decoder_stream,
    });

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(&block, 8, &.{
        .{ .name = "a", .value = "1" },
    });
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);

    // Inserting b would evict referenced a. The encoder must skip the insert,
    // not violate QPACK's prohibited-eviction rule.
    try std.testing.expectEqual(
        @as(?u64, null),
        try encoder.insertField("b", "2"),
    );
    try std.testing.expectEqualStrings("a", encoder.table.relative(0).?.name);

    var cancel_bytes: std.ArrayList(u8) = .empty;
    defer cancel_bytes.deinit(allocator);
    try http3.Qpack.writeDecoderInstruction(
        &cancel_bytes,
        allocator,
        .{ .stream_cancellation = 8 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = decoder_stream.len,
        .data = cancel_bytes.items,
    });
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);

    // Once acknowledged and unreferenced, a becomes evictable.
    try std.testing.expectEqual(
        @as(?u64, 1),
        try encoder.insertField("b", "2"),
    );
    try std.testing.expect(encoder.table.absolute(0) == null);
    try std.testing.expectEqualStrings("b", encoder.table.relative(0).?.name);
}

test "HTTP/3 QPACK encoder state rejects invalid decoder feedback" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 128, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(128);
    _ = try encoder.insertField("a", "1");
    var control = http3.ControlState{};

    const excessive_increment = [_]u8{
        @intFromEnum(http3.StreamType.qpack_decoder),
        0x02,
    };
    try std.testing.expectError(
        error.QpackDecoderStreamError,
        encoder.applyDecoderStreamFrame(&control, .{
            .stream_id = client_qpack_decoder_stream_id,
            .offset = 0,
            .data = &excessive_increment,
        }),
    );

    var ack_without_section = QpackEncodeState.init(allocator, 128, 4096);
    defer ack_without_section.deinit();
    var acknowledgment: std.ArrayList(u8) = .empty;
    defer acknowledgment.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&acknowledgment, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &acknowledgment,
        allocator,
        .{ .section_acknowledgment = 0 },
    );
    var second_control = http3.ControlState{};
    try std.testing.expectError(
        error.QpackDecoderStreamError,
        ack_without_section.applyDecoderStreamFrame(
            &second_control,
            .{
                .stream_id = client_qpack_decoder_stream_id,
                .offset = 0,
                .data = acknowledgment.items,
            },
        ),
    );
}

fn checkQpackEncoderStateAllocationFailure(allocator: std.mem.Allocator) !void {
    var encoder = QpackEncodeState.init(allocator, 256, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(256);
    _ = try encoder.insertField("x-one", "value-one");
    _ = try encoder.insertField("x-two", "value-two");

    // Simulate a decoder that has processed both inserts, then exercise
    // multi-container field-section reference tracking.
    encoder.known_received_count = encoder.table.insert_count;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(&block, 12, &.{
        .{ .name = "x-one", .value = "value-one" },
        .{ .name = "x-two", .value = "value-two" },
    });
}

test "HTTP/3 QPACK encoder state is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkQpackEncoderStateAllocationFailure,
        .{},
    );
}

test "HTTP/3 dynamic request writer inserts first and compresses after decoder feedback" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);

    const request = http3.Request{
        .method = "GET",
        .path = "/dynamic-writer",
        .authority = "example.com",
        .headers = &.{
            .{ .name = "x-service-release", .value = "2026.08.09" },
            .{ .name = "authorization", .value = "Bearer secret" },
            .{ .name = "cookie", .value = "session=secret" },
        },
    };
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try request.writeDynamic(&first, allocator, .{}, 0, &encoder);
    const first_headers = try http3.Frame.parse(first.items);
    var first_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        first_headers.payload,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &first_decoded);
    try std.testing.expectEqual(@as(u64, 0), first_decoded.required_insert_count);
    try std.testing.expect(encoder.table.findExact(
        "x-service-release",
        "2026.08.09",
    ) != null);
    try std.testing.expect(encoder.table.findName("authorization") == null);
    try std.testing.expect(encoder.table.findName("cookie") == null);
    try std.testing.expect(encoder.pendingEncoderInstructions().len != 0);

    // Decoder feedback makes the speculative insert referenceable without
    // risking a blocked request stream.
    encoder.known_received_count = encoder.table.insert_count;
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try request.writeDynamic(&second, allocator, .{}, 4, &encoder);
    const second_headers = try http3.Frame.parse(second.items);
    var second_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        second_headers.payload,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &second_decoded);
    try std.testing.expect(second_decoded.required_insert_count != 0);
    try std.testing.expect(second.items.len < first.items.len);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(u64, 4), encoder.pending_sections.items[0].stream_id);
}

test "HTTP/3 dynamic response writer tracks informational final and trailer sections" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    _ = try encoder.insertField("x-release", "netz-2026");
    encoder.known_received_count = encoder.table.insert_count;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http3.writeResponseSequenceDynamic(
        &encoded,
        allocator,
        &.{.{
            .status = 103,
            .headers = &.{.{ .name = "x-release", .value = "netz-2026" }},
        }},
        .{
            .status = 200,
            .headers = &.{.{ .name = "x-release", .value = "netz-2026" }},
            .body = "ok",
            .trailers = &.{.{ .name = "x-release", .value = "netz-2026" }},
        },
        .{},
        8,
        &encoder,
    );
    try std.testing.expectEqual(@as(usize, 3), encoder.pending_sections.items.len);
    for (encoder.pending_sections.items) |section| {
        try std.testing.expectEqual(@as(u64, 8), section.stream_id);
        try std.testing.expectEqual(@as(u64, 1), section.required_insert_count);
    }

    var cursor: usize = 0;
    var dynamic_sections: usize = 0;
    while (cursor < encoded.items.len) {
        const frame = try http3.Frame.parse(encoded.items[cursor..]);
        cursor += frame.consumed;
        if (frame.frame_type != http3.FrameType.headers) continue;
        var decoded = try http3.Qpack.decodeDynamicBlock(
            allocator,
            frame.payload,
            encoder.table,
        );
        defer http3.Qpack.freeDynamicBlock(allocator, &decoded);
        dynamic_sections += @intFromBool(decoded.required_insert_count != 0);
    }
    try std.testing.expectEqual(@as(usize, 3), dynamic_sections);
}

fn checkDynamicQpackWriterAllocationFailure(allocator: std.mem.Allocator) !void {
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    _ = try encoder.insertField("x-existing", "existing-value");
    encoder.known_received_count = encoder.table.insert_count;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/transactional",
        .authority = "example.com",
        .headers = &.{
            .{ .name = "x-existing", .value = "existing-value" },
            .{ .name = "x-future", .value = "future-value" },
        },
        .body = "body",
        .trailers = &.{.{ .name = "x-trailer", .value = "trailer-value" }},
    }).writeDynamic(
        &encoded,
        allocator,
        .{},
        0,
        &encoder,
    );
}

test "HTTP/3 dynamic writer is leak-free under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkDynamicQpackWriterAllocationFailure,
        .{},
    );
}

test "HTTP/3 runtime rejects closed critical streams" {
    const allocator = std.testing.allocator;

    var control_bytes: std.ArrayList(u8) = .empty;
    defer control_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&control_bytes, allocator);
    try http3.writeSettingsFrame(&control_bytes, allocator, .{});

    var control = http3.ControlState{};
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = 0,
        .fin = true,
        .data = control_bytes.items,
    }));
    try std.testing.expect(control.peer_control_stream_id == null);

    try std.testing.expect(try applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = 0,
        .fin = false,
        .data = control_bytes.items,
    }));
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = control_bytes.items.len,
        .fin = true,
        .data = &.{},
    }));

    var qpack_encoder: std.ArrayList(u8) = .empty;
    defer qpack_encoder.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&qpack_encoder, allocator);

    var qpack_control = http3.ControlState{};
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&qpack_control, allocator, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .fin = true,
        .data = qpack_encoder.items,
    }));

    try std.testing.expect(try applyControlStreamFrame(&qpack_control, allocator, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .fin = false,
        .data = qpack_encoder.items,
    }));
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&qpack_control, allocator, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = qpack_encoder.items.len,
        .fin = true,
        .data = &.{},
    }));
}

test "HTTP/3 runtime rejects critical stream reset requests" {
    const allocator = std.testing.allocator;

    var control_bytes: std.ArrayList(u8) = .empty;
    defer control_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&control_bytes, allocator);
    try http3.writeSettingsFrame(&control_bytes, allocator, .{});

    var control = http3.ControlState{};
    try std.testing.expect(try applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = 0,
        .data = control_bytes.items,
    }));

    try std.testing.expectError(error.ClosedCriticalStream, rejectCriticalStreamClosureFrame(control, .{ .reset_stream = .{
        .stream_id = client_control_stream_id,
        .application_error_code = 0,
        .final_size = control_bytes.items.len,
    } }, .server));

    try rejectCriticalStreamClosureFrame(control, .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 0,
        .final_size = 0,
    } }, .server);

    try std.testing.expectError(error.ClosedCriticalStream, rejectCriticalStreamClosureFrame(.{}, .{ .stop_sending = .{
        .stream_id = client_qpack_encoder_stream_id,
        .application_error_code = 0,
    } }, .client));
    try std.testing.expectError(error.ClosedCriticalStream, rejectCriticalStreamClosureFrame(.{}, .{ .stop_sending = .{
        .stream_id = server_control_stream_id,
        .application_error_code = 0,
    } }, .server));

    try rejectCriticalStreamClosureFrame(.{}, .{ .stop_sending = .{
        .stream_id = 0,
        .application_error_code = 0,
    } }, .client);
}

test "HTTP/3 protected runtime exchanges request and response over QUIC 1-RTT" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xca, 0xfe, 0x00, 0x01 };
    const server_cid = [_]u8{ 0xca, 0xfe, 0x00, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xa1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xa2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_settings = .{ .h3_datagram = true },
        .max_stream_frame_data = 7,
    });
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *ProtectedServer) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/protected-h3", request.request.path);
            try std.testing.expectEqualStrings("ping split across stream frames", request.request.body);
            try std.testing.expect(server_ptr.control.settings.received);
            try std.testing.expectEqual(@as(u64, 4), server_ptr.control.settings.peer.webtransport_max_sessions);
            try std.testing.expectEqual(@as(?u64, client_control_stream_id), server_ptr.control.peer_control_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_encoder_stream_id), server_ptr.control.peer_qpack_encoder_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_decoder_stream_id), server_ptr.control.peer_qpack_decoder_stream_id);
            try server_ptr.sendResponse(request.from, request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "pong",
            });
            try std.testing.expect(server_ptr.control.settings.sent);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_settings = .{ .webtransport_max_sessions = 4 },
        .max_stream_frame_data = 7,
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "POST",
        .path = "/protected-h3",
        .authority = "localhost",
        .body = "ping split across stream frames",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("pong", response.response.body);
    try std.testing.expect(client.control.settings.sent);
    try std.testing.expect(client.control.settings.received);
    try std.testing.expect(client.control.settings.peer.h3_datagram);
    try std.testing.expectEqual(@as(?u64, server_control_stream_id), client.control.peer_control_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_encoder_stream_id), client.control.peer_qpack_encoder_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_decoder_stream_id), client.control.peer_qpack_decoder_stream_id);

    client.control.peer_goaway_id = client.next_stream_id;
    try std.testing.expectError(error.GoAwayReceived, client.request(.{
        .method = "GET",
        .path = "/after-goaway",
    }));
}

test "HTTP/3 protected server decodes dynamic QPACK request and sends feedback" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xda, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xdb, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xd3} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xd4} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_settings = .{ .qpack_max_table_capacity = 256 },
        .max_stream_frame_data = 1024,
    });
    defer server.deinit();

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_settings = .{ .qpack_max_table_capacity = 256 },
        .max_stream_frame_data = 1024,
    });
    defer client.deinit();

    try sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        client_control_stream_id,
    );

    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&encoder_bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-live",
            .value = "protected-runtime",
        } },
    );
    var encoder_send = quic.stream_state.SendState.init(client_qpack_encoder_stream_id);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    try encoder_send.appendFrames(
        &frames,
        allocator,
        encoder_bytes.items,
        encoder_bytes.items.len / 2,
        false,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
    );

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-live", "protected-runtime");
    const request_fields = [_]http3.Qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/qpack-live" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-live", .value = "protected-runtime" },
    };
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &field_section,
        allocator,
        &request_fields,
        encoder_table,
    );
    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = field_section.items,
        .consumed = 0,
    }).write(&request_bytes, allocator);
    frames.clearRetainingCapacity();
    var request_send = quic.stream_state.SendState.init(0);
    try request_send.appendFrames(
        &frames,
        allocator,
        request_bytes.items,
        request_bytes.items.len,
        true,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
    );

    var received = try server.receiveRequest();
    defer received.deinit(allocator);
    try std.testing.expectEqualStrings("GET", received.request.method);
    try std.testing.expectEqualStrings("/qpack-live", received.request.path);
    var live_value: ?[]const u8 = null;
    for (received.request.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-live")) live_value = header.value;
    }
    try std.testing.expectEqualStrings("protected-runtime", live_value orelse
        return error.TestUnexpectedResult);
    try std.testing.expectEqual(@as(u64, 1), server.qpack_decode.table.insert_count);

    // Decoder feedback is sent after successful request decoding. Because the
    // server has not sent SETTINGS yet, this first write also carries the
    // decoder-stream type prefix at offset zero, followed by Increment +
    // Section Ack.
    var feedback_packet = try quic.one_rtt.receive(
        &client.quic_client.endpoint,
        server_keys,
        client_cid.len,
        0,
        8,
    );
    defer feedback_packet.deinit(allocator);
    var feedback_bytes: std.ArrayList(u8) = .empty;
    defer feedback_bytes.deinit(allocator);
    for (feedback_packet.frames) |frame| {
        if (frame != .stream or frame.stream.stream_id != server_qpack_decoder_stream_id) continue;
        try feedback_bytes.appendSlice(allocator, frame.stream.data);
    }
    try std.testing.expect(feedback_bytes.items.len != 0);
    var feedback_cursor = @import("../internal/wire.zig").Cursor.init(
        feedback_bytes.items,
    );
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(http3.StreamType.qpack_decoder)),
        try quic.varint.decode(&feedback_cursor),
    );
    const increment = try http3.Qpack.decodeDecoderInstruction(
        feedback_bytes.items[feedback_cursor.pos..],
    );
    const acknowledgment = try http3.Qpack.decodeDecoderInstruction(
        feedback_bytes.items[feedback_cursor.pos + increment.consumed ..],
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        increment.instruction.insert_count_increment,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        acknowledgment.instruction.section_acknowledgment,
    );
}

test "HTTP/3 protected client decodes dynamic QPACK response and sends feedback" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xea, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xeb, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xe3} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xe4} ** quic.protection.secret_len);

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    );
    defer server_endpoint.deinit();
    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server_endpoint.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_settings = .{ .qpack_max_table_capacity = 256 },
        .max_stream_frame_data = 1024,
    });
    defer client.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        client_address: net.IpAddress,
        server_keys: quic.protection.PacketProtectionKeys,
        client_keys: quic.protection.PacketProtectionKeys,
        client_cid: []const u8,
        server_cid: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            // Consume the client's static request plus control/QPACK bootstrap.
            var request_recv = quic.stream_state.RecvState.init(
                allocator,
                0,
                64 * 1024,
            );
            defer request_recv.deinit();
            var expected_packet_number: u64 = 0;
            while (request_recv.final_size == null or
                request_recv.contiguous_end < request_recv.final_size.?)
            {
                var packet = try quic.one_rtt.receive(
                    shared.endpoint,
                    shared.client_keys,
                    shared.server_cid.len,
                    expected_packet_number,
                    8,
                );
                defer packet.deinit(allocator);
                expected_packet_number = packet.packet.packet_number + 1;
                for (packet.frames) |frame| {
                    if (frame == .stream and frame.stream.stream_id == 0) {
                        try request_recv.insert(frame.stream);
                    }
                }
            }

            var encoder: std.ArrayList(u8) = .empty;
            defer encoder.deinit(allocator);
            try http3.writeQpackEncoderStreamPrefix(&encoder, allocator);
            try http3.Qpack.writeEncoderInstruction(
                &encoder,
                allocator,
                .{ .set_capacity = 256 },
            );
            try http3.Qpack.writeEncoderInstruction(
                &encoder,
                allocator,
                .{ .insert_literal = .{
                    .name = "x-response",
                    .value = "dynamic-client",
                } },
            );
            var frames: std.ArrayList(quic.Frame) = .empty;
            defer frames.deinit(allocator);
            var encoder_send = quic.stream_state.SendState.init(
                server_qpack_encoder_stream_id,
            );
            try encoder_send.appendFrames(
                &frames,
                allocator,
                encoder.items,
                encoder.items.len,
                false,
            );
            var next_packet_number: u64 = 0;
            try sendProtectedFrames(
                shared.endpoint,
                shared.client_address,
                shared.server_keys,
                shared.client_cid,
                &next_packet_number,
                frames.items,
                8,
            );

            var table = http3.Qpack.DynamicTable.init(allocator, 256);
            defer table.deinit();
            try table.setCapacity(256);
            _ = try table.insert("x-response", "dynamic-client");
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(allocator);
            try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "2" },
                .{ .name = "x-response", .value = "dynamic-client" },
            }, table);
            var message: std.ArrayList(u8) = .empty;
            defer message.deinit(allocator);
            try (http3.Frame{
                .frame_type = http3.FrameType.headers,
                .payload = block.items,
                .consumed = 0,
            }).write(&message, allocator);
            try (http3.Frame{
                .frame_type = http3.FrameType.data,
                .payload = "ok",
                .consumed = 0,
            }).write(&message, allocator);
            frames.clearRetainingCapacity();
            var response_send = quic.stream_state.SendState.init(0);
            try response_send.appendFrames(
                &frames,
                allocator,
                message.items,
                message.items.len,
                true,
            );
            try sendProtectedFrames(
                shared.endpoint,
                shared.client_address,
                shared.server_keys,
                shared.client_cid,
                &next_packet_number,
                frames.items,
                8,
            );
        }
    };

    var shared = Shared{
        .endpoint = &server_endpoint,
        .client_address = client.quic_client.address(),
        .server_keys = server_keys,
        .client_keys = client_keys,
        .client_cid = &client_cid,
        .server_cid = &server_cid,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var response = try client.request(.{
        .method = "GET",
        .path = "/dynamic-response",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("ok", response.response.body);
    var dynamic_value: ?[]const u8 = null;
    for (response.response.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-response")) {
            dynamic_value = header.value;
        }
    }
    try std.testing.expectEqualStrings("dynamic-client", dynamic_value orelse
        return error.TestUnexpectedResult);
    try std.testing.expectEqual(@as(u64, 1), client.qpack_decode.table.insert_count);
}

test "HTTP/3 handshake server rejects requests beyond local GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7 };
    const client_cid = [_]u8{ 0xe8, 0xe9, 0xea, 0xeb };
    const server_cid = [_]u8{ 0xec, 0xed, 0xee, 0xef };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xe2} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            session.control.local_goaway_id = 0;
            try std.testing.expectError(error.RequestRejected, session.receiveRequest());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xe1} ** 32,
            .x25519_secret_key = [_]u8{0xe3} ** 32,
        },
    });
    defer client.deinit();

    try sendConnectionSettings(
        &client.established.connection,
        &client.control,
        &client.control_send,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        client.options,
        client_control_stream_id,
    );
    try sendConnectionMessage(&client.established.connection, 0, http3.Request{ .method = "GET", .path = "/rejected", .authority = "localhost" }, client.options, client.control.settings.peer);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 protected server rejects requests beyond local GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xaa, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xbb, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xd1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xd2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();
    server.control.local_goaway_id = 0;

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            std.testing.expectError(error.RequestRejected, shared.server.receiveRequest()) catch |err| {
                shared.err = err;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    // Send a request without waiting for a response; the server-side receive path
    // should reject it because local GOAWAY(0) says no client request stream is
    // still acceptable.
    try sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        client_control_stream_id,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{ .method = "GET", .path = "/rejected", .authority = "localhost" }).write(&encoded, allocator);
    var send_state = quic.stream_state.SendState.init(0);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    try send_state.appendFrames(&frames, allocator, encoded.items, encoded.items.len, true);
    try sendProtectedFrames(&client.quic_client.endpoint, client.quic_client.peer, client.config.send_keys, client.config.peer_connection_id, &client.next_packet_number, frames.items, client.config.max_frames_per_packet);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 protected runtime rejects server-initiated bidirectional message streams" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc1, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xc2, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xc1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xc2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    const invalid = [_]quic.Frame{.{
        .stream = .{
            .stream_id = 1, // server-initiated bidirectional: invalid for HTTP/3 messages.
            .data = "not a request stream",
            .fin = true,
        },
    }};
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &invalid,
        client.config.max_frames_per_packet,
    );

    try std.testing.expectError(error.StreamCreationError, server.receiveRequest());
}

test "HTTP/3 handshake runtime establishes QUIC and exchanges request response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xd8, 0xd9, 0xda, 0xdb };
    const server_cid = [_]u8{ 0xdc, 0xdd, 0xde, 0xdf };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x73} ** 32,
            .x25519_secret_key = [_]u8{0x74} ** 32,
        },
        .session = .{ .local_settings = .{ .h3_datagram = true }, .max_stream_frame_data = 7 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            try std.testing.expectEqualStrings("h3", session.established.alpn);

            var request = try session.receiveRequest();
            defer request.deinit(session.established.connection.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/h3-handshake", request.request.path);
            try std.testing.expectEqualStrings("split by handshake runtime", request.request.body);
            try std.testing.expect(session.control.settings.received);
            try std.testing.expectEqual(@as(u64, 6), session.control.settings.peer.webtransport_max_sessions);
            try std.testing.expectEqual(@as(?u64, client_control_stream_id), session.control.peer_control_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_encoder_stream_id), session.control.peer_qpack_encoder_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_decoder_stream_id), session.control.peer_qpack_decoder_stream_id);
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "handshake pong",
            });
            try std.testing.expect(session.control.settings.sent);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x71} ** 32,
            .x25519_secret_key = [_]u8{0x72} ** 32,
        },
        .session = .{ .local_settings = .{ .webtransport_max_sessions = 6 }, .max_stream_frame_data = 7 },
    });
    defer client.deinit();
    try std.testing.expectEqualStrings("h3", client.established.alpn);

    var response = try client.request(.{
        .method = "POST",
        .path = "/h3-handshake",
        .authority = "localhost",
        .body = "split by handshake runtime",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("handshake pong", response.response.body);
    try std.testing.expect(client.control.settings.sent);
    try std.testing.expect(client.control.settings.received);
    try std.testing.expect(client.control.settings.peer.h3_datagram);
    try std.testing.expectEqual(@as(?u64, server_control_stream_id), client.control.peer_control_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_encoder_stream_id), client.control.peer_qpack_encoder_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_decoder_stream_id), client.control.peer_qpack_decoder_stream_id);
}

test "HTTP/3 handshake runtime decodes dynamic QPACK request and sends feedback" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7 };
    const client_cid = [_]u8{ 0xf8, 0xf9, 0xfa, 0xfb };
    const server_cid = [_]u8{ 0xfc, 0xfd, 0xfe, 0xff };
    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x83} ** 32,
            .x25519_secret_key = [_]u8{0x84} ** 32,
        },
        .session = .{
            .local_settings = .{ .qpack_max_table_capacity = 256 },
            .max_stream_frame_data = 1024,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            // Advertise capacity before accepting any dependent encoder
            // instruction or field section.
            try sendConnectionSettings(
                &session.established.connection,
                &session.control,
                &session.control_send,
                &session.qpack_decoder_send,
                &session.qpack_decoder_prefix_sent,
                session.options,
                server_control_stream_id,
            );
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings("GET", request.request.method);
            try std.testing.expectEqualStrings("/handshake-qpack", request.request.path);
            var value: ?[]const u8 = null;
            for (request.request.headers) |header| {
                if (std.mem.eql(u8, header.name, "x-handshake")) {
                    value = header.value;
                }
            }
            try std.testing.expectEqualStrings("dynamic", value orelse
                return error.TestUnexpectedResult);
            try std.testing.expectEqual(
                @as(u64, 1),
                session.qpack_decode.table.insert_count,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x81} ** 32,
            .x25519_secret_key = [_]u8{0x82} ** 32,
        },
        .session = .{
            .local_settings = .{ .qpack_max_table_capacity = 256 },
            .max_stream_frame_data = 1024,
        },
    });
    defer client.deinit();

    // Process the server SETTINGS and critical-stream prefixes before using
    // its advertised QPACK capacity.
    var settings_packet = try client.established.connection.receivePacket();
    defer settings_packet.deinit(allocator);
    for (settings_packet.frames) |frame| {
        if (frame != .stream) continue;
        if ((frame.stream.stream_id & 0x02) != 0 and
            frame.stream.stream_id == server_qpack_encoder_stream_id)
        {
            try client.qpack_decode.applyEncoderStreamFrame(
                &client.control,
                frame.stream,
            );
            continue;
        }
        _ = try applyControlStreamFrameForRole(
            &client.control,
            allocator,
            frame.stream,
            .client,
        );
    }
    try std.testing.expectEqual(
        @as(u64, 256),
        client.control.settings.peer.qpack_max_table_capacity,
    );

    try sendConnectionSettings(
        &client.established.connection,
        &client.control,
        &client.control_send,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        client.options,
        client_control_stream_id,
    );
    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-handshake",
            .value = "dynamic",
        } },
    );
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var encoder_send = quic.stream_state.SendState.init(
        client_qpack_encoder_stream_id,
    );
    encoder_send.next_offset = 1; // sendConnectionSettings emitted the prefix.
    try encoder_send.appendFrames(
        &frames,
        allocator,
        encoder_bytes.items,
        encoder_bytes.items.len / 2,
        false,
    );
    try sendConnectionFrames(
        &client.established.connection,
        frames.items,
        client.options.max_frames_per_packet,
    );

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-handshake", "dynamic");
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&field_section, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/handshake-qpack" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-handshake", .value = "dynamic" },
    }, encoder_table);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = field_section.items,
        .consumed = 0,
    }).write(&message, allocator);
    frames.clearRetainingCapacity();
    var request_send = quic.stream_state.SendState.init(0);
    try request_send.appendFrames(
        &frames,
        allocator,
        message.items,
        message.items.len,
        true,
    );
    try sendConnectionFrames(
        &client.established.connection,
        frames.items,
        client.options.max_frames_per_packet,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 runtime exchanges request and response over QUIC UDP frame endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
        .max_stream_frame_data = 7,
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/h3", request.request.path);
            try std.testing.expectEqualStrings("ping split by dev sender", request.request.body);
            try std.testing.expect(request.extra_datagrams.len != 0);
            try server_ptr.sendResponse(request.from, request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "pong split by dev sender",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
        .max_stream_frame_data = 7,
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "POST",
        .path = "/h3",
        .authority = "localhost",
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "ping split by dev sender",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expect(response.extra_datagrams.len != 0);
    try std.testing.expectEqualStrings("pong split by dev sender", response.response.body);
}

test "HTTP/3 dev runtime assembles split STREAM request and response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/split", request.request.path);
            try std.testing.expectEqualStrings("split request body", request.request.body);
            try std.testing.expectEqual(@as(u62, 0), request.stream_id);
            try std.testing.expect(request.extra_datagrams.len != 0);

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(server_ptr.quic_server.endpoint.allocator);
            try (http3.Response{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "split response body",
            }).write(&encoded, server_ptr.quic_server.endpoint.allocator);

            const mid = encoded.items.len / 2;
            const first = [_]quic.Frame{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = 0,
                .data = encoded.items[0..mid],
                .fin = false,
            } }};
            const second = [_]quic.Frame{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = mid,
                .data = encoded.items[mid..],
                .fin = true,
            } }};
            try server_ptr.quic_server.sendFrames(request.from, &first);
            try server_ptr.quic_server.sendFrames(request.from, &second);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client.deinit();

    var encoded_request: std.ArrayList(u8) = .empty;
    defer encoded_request.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/split",
        .authority = "localhost",
        .body = "split request body",
    }).write(&encoded_request, allocator);
    const split = encoded_request.items.len / 2;
    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = encoded_request.items[0..split],
        .fin = false,
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = split,
        .data = encoded_request.items[split..],
        .fin = true,
    } }};
    try client.quic_client.sendFrames(&first);
    try client.quic_client.sendFrames(&second);

    var assembled = try receiveRuntimeStreamBytes(&client.quic_client.endpoint, 0, client.limits.max_stream_buffer);
    defer assembled.deinit(allocator);
    try std.testing.expect(assembled.datagrams.len > 1);
    var response = try http3.decodeResponse(allocator, assembled.bytes);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("split response body", response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 dev client assembles split STREAM response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("/split-response", request.request.path);

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(server_ptr.quic_server.endpoint.allocator);
            try (http3.Response{
                .status = 200,
                .body = "client public API assembled this split response",
            }).write(&encoded, server_ptr.quic_server.endpoint.allocator);

            const mid = encoded.items.len / 2;
            try server_ptr.quic_server.sendFrames(request.from, &.{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = 0,
                .data = encoded.items[0..mid],
                .fin = false,
            } }});
            try server_ptr.quic_server.sendFrames(request.from, &.{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = mid,
                .data = encoded.items[mid..],
                .fin = true,
            } }});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "GET",
        .path = "/split-response",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expect(response.extra_datagrams.len != 0);
    try std.testing.expectEqualStrings("client public API assembled this split response", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 dev runtime enforces stream reassembly limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer receiver.deinit();
    var sender = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, receiver.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer sender.deinit();

    try sender.sendFrames(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 32,
        .data = "too-far",
        .fin = true,
    } }});
    try std.testing.expectError(error.StreamBufferTooLarge, receiveRuntimeStreamBytes(&receiver, 0, 16));
}

test "HTTP/3 dev runtime receives requests with std.Io async batch" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        batch: ?OwnedRequestBatch = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.batch = shared.server.receiveRequestsConcurrent(2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const receiver = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client_a = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client_a.deinit();
    var client_b = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client_b.deinit();

    const req_a = http3.Request{ .method = "POST", .path = "/batch-a", .authority = "localhost", .body = "a" };
    const req_b = http3.Request{ .method = "POST", .path = "/batch-b", .authority = "localhost", .body = "b" };
    var encoded_a: std.ArrayList(u8) = .empty;
    defer encoded_a.deinit(allocator);
    var encoded_b: std.ArrayList(u8) = .empty;
    defer encoded_b.deinit(allocator);
    try req_a.write(&encoded_a, allocator);
    try req_b.write(&encoded_b, allocator);
    const frame_a = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = encoded_a.items, .fin = true } }};
    const frame_b = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = encoded_b.items, .fin = true } }};
    try client_a.quic_client.sendFrames(&frame_a);
    try client_b.quic_client.sendFrames(&frame_b);

    receiver.join();
    if (shared.err) |err| return err;
    var batch = shared.batch.?;
    defer batch.deinit();
    if (batch.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), batch.receivedCount());

    var saw_a = false;
    var saw_b = false;
    for (batch.requests) |maybe_request| {
        const request = maybe_request.?;
        if (std.mem.eql(u8, request.request.path, "/batch-a")) saw_a = true;
        if (std.mem.eql(u8, request.request.path, "/batch-b")) saw_b = true;
    }
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
}
