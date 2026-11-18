//! HTTP/3 connection control state and SETTINGS handling.

const std = @import("std");
const runtime = @import("mod.zig");

const Error = runtime.Error;
const Frame = runtime.Frame;
const FrameType = runtime.FrameType;
const Origin = runtime.Origin;
const OriginKey = runtime.OriginKey;
const OriginPayload = runtime.OriginPayload;
const Priority = runtime.Priority;
const PriorityUpdatePayload = runtime.PriorityUpdatePayload;
const Settings = runtime.Settings;
const SettingsState = runtime.SettingsState;
const StreamType = runtime.StreamType;
const cloneOrigin = runtime.cloneOrigin;
const cloneOriginKey = runtime.cloneOriginKey;
const default_max_priority_update_payload_size = runtime.default_max_priority_update_payload_size;
const default_max_priority_updates = runtime.default_max_priority_updates;
const exact_range_set = runtime.exact_range_set;
const max_control_frame_header_size = runtime.max_control_frame_header_size;
const max_control_stream_buffer_size = runtime.max_control_stream_buffer_size;
const max_peer_origins = runtime.max_peer_origins;
const max_priority_update_payload_size = runtime.max_priority_update_payload_size;
const max_settings_payload_size = runtime.max_settings_payload_size;
const max_single_varint_frame_len = runtime.max_single_varint_frame_len;
const originListContains = runtime.originListContains;
const parseGoAwayPayload = runtime.parseGoAwayPayload;
const parsePriorityUpdatePayload = runtime.parsePriorityUpdatePayload;
const parseSettings = runtime.parseSettings;
const parseSingleVarintPayload = runtime.parseSingleVarintPayload;
const quic = runtime.quic;
const requestOriginKeyFromSerialized = runtime.requestOriginKeyFromSerialized;
const sameOrigin = runtime.sameOrigin;
const validateRequestStreamId = runtime.validateRequestStreamId;
const wire = runtime.wire;
const writeControlStreamPrefix = runtime.writeControlStreamPrefix;
const writeMaxPushIdFrameInto = runtime.writeMaxPushIdFrameInto;
const writeSettingsFrame = runtime.writeSettingsFrame;
const writeSingleVarintFrameInto = runtime.writeSingleVarintFrameInto;

pub const ControlState = struct {
    pub const Options = struct {
        /// Shared cap across request- and push-element priority entries.
        max_priority_updates: usize = default_max_priority_updates,
        /// Maximum accepted PRIORITY_UPDATE payload bytes. Zero rejects every
        /// nonempty update with H3_EXCESSIVE_LOAD while retaining the protocol
        /// error for an intrinsically invalid empty payload.
        max_priority_update_payload_size: usize =
            default_max_priority_update_payload_size,
    };

    const PriorityUpdateKey = struct {
        frame_type: u64,
        prioritized_element_id: u64,
    };

    pub const StoredPriorityUpdate = struct {
        frame_type: u64,
        payload: PriorityUpdatePayload,

        pub fn priority(self: StoredPriorityUpdate) Priority {
            return self.payload.priority();
        }

        fn deinit(
            self: *StoredPriorityUpdate,
            allocator: std.mem.Allocator,
        ) void {
            allocator.free(self.payload.field_value);
            self.* = undefined;
        }
    };

    /// Optional semantic validation performed for each complete control frame
    /// immediately before it mutates connection state. Runtime layers use this
    /// hook for checks that depend on transport limits or application-owned
    /// push metadata, neither of which belongs in the wire codec.
    pub const FrameDisposition = enum { apply, ignore };

    pub const FrameValidator = struct {
        context: *const anyopaque,
        validate: *const fn (
            context: *const anyopaque,
            state: ControlState,
            frame: Frame,
        ) Error!FrameDisposition,

        fn validateFrame(
            self: FrameValidator,
            state: ControlState,
            frame: Frame,
        ) Error!FrameDisposition {
            return self.validate(self.context, state, frame);
        }
    };

    settings: SettingsState = .{},
    /// Server settings remembered by a client that sent 0-RTT. Consumed by
    /// the first peer SETTINGS frame before any dependent response is routed.
    early_data_peer_settings: ?Settings = null,
    peer_goaway_id: ?u64 = null,
    local_goaway_id: ?u64 = null,
    /// Server-advertised RFC 9412 Origin Set additions, in first-seen order.
    /// The first successfully processed ORIGIN frame initializes the set even
    /// when it is empty; the client must then stop using implicit coalescing.
    peer_origins: std.ArrayList(OriginKey) = .empty,
    /// Origins removed after a 421 response, including the implicit initial
    /// origin which is not otherwise stored in `peer_origins`.
    peer_origin_exclusions: std.ArrayList(OriginKey) = .empty,
    peer_origin_set_initialized: bool = false,
    peer_origin_generation: u64 = 0,
    local_origin_set_sent: bool = false,
    peer_max_push_id: ?u64 = null,
    local_max_push_id: ?u64 = null,
    /// Counts successfully applied client-only frames even when a duplicate
    /// leaves their value state unchanged. Runtime role checks compare this
    /// generation after buffered parsing, including split control frames.
    peer_client_only_frame_generation: u64 = 0,
    /// Exact lifetime cancellation history. Sequential IDs use only the
    /// embedded prefix; sparse IDs are retained as merged ranges.
    peer_cancelled_push_ids: exact_range_set.Set = .{},
    push_cancellation_generation: u64 = 0,
    peer_control_stream_id: ?u64 = null,
    /// Absolute QUIC stream offset through which peer control bytes have been
    /// applied to this HTTP/3 control state. QUIC may retransmit STREAM ranges
    /// under new packet numbers; without this cursor, a duplicate offset-zero
    /// control frame would re-apply SETTINGS and incorrectly surface as
    /// H3_SETTINGS_ERROR.
    peer_control_stream_consumed_offset: usize = 0,
    /// Incomplete control-frame bytes retained across QUIC STREAM boundaries.
    peer_control_stream_buffer: std.ArrayList(u8) = .empty,
    /// Remaining payload bytes of an ignorable extension frame. Unknown frame
    /// bodies are discarded directly instead of entering the retained buffer.
    peer_control_stream_skip_remaining: usize = 0,
    latest_priority_update: ?PriorityUpdatePayload = null,
    latest_priority_update_type: ?u64 = null,
    priority_updates: std.ArrayList(StoredPriorityUpdate) = .empty,
    priority_update_index: std.AutoHashMapUnmanaged(PriorityUpdateKey, usize) = .empty,
    priority_update_generation: u64 = 0,
    max_priority_updates: usize = default_max_priority_updates,
    max_priority_update_payload_size: usize =
        default_max_priority_update_payload_size,
    /// Coarse retirement watermarks keep late updates from turning completed
    /// elements back into retained state. Advancing a watermark may also drop
    /// priority hints for lower idle request IDs or older promised push IDs;
    /// RFC 9218 explicitly permits ignoring priority signals, and this bounded
    /// policy is preferable to lifetime tombstone growth.
    retired_request_priority_through: ?u64 = null,
    retired_push_priority_through: ?u64 = null,
    peer_qpack_encoder_stream_id: ?u64 = null,
    peer_qpack_decoder_stream_id: ?u64 = null,
    peer_qpack_encoder_stream_consumed_offset: usize = 0,
    peer_qpack_decoder_stream_consumed_offset: usize = 0,

    pub fn init(options: Options) Error!ControlState {
        if (options.max_priority_updates == 0) return error.InvalidSetting;
        return .{
            .max_priority_updates = options.max_priority_updates,
            .max_priority_update_payload_size = options.max_priority_update_payload_size,
        };
    }

    pub fn deinit(self: *ControlState, allocator: std.mem.Allocator) void {
        for (self.peer_origins.items) |*origin| origin.deinit();
        self.peer_origins.deinit(allocator);
        for (self.peer_origin_exclusions.items) |*origin| origin.deinit();
        self.peer_origin_exclusions.deinit(allocator);
        self.peer_control_stream_buffer.deinit(allocator);
        for (self.priority_updates.items) |*update| {
            update.deinit(allocator);
        }
        self.priority_updates.deinit(allocator);
        self.priority_update_index.deinit(allocator);
        self.peer_cancelled_push_ids.deinit(allocator);
        self.* = undefined;
    }

    pub fn clone(
        self: ControlState,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!ControlState {
        return self.cloneWithControlBufferLen(
            allocator,
            self.peer_control_stream_buffer.items.len,
        );
    }

    fn cloneWithControlBufferLen(
        self: ControlState,
        allocator: std.mem.Allocator,
        control_buffer_len: usize,
    ) std.mem.Allocator.Error!ControlState {
        std.debug.assert(
            control_buffer_len <= self.peer_control_stream_buffer.items.len,
        );
        var copy = self;
        copy.latest_priority_update = null;
        copy.peer_origins = .empty;
        copy.peer_origin_exclusions = .empty;
        copy.peer_control_stream_buffer = .empty;
        copy.priority_updates = .empty;
        copy.priority_update_index = .empty;
        copy.peer_cancelled_push_ids = .{};
        errdefer copy.deinit(allocator);
        try copy.peer_origins.ensureTotalCapacity(
            allocator,
            self.peer_origins.items.len,
        );
        for (self.peer_origins.items) |origin| {
            const owned = try cloneOriginKey(allocator, origin);
            copy.peer_origins.appendAssumeCapacity(owned);
        }
        try copy.peer_origin_exclusions.ensureTotalCapacity(
            allocator,
            self.peer_origin_exclusions.items.len,
        );
        for (self.peer_origin_exclusions.items) |origin| {
            const owned = try cloneOriginKey(allocator, origin);
            copy.peer_origin_exclusions.appendAssumeCapacity(owned);
        }
        try copy.peer_control_stream_buffer.appendSlice(
            allocator,
            self.peer_control_stream_buffer.items[0..control_buffer_len],
        );
        copy.peer_cancelled_push_ids =
            try self.peer_cancelled_push_ids.clone(allocator);
        try copy.priority_updates.ensureTotalCapacity(
            allocator,
            self.priority_updates.items.len,
        );
        try copy.priority_update_index.ensureUnusedCapacity(
            allocator,
            std.math.cast(u32, self.priority_updates.items.len) orelse
                return error.OutOfMemory,
        );
        var latest_index: ?usize = null;
        for (self.priority_updates.items) |update| {
            const owned = try allocator.dupe(
                u8,
                update.payload.field_value,
            );
            const index = copy.priority_updates.items.len;
            const copied = StoredPriorityUpdate{
                .frame_type = update.frame_type,
                .payload = .{
                    .prioritized_element_id = update.payload.prioritized_element_id,
                    .field_value = owned,
                },
            };
            copy.priority_updates.appendAssumeCapacity(copied);
            copy.priority_update_index.putAssumeCapacity(
                priorityUpdateKey(copied.frame_type, copied.payload.prioritized_element_id),
                index,
            );
            if (self.latest_priority_update) |latest| {
                if (self.latest_priority_update_type == update.frame_type and
                    latest.prioritized_element_id ==
                        update.payload.prioritized_element_id)
                {
                    latest_index = index;
                }
            }
        }
        if (latest_index) |index| {
            // Replacement and swap-removal deliberately do not keep the
            // backing array in generation order. Rebind the compatibility
            // view while cloning rather than assuming the array tail is the
            // most recently processed update. Tracking the index here also
            // avoids a hash lookup that would use borrowed state as a key.
            copy.latest_priority_update = copy.priority_updates.items[index].payload;
        }
        return copy;
    }

    pub fn writeSettingsStream(self: *ControlState, list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: Settings) Error!void {
        try writeControlStreamPrefix(list, allocator);
        try writeSettingsFrame(list, allocator, settings);
        self.settings.markSent(settings);
    }

    pub fn writeGoAway(self: *ControlState, list: *std.ArrayList(u8), allocator: std.mem.Allocator, stream_id: u64) Error!void {
        if (self.local_goaway_id) |previous| {
            if (stream_id > previous) return error.GoAwayIdIncreased;
        }
        var storage: [max_single_varint_frame_len]u8 = undefined;
        const bytes = try writeSingleVarintFrameInto(
            &storage,
            FrameType.goaway,
            stream_id,
        );
        try list.ensureUnusedCapacity(allocator, bytes.len);
        list.appendSliceAssumeCapacity(bytes);
        self.local_goaway_id = stream_id;
    }

    /// Encodes GOAWAY into caller storage and commits the monotonic local ID
    /// only after validation and encoding have succeeded.
    pub fn writeGoAwayInto(
        self: *ControlState,
        storage: *[max_single_varint_frame_len]u8,
        stream_id: u64,
    ) Error![]const u8 {
        if (self.local_goaway_id) |previous| {
            if (stream_id > previous) return error.GoAwayIdIncreased;
        }

        const bytes = try writeSingleVarintFrameInto(storage, FrameType.goaway, stream_id);
        self.local_goaway_id = stream_id;
        return bytes;
    }

    pub fn writeMaxPushId(self: *ControlState, list: *std.ArrayList(u8), allocator: std.mem.Allocator, push_id: u64) Error!void {
        if (self.local_max_push_id) |previous| {
            if (push_id < previous) return error.MaxPushIdReduced;
        }
        var storage: [max_single_varint_frame_len]u8 = undefined;
        const bytes = try writeMaxPushIdFrameInto(&storage, push_id);
        try list.ensureUnusedCapacity(allocator, bytes.len);
        list.appendSliceAssumeCapacity(bytes);
        self.local_max_push_id = push_id;
    }

    /// Encodes MAX_PUSH_ID into caller storage and updates state only after a
    /// valid frame has been produced.
    pub fn writeMaxPushIdInto(
        self: *ControlState,
        storage: *[max_single_varint_frame_len]u8,
        push_id: u64,
    ) Error![]const u8 {
        if (self.local_max_push_id) |previous| {
            if (push_id < previous) return error.MaxPushIdReduced;
        }
        const bytes = try writeMaxPushIdFrameInto(storage, push_id);
        self.local_max_push_id = push_id;
        return bytes;
    }

    /// Append one RFC 9412 ORIGIN frame and commit the local advertisement
    /// marker only after all validation and allocation succeeds. Servers may
    /// call this repeatedly to add origins; an empty first frame deliberately
    /// restricts clients to the connection's initial origin.
    pub fn writeOrigins(
        self: *ControlState,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        origins: []const []const u8,
    ) Error!void {
        try OriginPayload.write(list, allocator, origins);
        self.local_origin_set_sent = true;
    }

    pub fn hasSentOriginSet(self: ControlState) bool {
        return self.local_origin_set_sent;
    }

    pub fn applyControlStreamBytes(self: *ControlState, allocator: std.mem.Allocator, bytes: []const u8) Error!void {
        var cursor = wire.Cursor.init(bytes);
        const stream_type: StreamType = @enumFromInt(try quic.varint.decode(&cursor));
        if (stream_type != .control) return error.InvalidStreamType;
        try self.registerControlStream(0);
        try self.applyControlPayload(allocator, bytes[cursor.pos..]);
    }

    pub fn applyControlPayload(self: *ControlState, allocator: std.mem.Allocator, payload: []const u8) Error!void {
        var cursor = wire.Cursor.init(payload);
        while (!cursor.eof()) {
            const frame = try Frame.parse(payload[cursor.pos..]);
            cursor.pos += frame.consumed;
            try self.applyFrame(allocator, frame);
        }
    }

    /// Append contiguous control-stream bytes and apply every complete frame.
    /// A split type, length, or payload remains buffered for the next STREAM
    /// fragment. The fixed cap prevents unknown or oversized extension frames
    /// from turning a critical stream into unbounded connection memory.
    pub fn appendControlPayload(
        self: *ControlState,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) Error!void {
        return self.appendControlPayloadValidated(
            allocator,
            payload,
            null,
        );
    }

    pub fn appendControlPayloadValidated(
        self: *ControlState,
        allocator: std.mem.Allocator,
        payload: []const u8,
        validator: ?FrameValidator,
    ) Error!void {
        const parser_snapshot = ControlParserSnapshot.capture(self.*);
        var previous: ?ControlState = null;
        defer if (previous) |*value| value.deinit(allocator);
        errdefer {
            if (previous) |value| {
                self.deinit(allocator);
                self.* = value;
                previous = null;
            } else {
                parser_snapshot.restore(self);
            }
        }

        var input_offset: usize = 0;
        while (input_offset < payload.len) {
            if (self.peer_control_stream_skip_remaining != 0) {
                const skipped = @min(
                    self.peer_control_stream_skip_remaining,
                    payload.len - input_offset,
                );
                self.peer_control_stream_skip_remaining -= skipped;
                input_offset += skipped;
                if (input_offset == payload.len) return;
                if (self.peer_control_stream_skip_remaining != 0) unreachable;
            }

            if (self.peer_control_stream_buffer.items.len == 0) {
                const remaining = payload[input_offset..];
                const header = Frame.parseHeader(remaining) catch |err| switch (err) {
                    error.BufferTooShort => {
                        try self.peer_control_stream_buffer.appendSlice(
                            allocator,
                            remaining,
                        );
                        return;
                    },
                    else => return err,
                };
                const known = controlFrameMayMutateOrError(header.frame_type);
                if (header.payload_length > max_control_stream_buffer_size and
                    (!self.settings.received or known))
                {
                    return error.ExcessiveLoad;
                }
                try self.validateControlFrameHeader(header);
                if (!known) {
                    input_offset += header.header_length;
                    const skipped = @min(
                        header.payload_length,
                        payload.len - input_offset,
                    );
                    input_offset += skipped;
                    self.peer_control_stream_skip_remaining =
                        header.payload_length - skipped;
                    continue;
                }

                const total = try header.totalLength();
                if (remaining.len < total) {
                    try self.peer_control_stream_buffer.appendSlice(
                        allocator,
                        remaining,
                    );
                    return;
                }
                const frame = Frame{
                    .frame_type = header.frame_type,
                    .payload = remaining[header.header_length..total],
                    .consumed = total,
                };
                if (validator) |value| {
                    if (try value.validateFrame(self.*, frame) == .ignore) {
                        input_offset += total;
                        continue;
                    }
                }
                if (previous == null) {
                    previous = try parser_snapshot.cloneOriginal(
                        self.*,
                        allocator,
                    );
                }
                try self.applyFrame(allocator, frame);
                input_offset += total;
                continue;
            }

            var header: Frame.Header = undefined;
            while (true) {
                header = Frame.parseHeader(
                    self.peer_control_stream_buffer.items,
                ) catch |err| switch (err) {
                    error.BufferTooShort => {
                        if (input_offset == payload.len) return;
                        if (self.peer_control_stream_buffer.items.len >=
                            max_control_frame_header_size)
                        {
                            return error.InvalidFrame;
                        }
                        try self.peer_control_stream_buffer.append(
                            allocator,
                            payload[input_offset],
                        );
                        input_offset += 1;
                        continue;
                    },
                    else => return err,
                };
                break;
            }
            const known = controlFrameMayMutateOrError(header.frame_type);
            if (header.payload_length > max_control_stream_buffer_size and
                (!self.settings.received or known))
            {
                return error.ExcessiveLoad;
            }
            try self.validateControlFrameHeader(header);
            if (!known) {
                std.debug.assert(
                    self.peer_control_stream_buffer.items.len ==
                        header.header_length,
                );
                self.peer_control_stream_buffer.clearRetainingCapacity();
                const skipped = @min(
                    header.payload_length,
                    payload.len - input_offset,
                );
                input_offset += skipped;
                self.peer_control_stream_skip_remaining =
                    header.payload_length - skipped;
                continue;
            }

            const total = try header.totalLength();
            if (self.peer_control_stream_buffer.items.len < total) {
                const needed = total - self.peer_control_stream_buffer.items.len;
                const appended = @min(needed, payload.len - input_offset);
                try self.peer_control_stream_buffer.appendSlice(
                    allocator,
                    payload[input_offset..][0..appended],
                );
                input_offset += appended;
                if (self.peer_control_stream_buffer.items.len < total) return;
            }
            const frame = Frame{
                .frame_type = header.frame_type,
                .payload = self.peer_control_stream_buffer.items[header.header_length..total],
                .consumed = total,
            };
            const disposition = if (validator) |value|
                try value.validateFrame(self.*, frame)
            else
                FrameDisposition.apply;
            if (disposition == .ignore) {
                if (input_offset < payload.len and previous == null and
                    parser_snapshot.buffer_len >
                        max_control_frame_header_size)
                {
                    previous = try parser_snapshot.cloneOriginal(
                        self.*,
                        allocator,
                    );
                }
                self.peer_control_stream_buffer.clearRetainingCapacity();
                continue;
            }
            if (previous == null) {
                previous = try parser_snapshot.cloneOriginal(
                    self.*,
                    allocator,
                );
            }
            try self.applyFrame(allocator, frame);
            self.peer_control_stream_buffer.clearRetainingCapacity();
        }
    }

    const ControlParserSnapshot = struct {
        buffer_len: usize,
        inline_buffer: [max_control_frame_header_size]u8 = undefined,
        inline_buffer_valid: bool,
        skip_remaining: usize,

        fn capture(control: ControlState) ControlParserSnapshot {
            const buffer_len = control.peer_control_stream_buffer.items.len;
            var snapshot = ControlParserSnapshot{
                .buffer_len = buffer_len,
                .inline_buffer_valid = buffer_len <= max_control_frame_header_size,
                .skip_remaining = control.peer_control_stream_skip_remaining,
            };
            if (snapshot.inline_buffer_valid) {
                @memcpy(
                    snapshot.inline_buffer[0..buffer_len],
                    control.peer_control_stream_buffer.items,
                );
            }
            return snapshot;
        }

        fn originalBytes(
            snapshot: *const ControlParserSnapshot,
            control: ControlState,
        ) []const u8 {
            if (snapshot.inline_buffer_valid) {
                return snapshot.inline_buffer[0..snapshot.buffer_len];
            }
            return control.peer_control_stream_buffer.items[0..snapshot.buffer_len];
        }

        fn restore(
            snapshot: *const ControlParserSnapshot,
            control: *ControlState,
        ) void {
            control.peer_control_stream_skip_remaining = snapshot.skip_remaining;
            control.peer_control_stream_buffer.items.len = snapshot.buffer_len;
            if (snapshot.inline_buffer_valid) {
                @memcpy(
                    control.peer_control_stream_buffer.items,
                    snapshot.inline_buffer[0..snapshot.buffer_len],
                );
            }
        }

        fn cloneOriginal(
            snapshot: *const ControlParserSnapshot,
            control: ControlState,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!ControlState {
            var copy = try control.cloneWithControlBufferLen(allocator, 0);
            errdefer copy.deinit(allocator);
            try copy.peer_control_stream_buffer.appendSlice(
                allocator,
                snapshot.originalBytes(control),
            );
            copy.peer_control_stream_skip_remaining = snapshot.skip_remaining;
            return copy;
        }
    };

    /// Reject known-invalid control frames as soon as their type and declared
    /// length are available. Waiting for the payload would let a peer retain a
    /// large, already-doomed frame across many QUIC STREAM fragments.
    fn validateControlFrameHeader(
        self: ControlState,
        header: Frame.Header,
    ) Error!void {
        if (!self.settings.received) {
            if (header.frame_type != FrameType.settings) {
                return error.MissingSettings;
            }
        } else if (header.frame_type == FrameType.settings) {
            return error.DuplicateSettings;
        }

        switch (header.frame_type) {
            FrameType.settings => if (header.payload_length >
                max_settings_payload_size)
            {
                return error.InvalidSetting;
            },
            FrameType.goaway,
            FrameType.cancel_push,
            FrameType.max_push_id,
            => if (header.payload_length == 0 or
                header.payload_length > 8)
            {
                return error.InvalidFrame;
            },
            FrameType.priority_update_request,
            FrameType.priority_update_push,
            => try self.validatePriorityUpdatePayloadSize(
                header.payload_length,
            ),
            FrameType.data,
            FrameType.headers,
            FrameType.push_promise,
            => return error.UnexpectedFrame,
            else => {},
        }
    }

    fn controlFrameMayMutateOrError(frame_type: u64) bool {
        return switch (frame_type) {
            FrameType.settings,
            FrameType.goaway,
            FrameType.max_push_id,
            FrameType.cancel_push,
            FrameType.origin,
            FrameType.priority_update_request,
            FrameType.priority_update_push,
            FrameType.data,
            FrameType.headers,
            FrameType.push_promise,
            FrameType.webtransport_stream,
            => true,
            else => false,
        };
    }

    fn validatePriorityUpdatePayloadSize(
        self: ControlState,
        payload_length: u64,
    ) Error!void {
        if (payload_length == 0) return error.InvalidFrame;
        const limit = std.math.cast(
            u64,
            self.max_priority_update_payload_size,
        ) orelse std.math.maxInt(u64);
        if (payload_length > limit) return error.ExcessiveLoad;
    }

    pub fn registerControlStream(self: *ControlState, stream_id: u64) Error!void {
        if (self.peer_control_stream_id) |existing| {
            if (existing != stream_id) return error.StreamCreationError;
            return;
        }
        self.peer_control_stream_id = stream_id;
    }

    pub fn registerQpackStream(self: *ControlState, stream_type: StreamType, stream_id: u64) Error!void {
        switch (stream_type) {
            .qpack_encoder => {
                if (self.peer_qpack_encoder_stream_id != null) return error.StreamCreationError;
                self.peer_qpack_encoder_stream_id = stream_id;
            },
            .qpack_decoder => {
                if (self.peer_qpack_decoder_stream_id != null) return error.StreamCreationError;
                self.peer_qpack_decoder_stream_id = stream_id;
            },
            else => return error.InvalidStreamType,
        }
    }

    pub fn applyFrame(self: *ControlState, allocator: std.mem.Allocator, frame: Frame) Error!void {
        if (!self.settings.received and frame.frame_type != FrameType.settings) return error.MissingSettings;

        switch (frame.frame_type) {
            FrameType.settings => {
                if (self.settings.received) return error.DuplicateSettings;
                const raw = try parseSettings(allocator, frame.payload);
                defer allocator.free(raw);
                const received = Settings.fromList(raw);
                if (self.early_data_peer_settings) |remembered| {
                    try remembered.validateAfterEarlyDataAccepted(received);
                }
                self.settings.markReceived(received);
                self.early_data_peer_settings = null;
            },
            FrameType.goaway => {
                const id = try parseGoAwayPayload(frame.payload);
                if (self.peer_goaway_id) |previous| {
                    if (id > previous) return error.GoAwayIdIncreased;
                }
                self.peer_goaway_id = id;
            },
            FrameType.max_push_id => {
                const push_id = try parseSingleVarintPayload(frame.payload);
                if (self.peer_max_push_id) |previous| {
                    if (push_id < previous) return error.MaxPushIdReduced;
                }
                self.peer_client_only_frame_generation = std.math.add(
                    u64,
                    self.peer_client_only_frame_generation,
                    1,
                ) catch return error.InvalidFrame;
                self.peer_max_push_id = push_id;
            },
            FrameType.cancel_push => {
                const push_id = try parseSingleVarintPayload(frame.payload);
                try self.storePushCancellation(allocator, push_id);
                self.peer_client_only_frame_generation = std.math.add(
                    u64,
                    self.peer_client_only_frame_generation,
                    1,
                ) catch return error.InvalidFrame;
            },
            FrameType.origin => try self.applyOriginFrame(
                allocator,
                frame.payload,
            ),
            FrameType.priority_update_request => {
                try self.validatePriorityUpdatePayloadSize(
                    frame.payload.len,
                );
                const priority_update = try parsePriorityUpdatePayload(frame.payload);
                validateRequestStreamId(
                    priority_update.prioritized_element_id,
                ) catch return error.IdError;
                try self.storePriorityUpdate(
                    allocator,
                    frame.frame_type,
                    priority_update,
                );
            },
            FrameType.priority_update_push => {
                try self.validatePriorityUpdatePayloadSize(
                    frame.payload.len,
                );
                try self.storePriorityUpdate(
                    allocator,
                    frame.frame_type,
                    try parsePriorityUpdatePayload(frame.payload),
                );
            },
            FrameType.data,
            FrameType.headers,
            FrameType.push_promise,
            FrameType.webtransport_stream,
            => return error.UnexpectedFrame,
            else => {}, // Unknown extension frames on the control stream are ignored.
        }
    }

    pub fn acceptsRequestStream(self: ControlState, stream_id: u64) bool {
        const goaway_id = self.peer_goaway_id orelse return true;
        return stream_id < goaway_id;
    }

    pub fn peerOrigins(self: ControlState) []const OriginKey {
        return self.peer_origins.items;
    }

    pub fn peerOriginSetInitialized(self: ControlState) bool {
        return self.peer_origin_set_initialized;
    }

    /// Monotonic authority-policy generation. ORIGIN updates and effective
    /// RFC 8336 removals both advance it so connection owners can publish an
    /// immutable authorization snapshot without rescanning on every response.
    pub fn peerOriginGeneration(self: ControlState) u64 {
        return self.peer_origin_generation;
    }

    pub fn peerOriginKnown(self: ControlState, origin: Origin) bool {
        return originListContains(self.peer_origins.items, origin);
    }

    pub fn peerOriginExcluded(self: ControlState, origin: Origin) bool {
        return originListContains(self.peer_origin_exclusions.items, origin);
    }

    /// Return null until the first ORIGIN frame initializes authority policy.
    /// Once initialized, the RFC 8336 Origin Set always includes the initial
    /// connection origin plus every valid advertised addition. Certificate
    /// verification remains a separate mandatory caller check.
    pub fn peerOriginSetAllows(
        self: ControlState,
        initial_origin: Origin,
        requested_origin: Origin,
    ) ?bool {
        if (!self.peer_origin_set_initialized) return null;
        if (originListContains(
            self.peer_origin_exclusions.items,
            requested_origin,
        )) return false;
        return sameOrigin(initial_origin, requested_origin) or
            self.peerOriginKnown(requested_origin);
    }

    fn applyOriginFrame(
        self: *ControlState,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) Error!void {
        const next_generation = std.math.add(
            u64,
            self.peer_origin_generation,
            1,
        ) catch return error.InvalidFrame;
        var parsed = try OriginPayload.parse(allocator, payload);
        defer parsed.deinit(allocator);
        var additions: std.ArrayList(OriginKey) = .empty;
        defer {
            for (additions.items) |*origin| origin.deinit();
            additions.deinit(allocator);
        }
        for (parsed.origins) |origin| {
            var key = requestOriginKeyFromSerialized(
                allocator,
                origin,
            ) catch |err| switch (err) {
                error.InvalidOrigin => continue,
                else => return err,
            };
            var duplicate = self.peerOriginKnown(key.origin());
            if (!duplicate) for (additions.items) |candidate| {
                if (sameOrigin(candidate.origin(), key.origin())) {
                    duplicate = true;
                    break;
                }
            };
            if (duplicate) {
                key.deinit();
                continue;
            }
            if (self.peer_origins.items.len + additions.items.len >=
                max_peer_origins)
            {
                key.deinit();
                return error.ExcessiveLoad;
            }
            additions.append(allocator, key) catch |err| {
                key.deinit();
                return err;
            };
        }
        try self.peer_origins.ensureUnusedCapacity(
            allocator,
            additions.items.len,
        );
        self.peer_origins.appendSliceAssumeCapacity(additions.items);
        additions.items.len = 0;
        // A later ORIGIN frame can re-add an origin removed by a 421 response.
        var excluded_index: usize = 0;
        while (excluded_index < self.peer_origin_exclusions.items.len) {
            if (!self.peerOriginKnown(
                self.peer_origin_exclusions.items[excluded_index].origin(),
            )) {
                excluded_index += 1;
                continue;
            }
            var removed = self.peer_origin_exclusions.orderedRemove(
                excluded_index,
            );
            removed.deinit();
        }
        self.peer_origin_set_initialized = true;
        self.peer_origin_generation = next_generation;
    }

    /// RFC 8336 removes an origin after a 421 response. The initial origin is
    /// supplied by the connection owner because this codec state does not own
    /// SNI or peer-address metadata. Removal is idempotent and preserves order.
    pub fn removePeerOrigin(
        self: *ControlState,
        allocator: std.mem.Allocator,
        origin: Origin,
    ) Error!void {
        const already_excluded = originListContains(
            self.peer_origin_exclusions.items,
            origin,
        );
        var peer_index: ?usize = null;
        for (self.peer_origins.items, 0..) |candidate, index| {
            if (sameOrigin(candidate.origin(), origin)) {
                peer_index = index;
                break;
            }
        }
        if (already_excluded and peer_index == null) return;
        const next_generation = std.math.add(
            u64,
            self.peer_origin_generation,
            1,
        ) catch return error.IntegerOverflow;
        if (!already_excluded) {
            if (self.peer_origin_exclusions.items.len >= max_peer_origins) {
                return error.ExcessiveLoad;
            }
            var owned = try cloneOrigin(allocator, origin);
            errdefer owned.deinit();
            try self.peer_origin_exclusions.append(allocator, owned);
        }
        if (peer_index) |index| {
            var removed = self.peer_origins.orderedRemove(index);
            removed.deinit();
        }
        self.peer_origin_generation = next_generation;
    }

    pub fn acceptsLocalRequestStream(self: ControlState, stream_id: u64) bool {
        const goaway_id = self.local_goaway_id orelse return true;
        return stream_id < goaway_id;
    }

    pub fn requestPriorityUpdate(
        self: ControlState,
        stream_id: u64,
    ) ?PriorityUpdatePayload {
        return self.priorityUpdate(
            FrameType.priority_update_request,
            stream_id,
        );
    }

    pub fn pushPriorityUpdate(
        self: ControlState,
        push_id: u64,
    ) ?PriorityUpdatePayload {
        return self.priorityUpdate(
            FrameType.priority_update_push,
            push_id,
        );
    }

    pub fn priorityUpdate(
        self: ControlState,
        frame_type: u64,
        prioritized_element_id: u64,
    ) ?PriorityUpdatePayload {
        if (self.priority_update_index.count() == 0) return null;
        const key = priorityUpdateKey(frame_type, prioritized_element_id);
        const index = self.priority_update_index.get(key) orelse return null;
        if (index >= self.priority_updates.items.len) return null;
        const update = self.priority_updates.items[index];
        if (update.frame_type != frame_type or
            update.payload.prioritized_element_id != prioritized_element_id)
        {
            return null;
        }
        return update.payload;
    }

    /// Forget request priority after the corresponding request becomes
    /// terminal. Removal is idempotent and repairs the swap-moved index entry.
    pub fn removeRequestPriority(
        self: *ControlState,
        allocator: std.mem.Allocator,
        stream_id: u64,
    ) void {
        self.removePriorityUpdate(
            allocator,
            FrameType.priority_update_request,
            stream_id,
        );
    }

    /// Forget push priority once the promised push is cancelled or its stream
    /// is complete. Keeping both element namespaces recyclable makes the bound
    /// a memory limit rather than a lifetime quota on long-lived connections.
    pub fn removePushPriority(
        self: *ControlState,
        allocator: std.mem.Allocator,
        push_id: u64,
    ) void {
        self.removePriorityUpdate(
            allocator,
            FrameType.priority_update_push,
            push_id,
        );
    }

    /// Mark a request priority namespace prefix as terminal and discard all
    /// retained hints in that prefix. Future late updates are discarded by
    /// `discardRetiredPriorityUpdates` after runtime validation.
    pub fn retireRequestPriority(
        self: *ControlState,
        allocator: std.mem.Allocator,
        stream_id: u64,
    ) void {
        self.retired_request_priority_through = if (self.retired_request_priority_through) |previous| @max(previous, stream_id) else stream_id;
        self.removePriorityPrefix(
            allocator,
            FrameType.priority_update_request,
            self.retired_request_priority_through.?,
        );
    }

    /// Mark a push priority namespace prefix as terminal. Push scheduling hints
    /// below the watermark may be discarded because priorities are advisory.
    pub fn retirePushPriority(
        self: *ControlState,
        allocator: std.mem.Allocator,
        push_id: u64,
    ) void {
        self.retired_push_priority_through = if (self.retired_push_priority_through) |previous| @max(previous, push_id) else push_id;
        self.removePriorityPrefix(
            allocator,
            FrameType.priority_update_push,
            self.retired_push_priority_through.?,
        );
    }

    /// Expose retained entries read-only so a runtime can validate or apply
    /// every update decoded from a batched control-stream fragment. Callers
    /// must not retain the slice across another mutating control operation.
    pub fn priorityUpdates(self: ControlState) []const StoredPriorityUpdate {
        return self.priority_updates.items;
    }

    /// Reclaim hints for element-ID prefixes the runtime has declared
    /// terminal. Calling this after each control-stream fragment also discards
    /// late updates without retaining an unbounded set of closed IDs.
    pub fn discardRetiredPriorityUpdates(
        self: *ControlState,
        allocator: std.mem.Allocator,
    ) void {
        if (self.retired_request_priority_through) |through| {
            self.removePriorityPrefix(
                allocator,
                FrameType.priority_update_request,
                through,
            );
        }
        if (self.retired_push_priority_through) |through| {
            self.removePriorityPrefix(
                allocator,
                FrameType.priority_update_push,
                through,
            );
        }
    }

    pub fn pushCancelled(self: ControlState, push_id: u64) bool {
        return self.peer_cancelled_push_ids.contains(push_id);
    }

    pub fn cancelledPushRangeCount(self: ControlState) usize {
        return self.peer_cancelled_push_ids.rangeCount();
    }

    fn storePushCancellation(
        self: *ControlState,
        allocator: std.mem.Allocator,
        push_id: u64,
    ) Error!void {
        if (self.peer_cancelled_push_ids.contains(push_id)) {
            return;
        }
        const next_generation = std.math.add(
            u64,
            self.push_cancellation_generation,
            1,
        ) catch return error.InvalidFrame;
        try self.peer_cancelled_push_ids.prepareInsertValue(
            allocator,
            push_id,
        );
        self.peer_cancelled_push_ids.insertAssumeCapacity(push_id);
        self.push_cancellation_generation = next_generation;
        self.retirePushPriority(allocator, push_id);
    }

    fn storePriorityUpdate(
        self: *ControlState,
        allocator: std.mem.Allocator,
        frame_type: u64,
        update: PriorityUpdatePayload,
    ) Error!void {
        const next_generation = std.math.add(
            u64,
            self.priority_update_generation,
            1,
        ) catch return error.InvalidPriorityUpdate;
        const key = priorityUpdateKey(
            frame_type,
            update.prioritized_element_id,
        );
        if (self.priority_update_index.count() != 0) {
            if (self.priority_update_index.get(key)) |index| {
                const stored = &self.priority_updates.items[index];
                if (std.mem.eql(u8, stored.payload.field_value, update.field_value)) {
                    self.latest_priority_update_type = frame_type;
                    self.latest_priority_update = stored.payload;
                    self.priority_update_generation = next_generation;
                    return;
                }
                const owned = try allocator.dupe(u8, update.field_value);
                errdefer allocator.free(owned);
                allocator.free(stored.payload.field_value);
                stored.payload.field_value = owned;
                self.latest_priority_update_type = frame_type;
                self.latest_priority_update = .{
                    .prioritized_element_id = update.prioritized_element_id,
                    .field_value = owned,
                };
                self.priority_update_generation = next_generation;
                return;
            }
        }
        if (self.priority_updates.items.len >= self.max_priority_updates) {
            return error.ExcessiveLoad;
        }
        const slot = try self.priority_update_index.getOrPut(allocator, key);
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.priority_update_index.remove(key);

        const owned = try allocator.dupe(u8, update.field_value);
        errdefer allocator.free(owned);
        try self.priority_updates.ensureUnusedCapacity(allocator, 1);
        const insert_index = self.priority_updates.items.len;
        self.priority_updates.appendAssumeCapacity(.{
            .frame_type = frame_type,
            .payload = .{
                .prioritized_element_id = update.prioritized_element_id,
                .field_value = owned,
            },
        });
        slot.value_ptr.* = insert_index;
        self.latest_priority_update_type = frame_type;
        self.latest_priority_update = .{
            .prioritized_element_id = update.prioritized_element_id,
            .field_value = owned,
        };
        self.priority_update_generation = next_generation;
    }

    fn removePriorityUpdate(
        self: *ControlState,
        allocator: std.mem.Allocator,
        frame_type: u64,
        prioritized_element_id: u64,
    ) void {
        const key = priorityUpdateKey(frame_type, prioritized_element_id);
        const index = self.priority_update_index.get(key) orelse return;
        const removed_was_latest = self.latest_priority_update_type == frame_type and
            self.latest_priority_update != null and
            self.latest_priority_update.?.prioritized_element_id ==
                prioritized_element_id;
        _ = self.priority_update_index.remove(key);
        var removed = self.priority_updates.swapRemove(index);
        removed.deinit(allocator);
        if (index < self.priority_updates.items.len) {
            const moved = self.priority_updates.items[index];
            const moved_key = priorityUpdateKey(
                moved.frame_type,
                moved.payload.prioritized_element_id,
            );
            self.priority_update_index.getPtr(moved_key).?.* = index;
        }
        if (removed_was_latest) {
            self.latest_priority_update = null;
            self.latest_priority_update_type = null;
        }
    }

    fn removePriorityPrefix(
        self: *ControlState,
        allocator: std.mem.Allocator,
        frame_type: u64,
        through: u64,
    ) void {
        var index: usize = 0;
        while (index < self.priority_updates.items.len) {
            const update = self.priority_updates.items[index];
            if (update.frame_type != frame_type or
                update.payload.prioritized_element_id > through)
            {
                index += 1;
                continue;
            }
            self.removePriorityUpdate(
                allocator,
                update.frame_type,
                update.payload.prioritized_element_id,
            );
            // swapRemove moved an unchecked entry into `index`.
        }
    }

    fn priorityUpdateKey(
        frame_type: u64,
        prioritized_element_id: u64,
    ) PriorityUpdateKey {
        return .{
            .frame_type = frame_type,
            .prioritized_element_id = prioritized_element_id,
        };
    }
};
