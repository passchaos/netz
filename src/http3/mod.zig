const std = @import("std");
const wire = @import("../internal/wire.zig");
const quic = @import("../quic/mod.zig");
const hpack_huffman = @import("../http2/hpack_huffman.zig");

pub const runtime = @import("runtime.zig");

pub const Error = wire.Error || error{
    BufferTooShort,
    InvalidFrame,
    InvalidSetting,
    InvalidStreamType,
    MissingSettings,
    DuplicateSettings,
    GoAwayIdIncreased,
    MaxPushIdReduced,
    PushIdExceeded,
    DuplicatePushId,
    ExpectedHeadersFrame,
    UnexpectedFrame,
    MissingMethod,
    MissingPath,
    MissingStatus,
    InvalidStatus,
    InvalidHeader,
    InvalidPriorityUpdate,
    StreamCreationError,
    RequestCancelled,
    RequestIncomplete,
    InvalidContentLength,
    IntegerOverflow,
    ExcessiveLoad,
    ExtendedConnectDisabled,
    QpackDynamicTableUnsupported,
    QpackEncoderStreamError,
    QpackDecoderStreamError,
    QpackDecompressionFailed,
    QpackBlocked,
} || std.mem.Allocator.Error;

pub const max_settings_payload_size: usize = 256;

pub const ApplicationErrorCode = struct {
    pub const request_rejected: u64 = 0x10b;
    pub const request_cancelled: u64 = 0x10c;
    pub const request_incomplete: u64 = 0x10d;
};

pub const FrameType = struct {
    pub const data: u64 = 0x00;
    pub const headers: u64 = 0x01;
    pub const cancel_push: u64 = 0x03;
    pub const settings: u64 = 0x04;
    pub const push_promise: u64 = 0x05;
    pub const goaway: u64 = 0x07;
    pub const max_push_id: u64 = 0x0d;
    pub const priority_update_request: u64 = 0x0f0700;
    pub const priority_update_push: u64 = 0x0f0701;
    pub const webtransport_stream: u64 = 0x41;
};

pub const StreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
    webtransport_unidirectional = 0x54,
    _,
};

pub const Frame = struct {
    pub const Header = struct {
        frame_type: u64,
        payload_length: usize,
        header_length: usize,

        pub fn totalLength(self: Header) Error!usize {
            return std.math.add(
                usize,
                self.header_length,
                self.payload_length,
            ) catch error.IntegerOverflow;
        }
    };

    frame_type: u64,
    payload: []const u8,
    consumed: usize,

    /// Parse only type and payload length.
    ///
    /// This succeeds as soon as both varints are available, even when the
    /// payload is split across later QUIC STREAM frames.
    pub fn parseHeader(bytes: []const u8) Error!Header {
        var cursor = wire.Cursor.init(bytes);
        const frame_type = try quic.varint.decode(&cursor);
        try validateFrameType(frame_type);
        const encoded_length = try quic.varint.decode(&cursor);
        const payload_length = std.math.cast(
            usize,
            encoded_length,
        ) orelse return error.IntegerOverflow;
        const header: Header = .{
            .frame_type = frame_type,
            .payload_length = payload_length,
            .header_length = cursor.pos,
        };
        _ = try header.totalLength();
        return header;
    }

    pub fn parse(bytes: []const u8) Error!Frame {
        const header = try parseHeader(bytes);
        const total_length = try header.totalLength();
        if (bytes.len < total_length) return error.BufferTooShort;
        return .{
            .frame_type = header.frame_type,
            .payload = bytes[header.header_length..total_length],
            .consumed = total_length,
        };
    }

    pub fn write(self: Frame, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        try validateFrameType(self.frame_type);
        try validateFramePayloadShape(self.frame_type, self.payload);
        try quic.varint.encode(list, allocator, self.frame_type);
        try quic.varint.encode(list, allocator, self.payload.len);
        try list.appendSlice(allocator, self.payload);
    }
};

fn validateFrameType(frame_type: u64) Error!void {
    switch (frame_type) {
        // RFC 9114 §7.2.8 reserves the HTTP/2 frame type code points that have
        // no HTTP/3 semantics.  tquic and quic-zig reject them as
        // H3_FRAME_UNEXPECTED rather than treating them as ignorable extension
        // frames; do the same at the frame parser boundary so every stream
        // context gets consistent behavior.
        0x02, 0x06, 0x08, 0x09 => return error.UnexpectedFrame,
        else => {},
    }
}

fn validateFramePayloadShape(frame_type: u64, payload: []const u8) Error!void {
    switch (frame_type) {
        FrameType.goaway,
        FrameType.cancel_push,
        FrameType.max_push_id,
        => _ = try parseSingleVarintPayload(payload),
        FrameType.push_promise => _ = try parsePushPromisePayload(payload),
        FrameType.priority_update_request,
        FrameType.priority_update_push,
        => _ = try parsePriorityUpdatePayload(payload),
        else => {},
    }
}

pub const SettingId = enum(u64) {
    qpack_max_table_capacity = 0x01,
    max_field_section_size = 0x06,
    qpack_blocked_streams = 0x07,
    enable_connect_protocol = 0x08,
    h3_datagram = 0x33,
    /// Legacy WebTransport enable/max-session identifier seen in older
    /// WebTransport drafts and retained by earlier netz releases.  Peers in
    /// the wild disagree on whether this identifier is a boolean enable bit or
    /// a session count, so Settings.fromList accepts either non-zero form.
    webtransport_max_sessions = 0x2b603742,
    enable_webtransport = 0x2c7cf000,
    webtransport_max_sessions_draft = 0xc671706a,
    webtransport_max_sessions_v13 = 0x14e9cd29,
    webtransport_initial_max_data = 0x2b61,
    webtransport_initial_max_streams_uni = 0x2b64,
    webtransport_initial_max_streams_bidi = 0x2b65,
    _,
};

pub const Setting = struct {
    id: u64,
    value: u64,
};

pub const Settings = struct {
    /// Hard implementation cap; each runtime additionally bounds this by its
    /// configured concurrent request-stream retention limit.
    pub const max_supported_qpack_blocked_streams: u64 = 128;

    qpack_max_table_capacity: u64 = 0,
    /// RFC 9114 inherits the HTTP semantics that an omitted
    /// SETTINGS_MAX_FIELD_SECTION_SIZE means "no advertised limit".  Mature
    /// stacks such as tquic represent this as None/unbounded; use maxInt here
    /// so callers can still compare against a concrete value.
    max_field_section_size: u64 = std.math.maxInt(u64),
    qpack_blocked_streams: u64 = 0,
    enable_connect_protocol: bool = false,
    h3_datagram: bool = false,
    enable_webtransport: bool = false,
    webtransport_max_sessions: u64 = 0,
    webtransport_initial_max_data: u64 = 0,
    webtransport_initial_max_streams_uni: u64 = 0,
    webtransport_initial_max_streams_bidi: u64 = 0,

    pub fn fromList(settings: []const Setting) Settings {
        var out: Settings = .{};
        for (settings) |setting| {
            switch (setting.id) {
                @intFromEnum(SettingId.qpack_max_table_capacity) => out.qpack_max_table_capacity = setting.value,
                @intFromEnum(SettingId.max_field_section_size) => out.max_field_section_size = setting.value,
                @intFromEnum(SettingId.qpack_blocked_streams) => out.qpack_blocked_streams = setting.value,
                @intFromEnum(SettingId.enable_connect_protocol) => out.enable_connect_protocol = setting.value != 0,
                @intFromEnum(SettingId.h3_datagram) => out.h3_datagram = setting.value != 0,
                @intFromEnum(SettingId.enable_webtransport) => out.enable_webtransport = setting.value != 0,
                @intFromEnum(SettingId.webtransport_max_sessions) => {
                    if (setting.value != 0) out.enable_webtransport = true;
                    // Older drafts used this identifier inconsistently: some
                    // peers send it as a boolean enable bit, while older netz
                    // used it as the session count.  Preserve a real count
                    // received under newer identifiers if this legacy bit
                    // arrives later in the SETTINGS payload.
                    if (setting.value > 1 or out.webtransport_max_sessions == 0) {
                        out.webtransport_max_sessions = setting.value;
                    }
                },
                @intFromEnum(SettingId.webtransport_max_sessions_draft),
                @intFromEnum(SettingId.webtransport_max_sessions_v13),
                => {
                    out.webtransport_max_sessions = setting.value;
                    if (setting.value != 0) out.enable_webtransport = true;
                },
                @intFromEnum(SettingId.webtransport_initial_max_data) => out.webtransport_initial_max_data = setting.value,
                @intFromEnum(SettingId.webtransport_initial_max_streams_uni) => out.webtransport_initial_max_streams_uni = setting.value,
                @intFromEnum(SettingId.webtransport_initial_max_streams_bidi) => out.webtransport_initial_max_streams_bidi = setting.value,
                else => {}, // RFC 9114 requires unknown settings to be ignored.
            }
        }
        return out;
    }

    pub fn writePayload(self: Settings, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try self.validateLocal();
        if (self.qpack_max_table_capacity != 0) try writeSetting(list, allocator, .qpack_max_table_capacity, self.qpack_max_table_capacity);
        if (self.max_field_section_size != std.math.maxInt(u64)) try writeSetting(list, allocator, .max_field_section_size, self.max_field_section_size);
        if (self.qpack_blocked_streams != 0) try writeSetting(list, allocator, .qpack_blocked_streams, self.qpack_blocked_streams);
        if (self.enable_connect_protocol) try writeSetting(list, allocator, .enable_connect_protocol, 1);
        if (self.h3_datagram) try writeSetting(list, allocator, .h3_datagram, 1);
        const webtransport_enabled = self.enable_webtransport or self.webtransport_max_sessions != 0;
        if (webtransport_enabled) {
            // Emit both legacy enable identifiers.  The historical netz name
            // for 0x2b603742 is kept for source compatibility, but writing a
            // boolean value here avoids peers that validate it as an enable bit
            // rejecting counts greater than one.  The concrete max-session
            // count is emitted below under the newer identifiers.
            try writeSetting(list, allocator, .webtransport_max_sessions, 1);
            try writeSetting(list, allocator, .enable_webtransport, 1);
        }
        if (self.webtransport_max_sessions != 0) {
            try writeSetting(list, allocator, .webtransport_max_sessions_draft, self.webtransport_max_sessions);
            try writeSetting(list, allocator, .webtransport_max_sessions_v13, self.webtransport_max_sessions);
        }
        if (self.webtransport_initial_max_data != 0) try writeSetting(list, allocator, .webtransport_initial_max_data, self.webtransport_initial_max_data);
        if (self.webtransport_initial_max_streams_uni != 0) try writeSetting(list, allocator, .webtransport_initial_max_streams_uni, self.webtransport_initial_max_streams_uni);
        if (self.webtransport_initial_max_streams_bidi != 0) try writeSetting(list, allocator, .webtransport_initial_max_streams_bidi, self.webtransport_initial_max_streams_bidi);
    }

    pub fn validateLocal(self: Settings) Error!void {
        if (self.qpack_blocked_streams > max_supported_qpack_blocked_streams) {
            return error.QpackDynamicTableUnsupported;
        }
        if (std.math.cast(usize, self.qpack_max_table_capacity) == null) {
            return error.InvalidSetting;
        }
    }
};

fn writeSetting(list: *std.ArrayList(u8), allocator: std.mem.Allocator, id: SettingId, value: u64) Error!void {
    try quic.varint.encode(list, allocator, @intFromEnum(id));
    try quic.varint.encode(list, allocator, value);
}

pub const SettingsState = struct {
    local: Settings = .{},
    peer: Settings = .{},
    sent: bool = false,
    received: bool = false,

    pub fn markSent(self: *SettingsState, settings: Settings) void {
        self.local = settings;
        self.sent = true;
    }

    pub fn markReceived(self: *SettingsState, settings: Settings) void {
        self.peer = settings;
        self.received = true;
    }

    pub fn ready(self: SettingsState) bool {
        return self.sent and self.received;
    }
};

pub const ControlState = struct {
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

    settings: SettingsState = .{},
    peer_goaway_id: ?u64 = null,
    local_goaway_id: ?u64 = null,
    peer_max_push_id: ?u64 = null,
    local_max_push_id: ?u64 = null,
    /// Most recent peer CANCEL_PUSH identifier, retained for compatibility.
    peer_cancelled_push_id: ?u64 = null,
    /// Every distinct peer-cancelled push ID in receive order.
    peer_cancelled_push_ids: std.ArrayList(u64) = .empty,
    push_cancellation_generation: u64 = 0,
    peer_control_stream_id: ?u64 = null,
    latest_priority_update: ?PriorityUpdatePayload = null,
    latest_priority_update_type: ?u64 = null,
    priority_updates: std.ArrayList(StoredPriorityUpdate) = .empty,
    priority_update_generation: u64 = 0,
    peer_qpack_encoder_stream_id: ?u64 = null,
    peer_qpack_decoder_stream_id: ?u64 = null,

    pub fn deinit(self: *ControlState, allocator: std.mem.Allocator) void {
        for (self.priority_updates.items) |*update| {
            update.deinit(allocator);
        }
        self.priority_updates.deinit(allocator);
        self.peer_cancelled_push_ids.deinit(allocator);
        self.* = undefined;
    }

    pub fn clone(
        self: ControlState,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!ControlState {
        var copy = self;
        copy.latest_priority_update = null;
        copy.priority_updates = .empty;
        copy.peer_cancelled_push_ids = .empty;
        errdefer copy.deinit(allocator);
        try copy.peer_cancelled_push_ids.appendSlice(
            allocator,
            self.peer_cancelled_push_ids.items,
        );
        try copy.priority_updates.ensureTotalCapacity(
            allocator,
            self.priority_updates.items.len,
        );
        for (self.priority_updates.items) |update| {
            const owned = try allocator.dupe(
                u8,
                update.payload.field_value,
            );
            copy.priority_updates.appendAssumeCapacity(.{
                .frame_type = update.frame_type,
                .payload = .{
                    .prioritized_element_id = update.payload.prioritized_element_id,
                    .field_value = owned,
                },
            });
        }
        if (copy.priority_updates.items.len != 0) {
            copy.latest_priority_update =
                copy.priority_updates.items[
                    copy.priority_updates.items.len - 1
                ].payload;
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

        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        try quic.varint.encode(&payload, allocator, stream_id);
        try (Frame{ .frame_type = FrameType.goaway, .payload = payload.items, .consumed = 0 }).write(list, allocator);
        self.local_goaway_id = stream_id;
    }

    pub fn writeMaxPushId(self: *ControlState, list: *std.ArrayList(u8), allocator: std.mem.Allocator, push_id: u64) Error!void {
        if (self.local_max_push_id) |previous| {
            if (push_id < previous) return error.MaxPushIdReduced;
        }
        try writeMaxPushIdFrame(list, allocator, push_id);
        self.local_max_push_id = push_id;
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
                self.settings.markReceived(Settings.fromList(raw));
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
                self.peer_max_push_id = push_id;
            },
            FrameType.cancel_push => {
                const push_id = try parseSingleVarintPayload(frame.payload);
                try self.storePushCancellation(allocator, push_id);
            },
            FrameType.priority_update_request => {
                const priority_update = try parsePriorityUpdatePayload(frame.payload);
                try validateRequestStreamId(priority_update.prioritized_element_id);
                try self.storePriorityUpdate(
                    allocator,
                    frame.frame_type,
                    priority_update,
                );
            },
            FrameType.priority_update_push => {
                try self.storePriorityUpdate(
                    allocator,
                    frame.frame_type,
                    try parsePriorityUpdatePayload(frame.payload),
                );
            },
            FrameType.data, FrameType.headers, FrameType.push_promise => return error.UnexpectedFrame,
            else => {}, // Unknown extension frames on the control stream are ignored.
        }
    }

    pub fn acceptsRequestStream(self: ControlState, stream_id: u64) bool {
        const goaway_id = self.peer_goaway_id orelse return true;
        return stream_id < goaway_id;
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
        for (self.priority_updates.items) |update| {
            if (update.frame_type == frame_type and
                update.payload.prioritized_element_id ==
                    prioritized_element_id)
            {
                return update.payload;
            }
        }
        return null;
    }

    pub fn pushCancelled(self: ControlState, push_id: u64) bool {
        for (self.peer_cancelled_push_ids.items) |cancelled| {
            if (cancelled == push_id) return true;
        }
        return false;
    }

    fn storePushCancellation(
        self: *ControlState,
        allocator: std.mem.Allocator,
        push_id: u64,
    ) Error!void {
        if (self.pushCancelled(push_id)) {
            self.peer_cancelled_push_id = push_id;
            return;
        }
        const next_generation = std.math.add(
            u64,
            self.push_cancellation_generation,
            1,
        ) catch return error.InvalidFrame;
        try self.peer_cancelled_push_ids.append(allocator, push_id);
        self.peer_cancelled_push_id = push_id;
        self.push_cancellation_generation = next_generation;
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
        const owned = try allocator.dupe(u8, update.field_value);
        errdefer allocator.free(owned);

        var existing_index: ?usize = null;
        for (self.priority_updates.items, 0..) |stored, index| {
            if (stored.frame_type == frame_type and
                stored.payload.prioritized_element_id ==
                    update.prioritized_element_id)
            {
                existing_index = index;
                break;
            }
        }
        if (existing_index == null) {
            try self.priority_updates.ensureUnusedCapacity(allocator, 1);
        }
        if (existing_index) |index| {
            var replaced = self.priority_updates.orderedRemove(index);
            replaced.deinit(allocator);
        }
        self.priority_updates.appendAssumeCapacity(.{
            .frame_type = frame_type,
            .payload = .{
                .prioritized_element_id = update.prioritized_element_id,
                .field_value = owned,
            },
        });
        self.latest_priority_update_type = frame_type;
        self.latest_priority_update = .{
            .prioritized_element_id = update.prioritized_element_id,
            .field_value = owned,
        };
        self.priority_update_generation = next_generation;
    }
};

pub const PushPromisePayload = struct {
    push_id: u64,
    field_section: []const u8,
};

pub const DecodedPushPromise = struct {
    push_id: u64,
    request: DecodedRequestHead,

    pub fn deinit(
        self: *DecodedPushPromise,
        allocator: std.mem.Allocator,
    ) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

pub const Priority = struct {
    urgency: u3 = 3,
    incremental: bool = false,

    pub fn parse(value: []const u8) Priority {
        var result = Priority{};
        var rest = value;
        while (rest.len != 0) {
            rest = trimPriorityLeading(rest);
            if (rest.len == 0) break;
            if (rest[0] == ',') {
                rest = rest[1..];
                continue;
            }

            const name_end = priorityNameEnd(rest);
            const name = rest[0..name_end];
            rest = trimPriorityLeading(rest[name_end..]);
            if (rest.len != 0 and rest[0] == '=') {
                rest = trimPriorityLeading(rest[1..]);
                const value_end = priorityValueEnd(rest);
                const parameter_value = rest[0..value_end];
                rest = rest[value_end..];
                if (std.mem.eql(u8, name, "u")) {
                    if (parameter_value.len == 1 and parameter_value[0] >= '0' and parameter_value[0] <= '7') {
                        result.urgency = @intCast(parameter_value[0] - '0');
                    }
                } else if (std.mem.eql(u8, name, "i")) {
                    if (std.mem.eql(u8, parameter_value, "?1")) result.incremental = true;
                    if (std.mem.eql(u8, parameter_value, "?0")) result.incremental = false;
                }
            } else if (std.mem.eql(u8, name, "i")) {
                result.incremental = true;
            }
        }
        return result;
    }

    pub fn serialize(self: Priority, out: []u8) []const u8 {
        var pos: usize = 0;
        if (self.urgency != 3) {
            if (out.len < 3) return out[0..0];
            out[pos] = 'u';
            pos += 1;
            out[pos] = '=';
            pos += 1;
            out[pos] = '0' + @as(u8, self.urgency);
            pos += 1;
        }
        if (self.incremental) {
            if (pos != 0) {
                if (pos + 2 > out.len) return out[0..pos];
                out[pos] = ',';
                pos += 1;
                out[pos] = ' ';
                pos += 1;
            }
            if (pos + 1 > out.len) return out[0..pos];
            out[pos] = 'i';
            pos += 1;
        }
        return out[0..pos];
    }
};

pub const PriorityUpdatePayload = struct {
    prioritized_element_id: u64,
    field_value: []const u8,

    pub fn priority(self: PriorityUpdatePayload) Priority {
        return Priority.parse(self.field_value);
    }
};

fn trimPriorityLeading(value: []const u8) []const u8 {
    var i: usize = 0;
    while (i < value.len and (value[i] == ' ' or value[i] == 0x09)) : (i += 1) {}
    return value[i..];
}

fn priorityNameEnd(value: []const u8) usize {
    var i: usize = 0;
    while (i < value.len and value[i] != '=' and value[i] != ',' and value[i] != ' ' and value[i] != 0x09) : (i += 1) {}
    return i;
}

fn priorityValueEnd(value: []const u8) usize {
    var i: usize = 0;
    while (i < value.len and value[i] != ',' and value[i] != ' ' and value[i] != 0x09) : (i += 1) {}
    return i;
}

pub fn writeControlStreamPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    try quic.varint.encode(list, allocator, @intFromEnum(StreamType.control));
}

pub fn writeQpackEncoderStreamPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    try quic.varint.encode(list, allocator, @intFromEnum(StreamType.qpack_encoder));
}

pub fn writeQpackDecoderStreamPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    try quic.varint.encode(list, allocator, @intFromEnum(StreamType.qpack_decoder));
}

pub fn writeSettingsFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: Settings) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try settings.writePayload(&payload, allocator);
    try (Frame{ .frame_type = FrameType.settings, .payload = payload.items, .consumed = 0 }).write(list, allocator);
}

pub fn parseGoAwayPayload(payload: []const u8) Error!u64 {
    return parseSingleVarintPayload(payload);
}

pub fn writeCancelPushFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, push_id: u64) Error!void {
    try writeSingleVarintFrame(list, allocator, FrameType.cancel_push, push_id);
}

pub fn parseCancelPushPayload(payload: []const u8) Error!u64 {
    return parseSingleVarintPayload(payload);
}

pub fn writeMaxPushIdFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, push_id: u64) Error!void {
    try writeSingleVarintFrame(list, allocator, FrameType.max_push_id, push_id);
}

pub fn parseMaxPushIdPayload(payload: []const u8) Error!u64 {
    return parseSingleVarintPayload(payload);
}

pub fn writePushPromiseFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    push_id: u64,
    field_section: []const u8,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try quic.varint.encode(&payload, allocator, push_id);
    try payload.appendSlice(allocator, field_section);
    try (Frame{ .frame_type = FrameType.push_promise, .payload = payload.items, .consumed = 0 }).write(list, allocator);
}

pub fn writePushPromiseDynamic(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    push_id: u64,
    promised_request: Request,
    peer_settings: Settings,
    request_stream_id: u64,
    encoder: anytype,
) Error!void {
    if (promised_request.body.len != 0 or
        promised_request.trailers.len != 0)
    {
        return error.InvalidContentLength;
    }
    var fields_buf: [64]Qpack.HeaderField = undefined;
    const fields = try promised_request.headerFields(&fields_buf);
    try validateHeaderBlock(fields, .request);
    try validateFieldSectionSize(
        fields,
        peer_settings.max_field_section_size,
    );
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(
        &block,
        request_stream_id,
        fields,
    );
    try writePushPromiseFrame(list, allocator, push_id, block.items);
    try queueIndexableFields(encoder, fields);
}

pub fn parsePushPromisePayload(payload: []const u8) Error!PushPromisePayload {
    var cursor = wire.Cursor.init(payload);
    const push_id = quic.varint.decode(&cursor) catch return error.InvalidFrame;
    return .{ .push_id = push_id, .field_section = payload[cursor.pos..] };
}

/// Decode and own the promised request field section.
pub fn decodePushPromiseWithDynamicTable(
    allocator: std.mem.Allocator,
    payload: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedPushPromise {
    const promise = try parsePushPromisePayload(payload);
    var request = try decodeRequestHeadFieldSectionWithDynamicTable(
        allocator,
        promise.field_section,
        settings,
        table,
    );
    errdefer request.deinit(allocator);
    request.consumed = payload.len;
    return .{ .push_id = promise.push_id, .request = request };
}

pub fn writePriorityUpdateFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    request_stream_id: u64,
    priority: Priority,
) Error!void {
    try validateRequestStreamId(request_stream_id);
    var field_value_buf: [16]u8 = undefined;
    const field_value = priority.serialize(&field_value_buf);
    try writePriorityUpdateFrameRaw(list, allocator, FrameType.priority_update_request, request_stream_id, field_value);
}

pub fn writePushPriorityUpdateFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    push_id: u64,
    priority: Priority,
) Error!void {
    var field_value_buf: [16]u8 = undefined;
    const field_value = priority.serialize(&field_value_buf);
    try writePriorityUpdateFrameRaw(
        list,
        allocator,
        FrameType.priority_update_push,
        push_id,
        field_value,
    );
}

pub fn writePriorityUpdateFrameRaw(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    frame_type: u64,
    prioritized_element_id: u64,
    field_value: []const u8,
) Error!void {
    if (frame_type != FrameType.priority_update_request and frame_type != FrameType.priority_update_push) return error.InvalidPriorityUpdate;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try quic.varint.encode(&payload, allocator, prioritized_element_id);
    try payload.appendSlice(allocator, field_value);
    try (Frame{ .frame_type = frame_type, .payload = payload.items, .consumed = 0 }).write(list, allocator);
}

pub fn parsePriorityUpdatePayload(payload: []const u8) Error!PriorityUpdatePayload {
    var cursor = wire.Cursor.init(payload);
    const id = quic.varint.decode(&cursor) catch return error.InvalidFrame;
    return .{ .prioritized_element_id = id, .field_value = payload[cursor.pos..] };
}

fn validateRequestStreamId(stream_id: u64) Error!void {
    if ((stream_id & 0x3) != 0) return error.UnexpectedFrame;
}

pub fn validatePushPromise(control: ControlState, push_id: u64) Error!void {
    const max_push_id = control.local_max_push_id orelse return error.PushIdExceeded;
    if (push_id > max_push_id) return error.PushIdExceeded;
}

pub fn validateResponsePushPromises(control: ControlState, bytes: []const u8) Error!void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = try Frame.parse(bytes[offset..]);
        if (frame.frame_type == FrameType.push_promise) {
            const promise = try parsePushPromisePayload(frame.payload);
            try validatePushPromise(control, promise.push_id);
        }
        offset += frame.consumed;
    }
}

fn writeSingleVarintFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, frame_type: u64, value: u64) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try quic.varint.encode(&payload, allocator, value);
    try (Frame{ .frame_type = frame_type, .payload = payload.items, .consumed = 0 }).write(list, allocator);
}

fn parseSingleVarintPayload(payload: []const u8) Error!u64 {
    var cursor = wire.Cursor.init(payload);
    const value = quic.varint.decode(&cursor) catch return error.InvalidFrame;
    if (!cursor.eof()) return error.InvalidFrame;
    return value;
}

pub fn parseSettings(allocator: std.mem.Allocator, payload: []const u8) Error![]Setting {
    if (payload.len > max_settings_payload_size) return error.InvalidSetting;
    var cursor = wire.Cursor.init(payload);
    var settings: std.ArrayList(Setting) = .empty;
    errdefer settings.deinit(allocator);
    while (!cursor.eof()) {
        const id = quic.varint.decode(&cursor) catch return error.InvalidSetting;
        const value = quic.varint.decode(&cursor) catch return error.InvalidSetting;
        try validateSetting(id, value, settings.items);
        try settings.append(allocator, .{ .id = id, .value = value });
    }
    return settings.toOwnedSlice(allocator);
}

fn validateSetting(id: u64, value: u64, seen: []const Setting) Error!void {
    for (seen) |setting| {
        if (setting.id == id) return error.InvalidSetting;
    }

    switch (id) {
        // RFC 9114 reserves HTTP/2 SETTINGS identifiers that have no HTTP/3
        // meaning.  Reference stacks such as tquic and quic-zig reject these as
        // H3_SETTINGS_ERROR instead of silently ignoring them.
        0x00, 0x02, 0x03, 0x04, 0x05 => return error.InvalidSetting,
        @intFromEnum(SettingId.enable_connect_protocol),
        @intFromEnum(SettingId.h3_datagram),
        @intFromEnum(SettingId.enable_webtransport),
        => if (value > 1) return error.InvalidSetting,
        else => {},
    }
}

pub fn writeSettings(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: []const Setting) Error!void {
    for (settings, 0..) |setting, index| {
        try validateSetting(setting.id, setting.value, settings[0..index]);
        try quic.varint.encode(list, allocator, setting.id);
        try quic.varint.encode(list, allocator, setting.value);
    }
}

pub const ControlStream = struct {
    stream_type: StreamType,
    frames: []Frame,

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) Error!ControlStream {
        var cursor = wire.Cursor.init(bytes);
        const stream_type: StreamType = @enumFromInt(try quic.varint.decode(&cursor));
        if (stream_type != .control) return error.InvalidStreamType;
        var frames: std.ArrayList(Frame) = .empty;
        errdefer frames.deinit(allocator);
        while (!cursor.eof()) {
            const frame = try Frame.parse(bytes[cursor.pos..]);
            cursor.pos += frame.consumed;
            try frames.append(allocator, frame);
        }
        return .{ .stream_type = stream_type, .frames = try frames.toOwnedSlice(allocator) };
    }

    pub fn deinit(self: *ControlStream, allocator: std.mem.Allocator) void {
        allocator.free(self.frames);
        self.* = undefined;
    }
};

pub const Qpack = struct {
    pub const HeaderField = struct {
        name: []const u8,
        value: []const u8,
        never_indexed: bool = false,
        /// Set when a decoded Huffman string had to be materialized.  Call
        /// `Qpack.freeDecodedFields` for decoder output so these allocations
        /// are released while non-Huffman strings can continue borrowing from
        /// the encoded field section.
        name_storage: ?[]u8 = null,
        value_storage: ?[]u8 = null,
    };

    pub const dynamic_entry_overhead: usize = 32;

    fn dynamicStringHash(bytes: []const u8) u64 {
        return std.hash.Wyhash.hash(0, bytes);
    }

    pub const DynamicEntry = struct {
        absolute_index: u64,
        name: []u8,
        value: []u8,
        name_hash: u64,
        value_hash: u64,

        pub fn size(self: DynamicEntry) usize {
            return self.name.len + self.value.len + dynamic_entry_overhead;
        }

        fn deinit(self: *DynamicEntry, allocator: std.mem.Allocator) void {
            allocator.free(self.name);
            allocator.free(self.value);
            self.* = undefined;
        }
    };

    /// RFC 9204 dynamic table, ordered oldest-to-newest.
    ///
    /// `head` avoids O(n) shifts on eviction. Compaction is deferred until the
    /// consumed prefix is at least half the allocation, keeping inserts and
    /// normal capacity pressure amortized O(1) while absolute indexes remain
    /// explicit and independent of storage position.
    pub const DynamicTable = struct {
        pub const Match = struct {
            absolute_index: u64,
            full_match: bool,
        };

        allocator: std.mem.Allocator,
        entries: std.ArrayList(DynamicEntry) = .empty,
        head: usize = 0,
        current_size: usize = 0,
        capacity: usize = 0,
        max_capacity: usize,
        insert_count: u64 = 0,

        pub fn init(allocator: std.mem.Allocator, max_capacity: usize) DynamicTable {
            return .{ .allocator = allocator, .max_capacity = max_capacity };
        }

        pub fn deinit(self: *DynamicTable) void {
            for (self.entries.items[self.head..]) |*entry| entry.deinit(self.allocator);
            self.entries.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn entryCount(self: DynamicTable) usize {
            return self.entries.items.len - self.head;
        }

        pub fn maxEntries(self: DynamicTable) u64 {
            return @intCast(self.max_capacity / dynamic_entry_overhead);
        }

        pub fn setCapacity(self: *DynamicTable, new_capacity: usize) Error!void {
            if (new_capacity > self.max_capacity) return error.QpackEncoderStreamError;
            self.capacity = new_capacity;
            self.evictToFit(0);
        }

        pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) Error!u64 {
            const entry_size = dynamicEntrySize(name, value) catch return error.QpackEncoderStreamError;
            if (entry_size > self.capacity) {
                self.clearEntries();
                return error.QpackEncoderStreamError;
            }
            const next_insert_count = std.math.add(u64, self.insert_count, 1) catch
                return error.QpackEncoderStreamError;
            // Name/value can borrow from an entry that this insertion evicts
            // (Duplicate and dynamic-name-reference instructions both allow
            // this). Stabilize them before changing table ownership.
            self.compactIfNeeded();
            try self.entries.ensureUnusedCapacity(self.allocator, 1);
            const name_copy = try self.allocator.dupe(u8, name);
            errdefer self.allocator.free(name_copy);
            const value_copy = try self.allocator.dupe(u8, value);
            errdefer self.allocator.free(value_copy);
            self.evictToFit(entry_size);

            const absolute_index = self.insert_count;
            self.entries.appendAssumeCapacity(.{
                .absolute_index = absolute_index,
                .name = name_copy,
                .value = value_copy,
                .name_hash = dynamicStringHash(name),
                .value_hash = dynamicStringHash(value),
            });
            self.current_size += entry_size;
            self.insert_count = next_insert_count;
            return absolute_index;
        }

        pub fn duplicate(self: *DynamicTable, relative_index: u64) Error!u64 {
            const entry = self.relative(relative_index) orelse return error.QpackEncoderStreamError;
            return self.insert(entry.name, entry.value);
        }

        /// Encoder-stream relative indexes use the current insertion point:
        /// zero identifies the most recently inserted entry.
        pub fn relative(self: DynamicTable, relative_index: u64) ?DynamicEntry {
            const count = self.entryCount();
            const index = std.math.cast(usize, relative_index) orelse return null;
            if (index >= count) return null;
            return self.entries.items[self.entries.items.len - 1 - index];
        }

        pub fn absolute(self: DynamicTable, absolute_index: u64) ?DynamicEntry {
            if (self.entryCount() == 0) return null;
            const oldest = self.entries.items[self.head].absolute_index;
            if (absolute_index < oldest or absolute_index >= self.insert_count) return null;
            const offset = std.math.cast(usize, absolute_index - oldest) orelse return null;
            const index = self.head + offset;
            if (index >= self.entries.items.len) return null;
            const entry = self.entries.items[index];
            if (entry.absolute_index != absolute_index) return null;
            return entry;
        }

        pub fn fieldRelativeToBase(self: DynamicTable, base: u64, relative_index: u64) ?DynamicEntry {
            if (relative_index >= base) return null;
            return self.absolute(base - relative_index - 1);
        }

        pub fn fieldPostBase(self: DynamicTable, base: u64, post_base_index: u64) ?DynamicEntry {
            const absolute_index = std.math.add(u64, base, post_base_index) catch return null;
            return self.absolute(absolute_index);
        }

        pub fn findExact(self: DynamicTable, name: []const u8, value: []const u8) ?u64 {
            const match = self.findMatchBefore(
                name,
                value,
                self.insert_count,
            ) orelse return null;
            return if (match.full_match) match.absolute_index else null;
        }

        pub fn findExactBefore(
            self: DynamicTable,
            name: []const u8,
            value: []const u8,
            absolute_index_limit: u64,
        ) ?u64 {
            const match = self.findMatchBefore(
                name,
                value,
                absolute_index_limit,
            ) orelse return null;
            return if (match.full_match) match.absolute_index else null;
        }

        /// Find the newest exact match, or otherwise the newest name match,
        /// before `absolute_index_limit` in one reverse table scan.
        pub fn findMatchBefore(
            self: DynamicTable,
            name: []const u8,
            value: []const u8,
            absolute_index_limit: u64,
        ) ?Match {
            const name_hash = dynamicStringHash(name);
            const value_hash = dynamicStringHash(value);
            var name_match: ?u64 = null;
            var index = self.entries.items.len;
            while (index > self.head) {
                index -= 1;
                const entry = self.entries.items[index];
                if (entry.absolute_index >= absolute_index_limit) continue;
                if (entry.name_hash != name_hash) continue;
                if (!std.mem.eql(u8, entry.name, name)) continue;
                if (entry.value_hash == value_hash and
                    std.mem.eql(u8, entry.value, value))
                {
                    return .{
                        .absolute_index = entry.absolute_index,
                        .full_match = true,
                    };
                }
                if (name_match == null) name_match = entry.absolute_index;
            }
            return if (name_match) |absolute_index| .{
                .absolute_index = absolute_index,
                .full_match = false,
            } else null;
        }

        pub fn findName(self: DynamicTable, name: []const u8) ?u64 {
            return self.findNameBefore(name, self.insert_count);
        }

        pub fn findNameBefore(
            self: DynamicTable,
            name: []const u8,
            absolute_index_limit: u64,
        ) ?u64 {
            const name_hash = dynamicStringHash(name);
            var index = self.entries.items.len;
            while (index > self.head) {
                index -= 1;
                const entry = self.entries.items[index];
                if (entry.absolute_index >= absolute_index_limit) continue;
                if (entry.name_hash != name_hash) continue;
                if (std.mem.eql(u8, entry.name, name)) return entry.absolute_index;
            }
            return null;
        }

        fn evictToFit(self: *DynamicTable, incoming_size: usize) void {
            while (self.entryCount() != 0 and
                (self.current_size > self.capacity or
                    incoming_size > self.capacity - self.current_size))
            {
                var entry = &self.entries.items[self.head];
                self.current_size -= entry.size();
                entry.deinit(self.allocator);
                self.head += 1;
            }
            self.compactIfNeeded();
        }

        fn clearEntries(self: *DynamicTable) void {
            for (self.entries.items[self.head..]) |*entry| entry.deinit(self.allocator);
            self.entries.clearRetainingCapacity();
            self.head = 0;
            self.current_size = 0;
        }

        fn compactIfNeeded(self: *DynamicTable) void {
            if (self.head == 0) return;
            if (self.head < self.entries.items.len / 2 and self.entryCount() != 0) return;
            const remaining = self.entryCount();
            @memmove(self.entries.items[0..remaining], self.entries.items[self.head..]);
            self.entries.items.len = remaining;
            self.head = 0;
        }
    };

    pub const EncoderInstruction = union(enum) {
        insert_name_reference: struct {
            static: bool,
            name_index: u64,
            value: []const u8,
        },
        insert_literal: struct {
            name: []const u8,
            value: []const u8,
        },
        set_capacity: u64,
        duplicate: u64,
    };

    pub const DecodedEncoderInstruction = struct {
        instruction: EncoderInstruction,
        consumed: usize,
        name_storage: ?[]u8 = null,
        value_storage: ?[]u8 = null,

        pub fn deinit(self: *DecodedEncoderInstruction, allocator: std.mem.Allocator) void {
            if (self.name_storage) |storage| allocator.free(storage);
            if (self.value_storage) |storage| allocator.free(storage);
            self.* = undefined;
        }
    };

    pub fn writeEncoderInstruction(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        instruction: EncoderInstruction,
    ) !void {
        switch (instruction) {
            .insert_name_reference => |reference| {
                try encodePrefixedInteger(
                    list,
                    allocator,
                    6,
                    if (reference.static) 0xc0 else 0x80,
                    reference.name_index,
                );
                try encodeString(list, allocator, reference.value);
            },
            .insert_literal => |literal| {
                try encodePrefixedInteger(list, allocator, 5, 0x40, literal.name.len);
                try list.appendSlice(allocator, literal.name);
                try encodeString(list, allocator, literal.value);
            },
            .set_capacity => |capacity| try encodePrefixedInteger(list, allocator, 5, 0x20, capacity),
            .duplicate => |index| try encodePrefixedInteger(list, allocator, 5, 0x00, index),
        }
    }

    pub fn decodeEncoderInstruction(
        allocator: std.mem.Allocator,
        bytes: []const u8,
    ) !DecodedEncoderInstruction {
        var cursor = wire.Cursor.init(bytes);
        const first = try cursor.readByte();
        if ((first & 0x80) != 0) {
            const name_index = try decodePrefixedInteger(&cursor, 6, first);
            var value = try decodeString(allocator, &cursor);
            errdefer if (value.storage) |storage| allocator.free(storage);
            const result: DecodedEncoderInstruction = .{
                .instruction = .{ .insert_name_reference = .{
                    .static = (first & 0x40) != 0,
                    .name_index = name_index,
                    .value = value.value,
                } },
                .consumed = cursor.pos,
                .value_storage = value.storage,
            };
            value.storage = null;
            return result;
        }
        if ((first & 0x40) != 0) {
            const name_len = try decodePrefixedInteger(&cursor, 5, first);
            var name = try decodeMaybeHuffman(
                allocator,
                try cursor.readSlice(name_len),
                (first & 0x20) != 0,
            );
            errdefer if (name.storage) |storage| allocator.free(storage);
            var value = try decodeString(allocator, &cursor);
            errdefer if (value.storage) |storage| allocator.free(storage);
            const result: DecodedEncoderInstruction = .{
                .instruction = .{ .insert_literal = .{
                    .name = name.value,
                    .value = value.value,
                } },
                .consumed = cursor.pos,
                .name_storage = name.storage,
                .value_storage = value.storage,
            };
            name.storage = null;
            value.storage = null;
            return result;
        }
        if ((first & 0x20) != 0) {
            return .{
                .instruction = .{ .set_capacity = try decodePrefixedInteger(&cursor, 5, first) },
                .consumed = cursor.pos,
            };
        }
        return .{
            .instruction = .{ .duplicate = try decodePrefixedInteger(&cursor, 5, first) },
            .consumed = cursor.pos,
        };
    }

    pub fn applyEncoderInstructions(
        table: *DynamicTable,
        allocator: std.mem.Allocator,
        bytes: []const u8,
    ) Error!usize {
        var offset: usize = 0;
        while (offset < bytes.len) {
            var decoded = decodeEncoderInstruction(allocator, bytes[offset..]) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return error.QpackEncoderStreamError,
            };
            defer decoded.deinit(allocator);
            switch (decoded.instruction) {
                .set_capacity => |capacity| {
                    const cast = std.math.cast(usize, capacity) orelse return error.QpackEncoderStreamError;
                    try table.setCapacity(cast);
                },
                .duplicate => |index| _ = try table.duplicate(index),
                .insert_literal => |literal| _ = try table.insert(literal.name, literal.value),
                .insert_name_reference => |reference| {
                    const name = if (reference.static) blk: {
                        const entry = staticEntry(std.math.cast(usize, reference.name_index) orelse
                            return error.QpackEncoderStreamError) orelse
                            return error.QpackEncoderStreamError;
                        break :blk entry.name;
                    } else blk: {
                        const entry = table.relative(reference.name_index) orelse
                            return error.QpackEncoderStreamError;
                        break :blk entry.name;
                    };
                    _ = try table.insert(name, reference.value);
                },
            }
            offset += decoded.consumed;
        }
        return offset;
    }

    pub fn encodeRequiredInsertCount(required_insert_count: u64, max_entries: u64) Error!u64 {
        if (required_insert_count == 0) return 0;
        if (max_entries == 0) return error.QpackDecompressionFailed;
        const full_range = std.math.mul(u64, 2, max_entries) catch return error.QpackDecompressionFailed;
        return (required_insert_count % full_range) + 1;
    }

    pub fn decodeRequiredInsertCount(
        encoded_insert_count: u64,
        max_entries: u64,
        total_number_of_inserts: u64,
    ) Error!u64 {
        if (encoded_insert_count == 0) return 0;
        if (max_entries == 0) return error.QpackDecompressionFailed;
        const full_range = std.math.mul(u64, 2, max_entries) catch return error.QpackDecompressionFailed;
        if (encoded_insert_count > full_range) return error.QpackDecompressionFailed;
        const max_value = std.math.add(u64, total_number_of_inserts, max_entries) catch
            return error.QpackDecompressionFailed;
        const max_wrapped = (max_value / full_range) * full_range;
        var required_insert_count = std.math.add(
            u64,
            max_wrapped,
            encoded_insert_count - 1,
        ) catch return error.QpackDecompressionFailed;
        if (required_insert_count > max_value) {
            if (required_insert_count <= full_range) return error.QpackDecompressionFailed;
            required_insert_count -= full_range;
        }
        if (required_insert_count == 0) return error.QpackDecompressionFailed;
        return required_insert_count;
    }

    pub const DecoderInstruction = union(enum) {
        section_acknowledgment: u64,
        stream_cancellation: u64,
        insert_count_increment: u64,
    };

    pub const DecodedDecoderInstruction = struct {
        instruction: DecoderInstruction,
        consumed: usize,
    };

    pub fn writeDecoderInstruction(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        instruction: DecoderInstruction,
    ) !void {
        switch (instruction) {
            .section_acknowledgment => |stream_id| try encodePrefixedInteger(
                list,
                allocator,
                7,
                0x80,
                stream_id,
            ),
            .stream_cancellation => |stream_id| try encodePrefixedInteger(
                list,
                allocator,
                6,
                0x40,
                stream_id,
            ),
            .insert_count_increment => |increment| {
                if (increment == 0) return error.QpackDecoderStreamError;
                try encodePrefixedInteger(list, allocator, 6, 0x00, increment);
            },
        }
    }

    pub fn decodeDecoderInstruction(bytes: []const u8) !DecodedDecoderInstruction {
        var cursor = wire.Cursor.init(bytes);
        const first = try cursor.readByte();
        if ((first & 0x80) != 0) {
            return .{
                .instruction = .{ .section_acknowledgment = try decodePrefixedInteger(&cursor, 7, first) },
                .consumed = cursor.pos,
            };
        }
        if ((first & 0x40) != 0) {
            return .{
                .instruction = .{ .stream_cancellation = try decodePrefixedInteger(&cursor, 6, first) },
                .consumed = cursor.pos,
            };
        }
        const increment = try decodePrefixedInteger(&cursor, 6, first);
        if (increment == 0) return error.QpackDecoderStreamError;
        return .{
            .instruction = .{ .insert_count_increment = increment },
            .consumed = cursor.pos,
        };
    }

    pub const DynamicBlockDecode = struct {
        fields: []HeaderField,
        required_insert_count: u64,
        base: u64,
    };

    pub const FieldSectionPrefix = struct {
        required_insert_count: u64,
        base: u64,
        consumed: usize,
    };

    /// Decode only the QPACK field-section prefix without allocating fields.
    ///
    /// Runtimes use this to decide whether a complete HTTP message must wait
    /// for encoder-stream inserts before attempting full semantic decoding.
    pub fn decodeFieldSectionPrefix(
        block: []const u8,
        table: DynamicTable,
    ) Error!FieldSectionPrefix {
        var cursor = wire.Cursor.init(block);
        const encoded_insert_count = try decodePrefixedInteger(
            &cursor,
            8,
            try cursor.readByte(),
        );
        const required_insert_count = try decodeRequiredInsertCount(
            encoded_insert_count,
            table.maxEntries(),
            table.insert_count,
        );
        const delta_first = try cursor.readByte();
        const delta_base = try decodePrefixedInteger(&cursor, 7, delta_first);
        const base = if ((delta_first & 0x80) == 0)
            std.math.add(u64, required_insert_count, delta_base) catch
                return error.QpackDecompressionFailed
        else blk: {
            if (required_insert_count <= delta_base) {
                return error.QpackDecompressionFailed;
            }
            break :blk required_insert_count - delta_base - 1;
        };
        return .{
            .required_insert_count = required_insert_count,
            .base = base,
            .consumed = cursor.pos,
        };
    }

    pub fn encodeDynamicBlock(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        fields: []const HeaderField,
        table: DynamicTable,
    ) !void {
        var ignored_references: std.ArrayList(u64) = .empty;
        defer ignored_references.deinit(allocator);
        try encodeDynamicBlockWithReferenceLimit(
            list,
            allocator,
            fields,
            table,
            table.insert_count,
            &ignored_references,
        );
    }

    /// Encode a non-blocking field section using only entries the decoder has
    /// acknowledged. Absolute indexes actually referenced by the section are
    /// appended to `references` for the encoder's eviction bookkeeping.
    pub fn encodeDynamicBlockKnownReceived(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        fields: []const HeaderField,
        table: DynamicTable,
        known_received_count: u64,
        references: *std.ArrayList(u64),
    ) !void {
        if (known_received_count > table.insert_count) {
            return error.QpackDecoderStreamError;
        }
        try encodeDynamicBlockWithReferenceLimit(
            list,
            allocator,
            fields,
            table,
            known_received_count,
            references,
        );
    }

    fn encodeDynamicBlockWithReferenceLimit(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        fields: []const HeaderField,
        table: DynamicTable,
        reference_limit: u64,
        references: *std.ArrayList(u64),
    ) !void {
        const stack_match_capacity = 64;
        var stack_matches: [stack_match_capacity]?DynamicTable.Match =
            undefined;
        const dynamic_matches = if (fields.len <= stack_matches.len)
            stack_matches[0..fields.len]
        else
            try allocator.alloc(?DynamicTable.Match, fields.len);
        defer if (fields.len > stack_matches.len) {
            allocator.free(dynamic_matches);
        };

        const base = table.insert_count;
        var required_insert_count: u64 = 0;
        for (fields, dynamic_matches) |field, *dynamic_match| {
            dynamic_match.* = table.findMatchBefore(
                field.name,
                field.value,
                reference_limit,
            );
            if (dynamic_match.*) |match| {
                required_insert_count = @max(
                    required_insert_count,
                    match.absolute_index + 1,
                );
            }
        }

        const encoded_insert_count = try encodeRequiredInsertCount(
            required_insert_count,
            table.maxEntries(),
        );
        try encodePrefixedInteger(list, allocator, 8, 0x00, encoded_insert_count);
        // Base is the insertion count at the start of this single-pass encode.
        // Required Insert Count cannot exceed it because this helper does not
        // mutate the table while encoding.
        try encodePrefixedInteger(
            list,
            allocator,
            7,
            0x00,
            base - required_insert_count,
        );

        for (fields, dynamic_matches) |field, dynamic_match| {
            if (!field.never_indexed) {
                if (dynamic_match) |match| {
                    if (match.full_match) {
                        const absolute_index = match.absolute_index;
                        try appendReferenceUnique(
                            references,
                            allocator,
                            absolute_index,
                        );
                        if (absolute_index < base) {
                            try encodePrefixedInteger(
                                list,
                                allocator,
                                6,
                                0x80,
                                base - absolute_index - 1,
                            );
                        } else {
                            try encodePrefixedInteger(
                                list,
                                allocator,
                                4,
                                0x10,
                                absolute_index - base,
                            );
                        }
                        continue;
                    }
                }
            }

            if (findStaticMatch(field.name, field.value)) |match| {
                if (match.full_match and !field.never_indexed) {
                    try encodePrefixedInteger(list, allocator, 6, 0xc0, match.index);
                } else {
                    try encodePrefixedInteger(
                        list,
                        allocator,
                        4,
                        0x50 | if (field.never_indexed) @as(u8, 0x20) else 0,
                        match.index,
                    );
                    try encodeString(list, allocator, field.value);
                }
                continue;
            }

            if (dynamic_match) |match| {
                const absolute_index = match.absolute_index;
                try appendReferenceUnique(references, allocator, absolute_index);
                if (absolute_index < base) {
                    try encodePrefixedInteger(
                        list,
                        allocator,
                        4,
                        0x40 | if (field.never_indexed) @as(u8, 0x20) else 0,
                        base - absolute_index - 1,
                    );
                } else {
                    try encodePrefixedInteger(
                        list,
                        allocator,
                        3,
                        if (field.never_indexed) 0x08 else 0x00,
                        absolute_index - base,
                    );
                }
                try encodeString(list, allocator, field.value);
                continue;
            }

            try encodePrefixedInteger(
                list,
                allocator,
                3,
                0x20 | if (field.never_indexed) @as(u8, 0x10) else 0,
                field.name.len,
            );
            try list.appendSlice(allocator, field.name);
            try encodeString(list, allocator, field.value);
        }
    }

    fn appendReferenceUnique(
        references: *std.ArrayList(u64),
        allocator: std.mem.Allocator,
        absolute_index: u64,
    ) !void {
        for (references.items) |existing| {
            if (existing == absolute_index) return;
        }
        try references.append(allocator, absolute_index);
    }

    pub fn decodeDynamicBlock(
        allocator: std.mem.Allocator,
        block: []const u8,
        table: DynamicTable,
    ) !DynamicBlockDecode {
        const prefix = try decodeFieldSectionPrefix(block, table);
        var cursor = wire.Cursor.init(block);
        cursor.pos = prefix.consumed;
        const required_insert_count = prefix.required_insert_count;
        const base = prefix.base;
        if (required_insert_count > table.insert_count) return error.QpackBlocked;

        var fields: std.ArrayList(HeaderField) = .empty;
        errdefer {
            freeFieldStorages(allocator, fields.items);
            fields.deinit(allocator);
        }
        while (!cursor.eof()) {
            const first = try cursor.readByte();
            var field: HeaderField = undefined;
            if ((first & 0x80) != 0) {
                const static = (first & 0x40) != 0;
                const index = try decodePrefixedInteger(&cursor, 6, first);
                if (static) {
                    field = staticEntry(index) orelse return error.QpackDecompressionFailed;
                } else {
                    const entry = table.fieldRelativeToBase(base, index) orelse
                        return error.QpackDecompressionFailed;
                    field = try ownedDynamicField(allocator, entry, entry.value, false);
                }
            } else if ((first & 0xf0) == 0x10) {
                const index = try decodePrefixedInteger(&cursor, 4, first);
                const entry = table.fieldPostBase(base, index) orelse
                    return error.QpackDecompressionFailed;
                field = try ownedDynamicField(allocator, entry, entry.value, false);
            } else if ((first & 0xc0) == 0x40) {
                const never_indexed = (first & 0x20) != 0;
                const static = (first & 0x10) != 0;
                const index = try decodePrefixedInteger(&cursor, 4, first);
                var value = try decodeString(allocator, &cursor);
                errdefer if (value.storage) |storage| allocator.free(storage);
                if (static) {
                    const entry = staticEntry(index) orelse return error.QpackDecompressionFailed;
                    field = .{
                        .name = entry.name,
                        .value = value.value,
                        .never_indexed = never_indexed,
                        .value_storage = value.storage,
                    };
                    value.storage = null;
                } else {
                    const entry = table.fieldRelativeToBase(base, index) orelse
                        return error.QpackDecompressionFailed;
                    field = try ownedDynamicField(allocator, entry, value.value, never_indexed);
                    if (value.storage) |storage| allocator.free(storage);
                    value.storage = null;
                }
            } else if ((first & 0xf0) == 0x00) {
                const never_indexed = (first & 0x08) != 0;
                const index = try decodePrefixedInteger(&cursor, 3, first);
                const entry = table.fieldPostBase(base, index) orelse
                    return error.QpackDecompressionFailed;
                const value = try decodeString(allocator, &cursor);
                defer if (value.storage) |storage| allocator.free(storage);
                field = try ownedDynamicField(allocator, entry, value.value, never_indexed);
            } else if ((first & 0xe0) == 0x20) {
                const never_indexed = (first & 0x10) != 0;
                const name_len = try decodePrefixedInteger(&cursor, 3, first);
                var name = try decodeMaybeHuffman(
                    allocator,
                    try cursor.readSlice(name_len),
                    (first & 0x08) != 0,
                );
                errdefer if (name.storage) |storage| allocator.free(storage);
                var value = try decodeString(allocator, &cursor);
                errdefer if (value.storage) |storage| allocator.free(storage);
                field = .{
                    .name = name.value,
                    .value = value.value,
                    .never_indexed = never_indexed,
                    .name_storage = name.storage,
                    .value_storage = value.storage,
                };
                name.storage = null;
                value.storage = null;
            } else {
                return error.QpackDecompressionFailed;
            }
            var appended = false;
            defer if (!appended) {
                if (field.name_storage) |storage| allocator.free(storage);
                if (field.value_storage) |storage| allocator.free(storage);
            };
            try fields.append(allocator, field);
            appended = true;
        }
        return .{
            .fields = try fields.toOwnedSlice(allocator),
            .required_insert_count = required_insert_count,
            .base = base,
        };
    }

    pub fn freeDynamicBlock(allocator: std.mem.Allocator, decoded: *DynamicBlockDecode) void {
        freeDecodedFields(allocator, decoded.fields);
        decoded.* = undefined;
    }

    fn ownedDynamicField(
        allocator: std.mem.Allocator,
        entry: DynamicEntry,
        value: []const u8,
        never_indexed: bool,
    ) !HeaderField {
        const name_copy = try allocator.dupe(u8, entry.name);
        errdefer allocator.free(name_copy);
        const value_copy = try allocator.dupe(u8, value);
        return .{
            .name = name_copy,
            .value = value_copy,
            .never_indexed = never_indexed,
            .name_storage = name_copy,
            .value_storage = value_copy,
        };
    }

    fn dynamicEntrySize(name: []const u8, value: []const u8) error{IntegerOverflow}!usize {
        const strings = std.math.add(usize, name.len, value.len) catch return error.IntegerOverflow;
        return std.math.add(usize, strings, dynamic_entry_overhead) catch error.IntegerOverflow;
    }

    const StaticEntry = struct {
        name: []const u8,
        value: []const u8,
    };

    // RFC 9204 Appendix A static table.  Keeping the full table makes the
    // bootstrap encoder interoperate with peers that use common indexed field
    // lines without introducing dynamic-table state or head-of-line blocking.
    pub const static_table = [_]StaticEntry{
        .{ .name = ":authority", .value = "" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "age", .value = "0" },
        .{ .name = "content-disposition", .value = "" },
        .{ .name = "content-length", .value = "0" },
        .{ .name = "cookie", .value = "" },
        .{ .name = "date", .value = "" },
        .{ .name = "etag", .value = "" },
        .{ .name = "if-modified-since", .value = "" },
        .{ .name = "if-none-match", .value = "" },
        .{ .name = "last-modified", .value = "" },
        .{ .name = "link", .value = "" },
        .{ .name = "location", .value = "" },
        .{ .name = "referer", .value = "" },
        .{ .name = "set-cookie", .value = "" },
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":method", .value = "DELETE" },
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "HEAD" },
        .{ .name = ":method", .value = "OPTIONS" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":method", .value = "PUT" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":status", .value = "103" },
        .{ .name = ":status", .value = "200" },
        .{ .name = ":status", .value = "304" },
        .{ .name = ":status", .value = "404" },
        .{ .name = ":status", .value = "503" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = "accept", .value = "application/dns-message" },
        .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
        .{ .name = "accept-ranges", .value = "bytes" },
        .{ .name = "access-control-allow-headers", .value = "cache-control" },
        .{ .name = "access-control-allow-headers", .value = "content-type" },
        .{ .name = "access-control-allow-origin", .value = "*" },
        .{ .name = "cache-control", .value = "max-age=0" },
        .{ .name = "cache-control", .value = "max-age=2592000" },
        .{ .name = "cache-control", .value = "max-age=604800" },
        .{ .name = "cache-control", .value = "no-cache" },
        .{ .name = "cache-control", .value = "no-store" },
        .{ .name = "cache-control", .value = "public, max-age=31536000" },
        .{ .name = "content-encoding", .value = "br" },
        .{ .name = "content-encoding", .value = "gzip" },
        .{ .name = "content-type", .value = "application/dns-message" },
        .{ .name = "content-type", .value = "application/javascript" },
        .{ .name = "content-type", .value = "application/json" },
        .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
        .{ .name = "content-type", .value = "image/gif" },
        .{ .name = "content-type", .value = "image/jpeg" },
        .{ .name = "content-type", .value = "image/png" },
        .{ .name = "content-type", .value = "text/css" },
        .{ .name = "content-type", .value = "text/html; charset=utf-8" },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
        .{ .name = "range", .value = "bytes=0-" },
        .{ .name = "strict-transport-security", .value = "max-age=31536000" },
        .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
        .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
        .{ .name = "vary", .value = "accept-encoding" },
        .{ .name = "vary", .value = "origin" },
        .{ .name = "x-content-type-options", .value = "nosniff" },
        .{ .name = "x-xss-protection", .value = "1; mode=block" },
        .{ .name = ":status", .value = "100" },
        .{ .name = ":status", .value = "204" },
        .{ .name = ":status", .value = "206" },
        .{ .name = ":status", .value = "302" },
        .{ .name = ":status", .value = "400" },
        .{ .name = ":status", .value = "403" },
        .{ .name = ":status", .value = "421" },
        .{ .name = ":status", .value = "425" },
        .{ .name = ":status", .value = "500" },
        .{ .name = "accept-language", .value = "" },
        .{ .name = "access-control-allow-credentials", .value = "FALSE" },
        .{ .name = "access-control-allow-credentials", .value = "TRUE" },
        .{ .name = "access-control-allow-headers", .value = "*" },
        .{ .name = "access-control-allow-methods", .value = "get" },
        .{ .name = "access-control-allow-methods", .value = "get, post, options" },
        .{ .name = "access-control-allow-methods", .value = "options" },
        .{ .name = "access-control-expose-headers", .value = "content-length" },
        .{ .name = "access-control-request-headers", .value = "content-type" },
        .{ .name = "access-control-request-method", .value = "get" },
        .{ .name = "access-control-request-method", .value = "post" },
        .{ .name = "alt-svc", .value = "clear" },
        .{ .name = "authorization", .value = "" },
        .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
        .{ .name = "early-data", .value = "1" },
        .{ .name = "expect-ct", .value = "" },
        .{ .name = "forwarded", .value = "" },
        .{ .name = "if-range", .value = "" },
        .{ .name = "origin", .value = "" },
        .{ .name = "purpose", .value = "prefetch" },
        .{ .name = "server", .value = "" },
        .{ .name = "timing-allow-origin", .value = "*" },
        .{ .name = "upgrade-insecure-requests", .value = "1" },
        .{ .name = "user-agent", .value = "" },
        .{ .name = "x-forwarded-for", .value = "" },
        .{ .name = "x-frame-options", .value = "deny" },
        .{ .name = "x-frame-options", .value = "sameorigin" },
    };

    pub fn staticEntry(index: usize) ?HeaderField {
        if (index >= static_table.len) return null;
        const entry = static_table[index];
        return .{ .name = entry.name, .value = entry.value };
    }

    fn findStaticMatch(name: []const u8, value: []const u8) ?struct { index: u64, full_match: bool } {
        var name_match: ?u64 = null;
        for (static_table, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                if (std.mem.eql(u8, entry.value, value)) return .{ .index = @intCast(i), .full_match = true };
                if (name_match == null) name_match = @intCast(i);
            }
        }
        if (name_match) |index| return .{ .index = index, .full_match = false };
        return null;
    }

    pub fn encodePrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator, required_insert_count: u64, base: u64) !void {
        try quic.varint.encode(list, allocator, required_insert_count);
        try quic.varint.encode(list, allocator, base);
    }

    /// Stateless QPACK encoder for deterministic clients. It uses the static
    /// table and literal fields only, so it remains safe with zero dynamic-table
    /// capacity while interoperating with peers that expect common static refs.
    pub fn encodeLiteralBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const HeaderField) !void {
        try encodePrefix(list, allocator, 0, 0);
        for (fields) |field| {
            var lower_name_storage: ?[]u8 = null;
            defer if (lower_name_storage) |storage| allocator.free(storage);
            const name = try normalizedFieldName(allocator, field.name, &lower_name_storage);
            if (findStaticMatch(name, field.value)) |match| {
                if (match.full_match) {
                    try encodePrefixedInteger(list, allocator, 6, 0xc0, match.index);
                } else {
                    try encodePrefixedInteger(list, allocator, 4, 0x50, match.index);
                    try encodeString(list, allocator, field.value);
                }
            } else {
                try encodePrefixedInteger(list, allocator, 3, 0x20, name.len);
                try list.appendSlice(allocator, name);
                try encodeString(list, allocator, field.value);
            }
        }
    }

    fn normalizedFieldName(allocator: std.mem.Allocator, name: []const u8, storage: *?[]u8) ![]const u8 {
        for (name) |byte| {
            if (byte >= 'A' and byte <= 'Z') {
                const lowered = try allocator.dupe(u8, name);
                for (lowered) |*out| out.* = std.ascii.toLower(out.*);
                storage.* = lowered;
                return lowered;
            }
        }
        return name;
    }

    pub fn decodeLiteralBlock(allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
        var cursor = wire.Cursor.init(block);
        const required_insert_count = try decodePrefixedInteger(&cursor, 8, try cursor.readByte());
        const base = try decodePrefixedInteger(&cursor, 7, try cursor.readByte());
        if (required_insert_count != 0 or base != 0) return error.QpackDynamicTableUnsupported;

        var fields: std.ArrayList(HeaderField) = .empty;
        errdefer {
            freeFieldStorages(allocator, fields.items);
            fields.deinit(allocator);
        }
        while (!cursor.eof()) {
            const first = try cursor.readByte();
            if ((first & 0xc0) == 0xc0) {
                const index = try decodePrefixedInteger(&cursor, 6, first);
                const entry = staticEntry(index) orelse return error.InvalidFrame;
                try fields.append(allocator, entry);
            } else if ((first & 0xc0) == 0x40) {
                const is_static = (first & 0x10) != 0;
                const index = try decodePrefixedInteger(&cursor, 4, first);
                var value = try decodeString(allocator, &cursor);
                errdefer if (value.storage) |storage| allocator.free(storage);
                if (!is_static) return error.QpackDynamicTableUnsupported;
                const entry = staticEntry(index) orelse return error.InvalidFrame;
                try fields.append(allocator, .{ .name = entry.name, .value = value.value, .value_storage = value.storage });
                value.storage = null;
            } else if ((first & 0xe0) == 0x20) {
                const name_len = try decodePrefixedInteger(&cursor, 3, first);
                var name = try decodeMaybeHuffman(allocator, try cursor.readSlice(name_len), (first & 0x08) != 0);
                errdefer if (name.storage) |storage| allocator.free(storage);
                var value = try decodeString(allocator, &cursor);
                errdefer if (value.storage) |storage| allocator.free(storage);
                try fields.append(allocator, .{
                    .name = name.value,
                    .value = value.value,
                    .name_storage = name.storage,
                    .value_storage = value.storage,
                });
                name.storage = null;
                value.storage = null;
            } else {
                return error.QpackDynamicTableUnsupported;
            }
        }
        return fields.toOwnedSlice(allocator);
    }

    pub fn freeDecodedFields(allocator: std.mem.Allocator, fields: []HeaderField) void {
        freeFieldStorages(allocator, fields);
        allocator.free(fields);
    }

    fn freeFieldStorages(allocator: std.mem.Allocator, fields: []HeaderField) void {
        for (fields) |field| {
            if (field.name_storage) |storage| allocator.free(storage);
            if (field.value_storage) |storage| allocator.free(storage);
        }
    }

    fn encodeString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
        const huffman = try encodeHuffman(allocator, value);
        defer allocator.free(huffman);
        if (huffman.len < value.len) {
            try encodePrefixedInteger(list, allocator, 7, 0x80, huffman.len);
            try list.appendSlice(allocator, huffman);
        } else {
            try encodePrefixedInteger(list, allocator, 7, 0x00, value.len);
            try list.appendSlice(allocator, value);
        }
    }

    const DecodedString = struct {
        value: []const u8,
        storage: ?[]u8 = null,
    };

    fn decodeString(allocator: std.mem.Allocator, cursor: *wire.Cursor) !DecodedString {
        const first = try cursor.readByte();
        const len = try decodePrefixedInteger(cursor, 7, first);
        const raw = try cursor.readSlice(len);
        return decodeMaybeHuffman(allocator, raw, (first & 0x80) != 0);
    }

    fn decodeMaybeHuffman(allocator: std.mem.Allocator, raw: []const u8, huffman: bool) !DecodedString {
        if (!huffman) return .{ .value = raw };
        const decoded = try decodeHuffman(allocator, raw);
        return .{ .value = decoded, .storage = decoded };
    }

    fn encodeHuffman(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

        var bits: u64 = 0;
        var bits_left: u6 = 40;
        for (value) |byte| {
            const entry = hpack_huffman.encode_table[byte];
            bits |= @as(u64, entry.code) << @intCast(bits_left - entry.bits);
            bits_left -= entry.bits;

            while (bits_left <= 32) {
                try out.append(allocator, @truncate(bits >> 32));
                bits <<= 8;
                bits_left += 8;
            }
        }

        if (bits_left != 40) {
            // QPACK reuses HPACK's canonical Huffman code (RFC 9204 §4.1.2),
            // including EOS-prefix padding of the final octet.
            bits |= (@as(u64, 1) << bits_left) - 1;
            try out.append(allocator, @truncate(bits >> 32));
        }
        return out.toOwnedSlice(allocator);
    }

    fn decodeHuffman(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

        var node: u16 = huffman_root_node;
        var pending_code: u32 = 0;
        var pending_bits: u6 = 0;
        for (encoded) |byte| {
            var bit_index: u4 = 0;
            while (bit_index < 8) : (bit_index += 1) {
                const bit: u1 = @truncate((byte >> @intCast(7 - bit_index)) & 1);
                pending_code = (pending_code << 1) | bit;
                pending_bits += 1;
                if (pending_bits > huffman_max_code_bits) return error.InvalidEncoding;

                const next = huffman_decode_trie[node].child[bit] orelse return error.InvalidEncoding;
                node = next;
                if (huffman_decode_trie[node].symbol) |symbol| {
                    if (symbol == hpack_huffman.eos_symbol) return error.InvalidEncoding;
                    try out.append(allocator, @intCast(symbol));
                    node = huffman_root_node;
                    pending_code = 0;
                    pending_bits = 0;
                }
            }
        }

        if (pending_bits != 0) {
            // The only legal incomplete suffix is EOS-prefix padding of at
            // most seven one bits.  QPACK inherits this exact Huffman coding
            // from HPACK (RFC 9204 §4.1.2).
            if (pending_bits > 7) return error.InvalidEncoding;
            const padding = (@as(u32, 1) << @as(u5, @intCast(pending_bits))) - 1;
            if (pending_code != padding) return error.InvalidEncoding;
        }

        return out.toOwnedSlice(allocator);
    }

    fn encodePrefixedInteger(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime prefix_bits: u4, first_prefix: u8, value: u64) !void {
        const max_prefix: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
        if (value < max_prefix) {
            try list.append(allocator, first_prefix | @as(u8, @intCast(value)));
            return;
        }
        try list.append(allocator, first_prefix | max_prefix);
        var remaining = value - max_prefix;
        while (remaining >= 128) {
            try list.append(allocator, @as(u8, @intCast(remaining & 0x7f)) | 0x80);
            remaining >>= 7;
        }
        try list.append(allocator, @intCast(remaining));
    }

    fn decodePrefixedInteger(cursor: *wire.Cursor, comptime prefix_bits: u4, first: u8) !usize {
        const max_prefix: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
        var value: usize = first & max_prefix;
        if (value < max_prefix) return value;
        var shift: u6 = 0;
        while (true) {
            const byte = try cursor.readByte();
            value = std.math.add(usize, value, (@as(usize, byte & 0x7f) << shift)) catch return error.IntegerOverflow;
            if ((byte & 0x80) == 0) return value;
            shift += 7;
            if (shift >= @bitSizeOf(usize)) return error.IntegerOverflow;
        }
    }

    const huffman_root_node: u16 = 0;
    const huffman_max_code_bits: u6 = 30;

    const HuffmanDecodeNode = struct {
        child: [2]?u16 = .{ null, null },
        symbol: ?u16 = null,
    };

    const huffman_decode_trie = buildHuffmanDecodeTrie();

    fn buildHuffmanDecodeTrie() [huffman_decode_node_count]HuffmanDecodeNode {
        @setEvalBranchQuota(200_000);
        var nodes = [_]HuffmanDecodeNode{.{}} ** huffman_decode_node_count;
        var used: u16 = 1;

        for (hpack_huffman.encode_table, 0..) |entry, symbol| {
            var node: u16 = huffman_root_node;
            var bit_index: u6 = 0;
            while (bit_index < entry.bits) : (bit_index += 1) {
                const shift: u5 = @intCast(entry.bits - 1 - bit_index);
                const bit: u1 = @truncate((entry.code >> shift) & 1);
                if (nodes[node].child[bit] == null) {
                    nodes[node].child[bit] = used;
                    used += 1;
                }
                node = nodes[node].child[bit].?;
            }
            nodes[node].symbol = @intCast(symbol);
        }

        return nodes;
    }

    const huffman_decode_node_count = blk: {
        var count: usize = 1;
        for (hpack_huffman.encode_table) |entry| count += entry.bits;
        break :blk count;
    };
};

pub const Request = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8 = "https",
    authority: ?[]const u8 = null,
    headers: []const Qpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const Qpack.HeaderField = &.{},

    pub fn headerFields(self: Request, out: []Qpack.HeaderField) Error![]Qpack.HeaderField {
        var count: usize = 0;
        const extended_connect = std.mem.eql(u8, self.method, "CONNECT") and requestHasProtocolPseudo(self.headers);
        try appendHeaderField(out, &count, .{ .name = ":method", .value = self.method });
        if (!std.mem.eql(u8, self.method, "CONNECT") or extended_connect) {
            try appendHeaderField(out, &count, .{ .name = ":path", .value = self.path });
            try appendHeaderField(out, &count, .{ .name = ":scheme", .value = self.scheme });
        }
        if (self.authority) |authority| try appendHeaderField(out, &count, .{ .name = ":authority", .value = authority });
        for (self.headers) |header| try appendHeaderField(out, &count, header);
        return out[0..count];
    }

    pub fn write(self: Request, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try self.writeWithSettings(list, allocator, .{});
    }

    pub fn writeWithSettings(self: Request, list: *std.ArrayList(u8), allocator: std.mem.Allocator, peer_settings: Settings) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var fields = try self.headerFields(&fields_buf);
        var content_length_buf: [32]u8 = undefined;
        if (requestShouldDefaultContentLength(self.method, fields, self.body.len)) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(&content_length_buf, "{}", .{self.body.len}) catch unreachable;
            try appendHeaderField(&fields_buf, &field_count, .{ .name = "content-length", .value = content_length });
            fields = fields_buf[0..field_count];
        }
        try validateHeaderBlock(fields, .request);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateRequestBodyForMethod(fields, self.body, self.trailers);
        try validateContentLength(fields, self.body.len);
        try writeHeadersAndData(list, allocator, fields, self.body, self.trailers);
    }

    pub fn writeDynamic(
        self: Request,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
    ) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var fields = try self.headerFields(&fields_buf);
        var content_length_buf: [32]u8 = undefined;
        if (requestShouldDefaultContentLength(self.method, fields, self.body.len)) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{self.body.len},
            ) catch unreachable;
            try appendHeaderField(&fields_buf, &field_count, .{
                .name = "content-length",
                .value = content_length,
            });
            fields = fields_buf[0..field_count];
        }
        try validateHeaderBlock(fields, .request);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateRequestBodyForMethod(fields, self.body, self.trailers);
        try validateContentLength(fields, self.body.len);
        try writeHeadersAndDataDynamic(
            list,
            allocator,
            fields,
            self.body,
            self.trailers,
            stream_id,
            encoder,
        );
        try queueIndexableFields(encoder, fields);
        try queueIndexableFields(encoder, self.trailers);
    }

    /// Encode only the initial HEADERS section for an incrementally-sent body.
    ///
    /// `body_length` adds (or verifies) Content-Length. Null permits an
    /// unknown-length body delimited by stream FIN. The returned value is the
    /// effective length to enforce while streaming; plain CONNECT returns zero
    /// because RFC 9114 forbids request DATA on that form.
    pub fn writeStreamingHeadDynamic(
        self: Request,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        body_length: ?usize,
        encoder: anytype,
    ) Error!struct { expected_length: ?usize, body_allowed: bool } {
        if (self.body.len != 0 or self.trailers.len != 0) {
            return error.InvalidContentLength;
        }
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var fields = try self.headerFields(&fields_buf);
        var content_length_buf: [32]u8 = undefined;
        const plain_connect = std.mem.eql(u8, self.method, "CONNECT") and
            !requestHasProtocolPseudo(self.headers);
        if (plain_connect) {
            if (body_length) |length| {
                if (length != 0) return error.InvalidContentLength;
            }
            try validateHeaderBlock(fields, .request);
            try validateFieldSectionSize(
                fields,
                peer_settings.max_field_section_size,
            );
            try validateRequestBodyForMethod(fields, &.{}, &.{});
            try writeHeadersFrameDynamic(
                list,
                allocator,
                fields,
                stream_id,
                encoder,
            );
            try queueIndexableFields(encoder, fields);
            return .{ .expected_length = 0, .body_allowed = false };
        }
        const effective_length = try applyStreamingContentLength(
            &fields_buf,
            &fields,
            body_length,
            &content_length_buf,
        );
        try validateHeaderBlock(fields, .request);
        try validateFieldSectionSize(
            fields,
            peer_settings.max_field_section_size,
        );
        try validateRequestBodyForMethod(fields, &.{}, &.{});
        try writeHeadersFrameDynamic(
            list,
            allocator,
            fields,
            stream_id,
            encoder,
        );
        try queueIndexableFields(encoder, fields);
        return .{
            .expected_length = effective_length,
            .body_allowed = true,
        };
    }
};

fn requestHasProtocolPseudo(headers: []const Qpack.HeaderField) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":protocol")) return true;
    }
    return false;
}

fn requestShouldDefaultContentLength(method: []const u8, headers: []const Qpack.HeaderField, body_len: usize) bool {
    if (std.mem.eql(u8, method, "CONNECT")) return false;
    // Align the HTTP/3 convenience writer with Hyper's h2 shaping and our
    // HTTP/2 runtime: known non-empty bodies get an explicit length, and empty
    // bodies on methods with defined payload semantics (POST/PUT/PATCH/etc.)
    // get `content-length: 0` so intermediaries and applications do not have
    // to infer intent from the absence of DATA frames.
    if (body_len == 0 and !methodHasDefinedPayloadSemantics(method)) return false;
    return (contentLength(headers) catch return false) == null;
}

fn methodHasDefinedPayloadSemantics(method: []const u8) bool {
    return !std.mem.eql(u8, method, "GET") and
        !std.mem.eql(u8, method, "HEAD") and
        !std.mem.eql(u8, method, "DELETE") and
        !std.mem.eql(u8, method, "CONNECT");
}

fn findHeader(headers: []const Qpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

pub const Response = struct {
    status: u16,
    headers: []const Qpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const Qpack.HeaderField = &.{},

    pub fn successful(self: Response) bool {
        return self.status >= 200 and self.status < 300;
    }

    pub fn headerFields(self: Response, out: []Qpack.HeaderField, status_buf: *[3]u8) Error![]Qpack.HeaderField {
        var count: usize = 0;
        if (self.status < 100 or self.status > 999) return error.InvalidStatus;
        if (self.status < 200) return error.InvalidStatus;
        const status = std.fmt.bufPrint(status_buf, "{d}", .{self.status}) catch return error.InvalidStatus;
        try appendHeaderField(out, &count, .{ .name = ":status", .value = status });
        for (self.headers) |header| try appendHeaderField(out, &count, header);
        return out[0..count];
    }

    pub fn write(self: Response, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try self.writeWithSettings(list, allocator, .{});
    }

    pub fn writeWithSettings(self: Response, list: *std.ArrayList(u8), allocator: std.mem.Allocator, peer_settings: Settings) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var status_buf: [3]u8 = undefined;
        var fields = try self.headerFields(&fields_buf, &status_buf);
        var content_length_buf: [32]u8 = undefined;
        if (responseShouldDefaultContentLength(self.status, fields, self.body.len)) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(&content_length_buf, "{}", .{self.body.len}) catch unreachable;
            try appendHeaderField(&fields_buf, &field_count, .{ .name = "content-length", .value = content_length });
            fields = fields_buf[0..field_count];
        }
        try validateHeaderBlock(fields, .response);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateResponseBodyForStatus(self.status, fields, self.body, self.trailers);
        try validateContentLengthForStatus(self.status, fields, self.body.len);
        try writeHeadersAndData(list, allocator, fields, self.body, self.trailers);
    }

    pub fn writeDynamic(
        self: Response,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
    ) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var status_buf: [3]u8 = undefined;
        var fields = try self.headerFields(&fields_buf, &status_buf);
        var content_length_buf: [32]u8 = undefined;
        if (responseShouldDefaultContentLength(self.status, fields, self.body.len)) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{self.body.len},
            ) catch unreachable;
            try appendHeaderField(&fields_buf, &field_count, .{
                .name = "content-length",
                .value = content_length,
            });
            fields = fields_buf[0..field_count];
        }
        try validateHeaderBlock(fields, .response);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateResponseBodyForStatus(self.status, fields, self.body, self.trailers);
        try validateContentLengthForStatus(self.status, fields, self.body.len);
        try writeHeadersAndDataDynamic(
            list,
            allocator,
            fields,
            self.body,
            self.trailers,
            stream_id,
            encoder,
        );
        try queueIndexableFields(encoder, fields);
        try queueIndexableFields(encoder, self.trailers);
    }

    /// Encode only final response HEADERS for incremental DATA transmission.
    pub fn writeStreamingHeadDynamic(
        self: Response,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        body_length: ?usize,
        encoder: anytype,
    ) Error!struct { expected_length: ?usize, body_allowed: bool } {
        if (self.body.len != 0 or self.trailers.len != 0) {
            return error.InvalidContentLength;
        }
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var status_buf: [3]u8 = undefined;
        var fields = try self.headerFields(&fields_buf, &status_buf);
        const body_forbidden = self.status == 204 or self.status == 304;
        if (body_forbidden) {
            if (self.status == 204 and findHeader(
                self.headers,
                "content-length",
            ) != null) {
                return error.InvalidContentLength;
            }
            if (body_length) |length| {
                if (length != 0) return error.InvalidContentLength;
            }
            try validateHeaderBlock(fields, .response);
            try validateFieldSectionSize(
                fields,
                peer_settings.max_field_section_size,
            );
            try validateResponseBodyForStatus(
                self.status,
                fields,
                &.{},
                &.{},
            );
            try writeHeadersFrameDynamic(
                list,
                allocator,
                fields,
                stream_id,
                encoder,
            );
            try queueIndexableFields(encoder, fields);
            return .{ .expected_length = 0, .body_allowed = false };
        }
        var content_length_buf: [32]u8 = undefined;
        const effective_length = try applyStreamingContentLength(
            &fields_buf,
            &fields,
            body_length,
            &content_length_buf,
        );
        try validateHeaderBlock(fields, .response);
        try validateFieldSectionSize(
            fields,
            peer_settings.max_field_section_size,
        );
        try validateResponseBodyForStatus(self.status, fields, &.{}, &.{});
        try writeHeadersFrameDynamic(
            list,
            allocator,
            fields,
            stream_id,
            encoder,
        );
        try queueIndexableFields(encoder, fields);
        return .{
            .expected_length = effective_length,
            .body_allowed = true,
        };
    }
};

fn applyStreamingContentLength(
    fields_buf: *[64]Qpack.HeaderField,
    fields: *[]Qpack.HeaderField,
    requested: ?usize,
    content_length_buf: *[32]u8,
) Error!?usize {
    const declared = try contentLength(fields.*);
    const expected = requested orelse return declared;
    if (declared) |value| {
        if (value != expected) return error.InvalidContentLength;
        return expected;
    }
    const rendered = std.fmt.bufPrint(
        content_length_buf,
        "{}",
        .{expected},
    ) catch unreachable;
    var field_count = fields.*.len;
    try appendHeaderField(fields_buf, &field_count, .{
        .name = "content-length",
        .value = rendered,
    });
    fields.* = fields_buf[0..field_count];
    return expected;
}

fn responseShouldDefaultContentLength(status: u16, headers: []const Qpack.HeaderField, body_len: usize) bool {
    if (body_len == 0) return false;
    if ((status >= 100 and status < 200) or status == 204 or status == 304) return false;
    return (contentLength(headers) catch return false) == null;
}

pub const InformationalResponse = struct {
    status: u16,
    headers: []const Qpack.HeaderField = &.{},

    pub fn headerFields(self: InformationalResponse, out: []Qpack.HeaderField, status_buf: *[3]u8) Error![]Qpack.HeaderField {
        if (self.status < 100 or self.status >= 200) return error.InvalidStatus;
        var count: usize = 0;
        const status = std.fmt.bufPrint(status_buf, "{d}", .{self.status}) catch return error.InvalidStatus;
        try appendHeaderField(out, &count, .{ .name = ":status", .value = status });
        for (self.headers) |header| try appendHeaderField(out, &count, header);
        return out[0..count];
    }

    pub fn write(self: InformationalResponse, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try self.writeWithSettings(list, allocator, .{});
    }

    pub fn writeWithSettings(self: InformationalResponse, list: *std.ArrayList(u8), allocator: std.mem.Allocator, peer_settings: Settings) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var status_buf: [3]u8 = undefined;
        const fields = try self.headerFields(&fields_buf, &status_buf);
        try validateHeaderBlock(fields, .response);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateResponseBodyForStatus(self.status, fields, &.{}, &.{});
        try writeHeadersFrame(list, allocator, fields);
    }

    pub fn writeDynamic(
        self: InformationalResponse,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
    ) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var status_buf: [3]u8 = undefined;
        const fields = try self.headerFields(&fields_buf, &status_buf);
        try validateHeaderBlock(fields, .response);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateResponseBodyForStatus(self.status, fields, &.{}, &.{});
        try writeHeadersFrameDynamic(
            list,
            allocator,
            fields,
            stream_id,
            encoder,
        );
        try queueIndexableFields(encoder, fields);
    }
};

pub fn writeResponseSequence(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    informational: []const InformationalResponse,
    response: Response,
) Error!void {
    try writeResponseSequenceWithSettings(list, allocator, informational, response, .{});
}

pub fn writeResponseSequenceWithSettings(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    informational: []const InformationalResponse,
    response: Response,
    peer_settings: Settings,
) Error!void {
    for (informational) |info| try info.writeWithSettings(list, allocator, peer_settings);
    try response.writeWithSettings(list, allocator, peer_settings);
}

pub fn writeResponseSequenceDynamic(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    informational: []const InformationalResponse,
    response: Response,
    peer_settings: Settings,
    stream_id: u64,
    encoder: anytype,
) Error!void {
    for (informational) |info| {
        try info.writeDynamic(
            list,
            allocator,
            peer_settings,
            stream_id,
            encoder,
        );
    }
    try response.writeDynamic(
        list,
        allocator,
        peer_settings,
        stream_id,
        encoder,
    );
}

pub const DecodedRequest = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    headers: []Qpack.HeaderField,
    trailers: []Qpack.HeaderField = &.{},
    body: []const u8,
    body_storage: ?[]u8 = null,
    consumed: usize,
    qpack_section_acknowledgments: usize = 0,

    /// Release arrays and body storage owned by `decodeRequest`. Header field
    /// names/values still borrow from the encoded stream bytes; callers must
    /// keep those bytes alive while reading `headers` or `trailers`.
    pub fn deinit(self: *DecodedRequest, allocator: std.mem.Allocator) void {
        Qpack.freeDecodedFields(allocator, self.headers);
        Qpack.freeDecodedFields(allocator, self.trailers);
        if (self.body_storage) |body| allocator.free(body);
        self.* = undefined;
    }
};

pub const DecodedResponse = struct {
    status: u16,
    headers: []Qpack.HeaderField,
    trailers: []Qpack.HeaderField = &.{},
    body: []const u8,
    body_storage: ?[]u8 = null,
    consumed: usize,
    qpack_section_acknowledgments: usize = 0,

    pub fn successful(self: DecodedResponse) bool {
        return self.status >= 200 and self.status < 300;
    }

    /// Release arrays and body storage owned by `decodeResponse`. Header field
    /// names/values still borrow from the encoded stream bytes; callers must
    /// keep those bytes alive while reading `headers` or `trailers`.
    pub fn deinit(self: *DecodedResponse, allocator: std.mem.Allocator) void {
        Qpack.freeDecodedFields(allocator, self.headers);
        Qpack.freeDecodedFields(allocator, self.trailers);
        if (self.body_storage) |body| allocator.free(body);
        self.* = undefined;
    }
};

pub const DecodedRequestHead = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    headers: []Qpack.HeaderField,
    content_length: ?usize,
    body_allowed: bool,
    consumed: usize,
    qpack_section_acknowledgments: usize,

    pub fn deinit(
        self: *DecodedRequestHead,
        allocator: std.mem.Allocator,
    ) void {
        Qpack.freeDecodedFields(allocator, self.headers);
        self.* = undefined;
    }
};

pub const DecodedResponseHead = struct {
    status: u16,
    headers: []Qpack.HeaderField,
    content_length: ?usize,
    body_allowed: bool,
    consumed: usize,
    qpack_section_acknowledgments: usize,

    pub fn deinit(
        self: *DecodedResponseHead,
        allocator: std.mem.Allocator,
    ) void {
        Qpack.freeDecodedFields(allocator, self.headers);
        self.* = undefined;
    }
};

pub const DecodedTrailers = struct {
    fields: []Qpack.HeaderField,
    qpack_section_acknowledgments: usize,

    pub fn deinit(
        self: *DecodedTrailers,
        allocator: std.mem.Allocator,
    ) void {
        Qpack.freeDecodedFields(allocator, self.fields);
        self.* = undefined;
    }
};

pub fn decodeTrailersWithDynamicTable(
    allocator: std.mem.Allocator,
    payload: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedTrailers {
    const field_decoder = FieldSectionDecoder{ .dynamic = table };
    const decoded = try field_decoder.decode(allocator, payload);
    errdefer Qpack.freeDecodedFields(allocator, decoded.fields);
    try validateHeaderBlock(decoded.fields, .trailers);
    try validateFieldSectionSize(
        decoded.fields,
        settings.max_field_section_size,
    );
    const owned = try ownHeaderFields(allocator, decoded.fields);
    Qpack.freeDecodedFields(allocator, decoded.fields);
    return .{
        .fields = owned,
        .qpack_section_acknowledgments = @intFromBool(decoded.requires_acknowledgment),
    };
}

pub fn decodeRequestHeadWithDynamicTable(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedRequestHead {
    const frame = try firstHeadersFrame(bytes, .request);
    var head = try decodeRequestHeadFieldSectionWithDynamicTable(
        allocator,
        frame.value.payload,
        settings,
        table,
    );
    head.consumed = frame.consumed;
    return head;
}

pub fn decodeRequestHeadFieldSectionWithDynamicTable(
    allocator: std.mem.Allocator,
    field_section: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedRequestHead {
    const field_decoder = FieldSectionDecoder{ .dynamic = table };
    const decoded = try field_decoder.decode(allocator, field_section);
    errdefer Qpack.freeDecodedFields(allocator, decoded.fields);
    try validateHeaderBlock(decoded.fields, .request);
    try validateFieldSectionSize(
        decoded.fields,
        settings.max_field_section_size,
    );

    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    for (decoded.fields) |header| {
        if (std.mem.eql(u8, header.name, ":method")) {
            method = header.value;
        } else if (std.mem.eql(u8, header.name, ":path")) {
            path = header.value;
        } else if (std.mem.eql(u8, header.name, ":scheme")) {
            scheme = header.value;
        } else if (std.mem.eql(u8, header.name, ":authority")) {
            authority = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "host") and
            authority == null)
        {
            authority = header.value;
        }
    }
    const method_value = method orelse return error.MissingMethod;
    const has_protocol = requestHasProtocolPseudo(decoded.fields);
    if (has_protocol and !settings.enable_connect_protocol) {
        return error.ExtendedConnectDisabled;
    }
    const plain_connect = std.mem.eql(u8, method_value, "CONNECT") and
        !has_protocol;
    const declared_length = try contentLength(decoded.fields);
    if (plain_connect and declared_length != null) {
        return error.InvalidContentLength;
    }
    // validateHeaderBlock above guarantees these pseudo fields. Resolve all
    // fallible semantic choices before transferring field ownership so no
    // error path can double-free the decoder output.
    _ = path orelse if (plain_connect) "" else return error.MissingPath;
    _ = scheme orelse if (plain_connect) "" else return error.InvalidHeader;
    const owned_fields = try ownHeaderFields(allocator, decoded.fields);
    Qpack.freeDecodedFields(allocator, decoded.fields);
    return .{
        .method = ownedFieldValue(owned_fields, ":method").?,
        .path = ownedFieldValue(owned_fields, ":path") orelse
            if (plain_connect) "" else return error.MissingPath,
        .scheme = ownedFieldValue(owned_fields, ":scheme") orelse
            if (plain_connect) "" else return error.InvalidHeader,
        .authority = ownedFieldValue(owned_fields, ":authority") orelse
            ownedFieldValueCaseInsensitive(owned_fields, "host"),
        .headers = owned_fields,
        .content_length = declared_length,
        .body_allowed = !plain_connect,
        .consumed = 0,
        .qpack_section_acknowledgments = @intFromBool(decoded.requires_acknowledgment),
    };
}

pub fn decodeResponseHeadWithDynamicTable(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedResponseHead {
    var offset: usize = 0;
    var acknowledgments: usize = 0;
    while (true) {
        const frame = try firstHeadersFrame(bytes[offset..], .response);
        var head = try decodeResponseHeadFieldSectionWithDynamicTable(
            allocator,
            frame.value.payload,
            settings,
            table,
        );
        acknowledgments += head.qpack_section_acknowledgments;
        offset += frame.consumed;
        if (head.status < 200) {
            head.deinit(allocator);
            if (offset >= bytes.len) return error.BufferTooShort;
            continue;
        }
        head.consumed = offset;
        head.qpack_section_acknowledgments = acknowledgments;
        return head;
    }
}

pub fn decodeResponseHeadFieldSectionWithDynamicTable(
    allocator: std.mem.Allocator,
    field_section: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedResponseHead {
    const field_decoder = FieldSectionDecoder{ .dynamic = table };
    const decoded = try field_decoder.decode(allocator, field_section);
    errdefer Qpack.freeDecodedFields(allocator, decoded.fields);
    try validateHeaderBlock(decoded.fields, .response);
    try validateFieldSectionSize(
        decoded.fields,
        settings.max_field_section_size,
    );
    const status = try responseStatus(decoded.fields);
    const declared_length = try contentLength(decoded.fields);
    if (status == 204 and declared_length != null) {
        return error.InvalidContentLength;
    }
    const owned_fields = try ownHeaderFields(allocator, decoded.fields);
    Qpack.freeDecodedFields(allocator, decoded.fields);
    return .{
        .status = status,
        .headers = owned_fields,
        .content_length = declared_length,
        .body_allowed = status != 204 and status != 304,
        .consumed = 0,
        .qpack_section_acknowledgments = @intFromBool(decoded.requires_acknowledgment),
    };
}

const FirstHeaders = struct {
    value: Frame,
    consumed: usize,
};

fn firstHeadersFrame(
    bytes: []const u8,
    kind: MessageStreamKind,
) Error!FirstHeaders {
    var offset: usize = 0;
    while (true) {
        const frame = try Frame.parse(bytes[offset..]);
        offset += frame.consumed;
        if (frame.frame_type == FrameType.headers) {
            return .{ .value = frame, .consumed = offset };
        }
        if (frame.frame_type == FrameType.push_promise) {
            if (kind == .request) return error.ExpectedHeadersFrame;
            _ = try parsePushPromisePayload(frame.payload);
        } else if (frame.frame_type == FrameType.data or
            requestStreamForbiddenFrame(frame.frame_type))
        {
            return error.ExpectedHeadersFrame;
        }
        if (offset >= bytes.len) return error.BufferTooShort;
    }
}

fn ownHeaderFields(
    allocator: std.mem.Allocator,
    fields: []const Qpack.HeaderField,
) std.mem.Allocator.Error![]Qpack.HeaderField {
    const owned = try allocator.alloc(Qpack.HeaderField, fields.len);
    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |field| {
            if (field.name_storage) |storage| allocator.free(storage);
            if (field.value_storage) |storage| allocator.free(storage);
        }
        allocator.free(owned);
    }
    for (fields, owned) |field, *destination| {
        const name = try allocator.dupe(u8, field.name);
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, field.value);
        destination.* = .{
            .name = name,
            .value = value,
            .never_indexed = field.never_indexed,
            .name_storage = name,
            .value_storage = value,
        };
        initialized += 1;
    }
    return owned;
}

fn ownedFieldValue(
    fields: []const Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}

fn ownedFieldValueCaseInsensitive(
    fields: []const Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}

pub fn decodeRequest(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedRequest {
    // `decodeRequest` is the codec-level entry point and intentionally does
    // not assume a SETTINGS exchange has happened. Negotiated runtime paths
    // call `decodeRequestWithSettings`, which enforces advertised features such
    // as RFC 9220 extended CONNECT.
    return decodeRequestWithOptions(allocator, bytes, .{}, false, .literal);
}

pub fn decodeRequestWithSettings(allocator: std.mem.Allocator, bytes: []const u8, settings: Settings) Error!DecodedRequest {
    return decodeRequestWithOptions(allocator, bytes, settings, true, .literal);
}

pub fn decodeRequestWithDynamicTable(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedRequest {
    return decodeRequestWithOptions(allocator, bytes, settings, true, .{ .dynamic = table });
}

fn decodeRequestWithOptions(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    enforce_extended_connect_setting: bool,
    field_decoder: FieldSectionDecoder,
) Error!DecodedRequest {
    var message = try decodeMessage(
        allocator,
        bytes,
        .request,
        settings.max_field_section_size,
        field_decoder,
    );
    errdefer message.deinit(allocator);

    try validateHeaderBlock(message.headers, .request);
    try validateHeaderBlock(message.trailers, .trailers);
    try validateRequestBodyForMethod(message.headers, message.body, message.trailers);
    try validateContentLength(message.headers, message.body.len);

    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    for (message.headers) |header| {
        if (std.mem.eql(u8, header.name, ":method")) {
            method = header.value;
        } else if (std.mem.eql(u8, header.name, ":path")) {
            path = header.value;
        } else if (std.mem.eql(u8, header.name, ":scheme")) {
            scheme = header.value;
        } else if (std.mem.eql(u8, header.name, ":authority")) {
            authority = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "host") and authority == null) {
            authority = header.value;
        }
    }
    const method_value = method orelse return error.MissingMethod;
    const has_protocol = requestHasProtocolPseudo(message.headers);
    if (enforce_extended_connect_setting and has_protocol and !settings.enable_connect_protocol) {
        return error.ExtendedConnectDisabled;
    }
    const plain_connect = std.mem.eql(u8, method_value, "CONNECT") and !has_protocol;

    return .{
        .method = method_value,
        .path = path orelse if (plain_connect) "" else return error.MissingPath,
        .scheme = scheme orelse if (plain_connect) "" else return error.InvalidHeader,
        .authority = authority,
        .headers = message.headers,
        .trailers = message.trailers,
        .body = message.body,
        .body_storage = message.body_storage,
        .consumed = message.consumed,
        .qpack_section_acknowledgments = message.qpack_section_acknowledgments,
    };
}

pub fn decodeResponse(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedResponse {
    return decodeResponseWithSettings(allocator, bytes, .{});
}

pub fn decodeResponseWithSettings(allocator: std.mem.Allocator, bytes: []const u8, settings: Settings) Error!DecodedResponse {
    return decodeResponseWithFieldDecoder(allocator, bytes, settings, .literal);
}

pub fn decodeResponseWithDynamicTable(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedResponse {
    return decodeResponseWithFieldDecoder(
        allocator,
        bytes,
        settings,
        .{ .dynamic = table },
    );
}

fn decodeResponseWithFieldDecoder(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    field_decoder: FieldSectionDecoder,
) Error!DecodedResponse {
    var message = try decodeResponseMessage(
        allocator,
        bytes,
        settings.max_field_section_size,
        field_decoder,
    );
    errdefer message.deinit(allocator);

    try validateHeaderBlock(message.headers, .response);
    try validateHeaderBlock(message.trailers, .trailers);

    const final_status = try responseStatus(message.headers);
    try validateResponseBodyForStatus(final_status, message.headers, message.body, message.trailers);
    try validateContentLengthForStatus(final_status, message.headers, message.body.len);

    return .{
        .status = final_status,
        .headers = message.headers,
        .trailers = message.trailers,
        .body = message.body,
        .body_storage = message.body_storage,
        .consumed = message.consumed,
        .qpack_section_acknowledgments = message.qpack_section_acknowledgments,
    };
}

const DecodedMessage = struct {
    headers: []Qpack.HeaderField,
    trailers: []Qpack.HeaderField = &.{},
    body: []const u8,
    body_storage: ?[]u8 = null,
    consumed: usize,
    qpack_section_acknowledgments: usize = 0,

    fn deinit(self: *DecodedMessage, allocator: std.mem.Allocator) void {
        Qpack.freeDecodedFields(allocator, self.headers);
        Qpack.freeDecodedFields(allocator, self.trailers);
        if (self.body_storage) |body| allocator.free(body);
        self.* = undefined;
    }
};

const MessageStreamKind = enum {
    request,
    response,
};

const DecodedFieldSection = struct {
    fields: []Qpack.HeaderField,
    requires_acknowledgment: bool = false,
};

const FieldSectionDecoder = union(enum) {
    literal,
    dynamic: Qpack.DynamicTable,

    fn decode(
        self: FieldSectionDecoder,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) Error!DecodedFieldSection {
        return switch (self) {
            .literal => .{ .fields = try Qpack.decodeLiteralBlock(allocator, payload) },
            .dynamic => |table| blk: {
                const decoded = try Qpack.decodeDynamicBlock(allocator, payload, table);
                break :blk .{
                    .fields = decoded.fields,
                    .requires_acknowledgment = decoded.required_insert_count != 0,
                };
            },
        };
    }
};

fn writeHeadersFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const Qpack.HeaderField) Error!void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&block, allocator, fields);
    try (Frame{ .frame_type = FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, allocator);
}

fn writeHeadersFrameDynamic(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const Qpack.HeaderField,
    stream_id: u64,
    encoder: anytype,
) Error!void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(&block, stream_id, fields);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(list, allocator);
}

pub fn writeTrailersDynamic(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    trailers: []const Qpack.HeaderField,
    peer_settings: Settings,
    stream_id: u64,
    encoder: anytype,
) Error!void {
    if (trailers.len == 0) return error.InvalidHeader;
    try validateHeaderBlock(trailers, .trailers);
    try validateFieldSectionSize(
        trailers,
        peer_settings.max_field_section_size,
    );
    try writeHeadersFrameDynamic(
        list,
        allocator,
        trailers,
        stream_id,
        encoder,
    );
    try queueIndexableFields(encoder, trailers);
}

fn writeHeadersAndData(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const Qpack.HeaderField,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
) Error!void {
    try writeHeadersFrame(list, allocator, fields);
    if (body.len > 0) {
        try (Frame{ .frame_type = FrameType.data, .payload = body, .consumed = 0 }).write(list, allocator);
    }
    if (trailers.len > 0) {
        try writeHeadersFrame(list, allocator, trailers);
    }
}

fn writeHeadersAndDataDynamic(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const Qpack.HeaderField,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
    stream_id: u64,
    encoder: anytype,
) Error!void {
    try writeHeadersFrameDynamic(list, allocator, fields, stream_id, encoder);
    if (body.len > 0) {
        try (Frame{
            .frame_type = FrameType.data,
            .payload = body,
            .consumed = 0,
        }).write(list, allocator);
    }
    if (trailers.len > 0) {
        try writeHeadersFrameDynamic(
            list,
            allocator,
            trailers,
            stream_id,
            encoder,
        );
    }
}

fn queueIndexableFields(encoder: anytype, fields: []const Qpack.HeaderField) !void {
    for (fields) |field| {
        if (!qpackShouldIndex(field)) continue;
        if (encoder.table.findExact(field.name, field.value) != null) continue;
        _ = try encoder.insertField(field.name, field.value);
    }
}

fn qpackShouldIndex(field: Qpack.HeaderField) bool {
    if (field.never_indexed) return false;
    if (field.name.len + field.value.len < 8) return false;
    if (std.mem.eql(u8, field.name, "authorization") or
        std.mem.eql(u8, field.name, "proxy-authorization") or
        std.mem.eql(u8, field.name, "cookie") or
        std.mem.eql(u8, field.name, "set-cookie"))
    {
        return false;
    }
    return true;
}

fn requestStreamForbiddenFrame(frame_type: u64) bool {
    return switch (frame_type) {
        FrameType.cancel_push,
        FrameType.settings,
        FrameType.goaway,
        FrameType.max_push_id,
        FrameType.priority_update_request,
        FrameType.priority_update_push,
        => true,
        else => false,
    };
}

fn responseStatus(headers: []const Qpack.HeaderField) Error!u16 {
    for (headers) |header| {
        if (!std.mem.eql(u8, header.name, ":status")) continue;
        if (header.value.len != 3) return error.InvalidStatus;
        for (header.value) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidStatus;
        }
        const status = std.fmt.parseInt(u16, header.value, 10) catch return error.InvalidStatus;
        if (status < 100 or status > 999) return error.InvalidStatus;
        return status;
    }
    return error.MissingStatus;
}

fn decodeResponseMessage(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    max_field_section_size: u64,
    field_decoder: FieldSectionDecoder,
) Error!DecodedMessage {
    var offset: usize = 0;
    var informational_acknowledgments: usize = 0;
    while (true) {
        const frame = try Frame.parse(bytes[offset..]);
        if (frame.frame_type != FrameType.headers) {
            if (frame.frame_type == FrameType.data or requestStreamForbiddenFrame(frame.frame_type)) return error.ExpectedHeadersFrame;
            if (frame.frame_type == FrameType.push_promise) _ = try parsePushPromisePayload(frame.payload);
            offset += frame.consumed;
            if (offset >= bytes.len) return error.MissingStatus;
            continue;
        }
        const decoded = try field_decoder.decode(allocator, frame.payload);
        var decoded_owned = true;
        defer if (decoded_owned) Qpack.freeDecodedFields(allocator, decoded.fields);
        try validateHeaderBlock(decoded.fields, .response);
        try validateFieldSectionSize(decoded.fields, max_field_section_size);
        const status = try responseStatus(decoded.fields);
        if (status < 200) {
            informational_acknowledgments += @intFromBool(decoded.requires_acknowledgment);
            Qpack.freeDecodedFields(allocator, decoded.fields);
            decoded_owned = false;
            offset += frame.consumed;
            if (offset >= bytes.len) return error.MissingStatus;
            continue;
        }
        decoded_owned = false;
        var message = try decodeMessageAfterHeaders(
            allocator,
            bytes,
            .response,
            max_field_section_size,
            field_decoder,
            decoded,
            offset + frame.consumed,
        );
        message.qpack_section_acknowledgments += informational_acknowledgments;
        return message;
    }
}

fn decodeMessage(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    kind: MessageStreamKind,
    max_field_section_size: u64,
    field_decoder: FieldSectionDecoder,
) Error!DecodedMessage {
    var offset: usize = 0;
    const headers_frame = while (true) {
        const frame = try Frame.parse(bytes[offset..]);
        if (frame.frame_type == FrameType.headers) break frame;
        if (frame.frame_type == FrameType.push_promise) {
            if (kind == .request) return error.ExpectedHeadersFrame;
            _ = try parsePushPromisePayload(frame.payload);
            offset += frame.consumed;
            if (offset >= bytes.len) return error.ExpectedHeadersFrame;
            continue;
        }
        if (frame.frame_type == FrameType.data or requestStreamForbiddenFrame(frame.frame_type)) return error.ExpectedHeadersFrame;
        // RFC 9114 allows unknown extension frames on request streams.  Like
        // tquic's request-stream state machine, ignore them before the first
        // HEADERS rather than treating every non-HEADERS frame as fatal.
        offset += frame.consumed;
        if (offset >= bytes.len) return error.ExpectedHeadersFrame;
    };
    const decoded_headers = try field_decoder.decode(allocator, headers_frame.payload);
    var headers_owned = true;
    errdefer if (headers_owned) Qpack.freeDecodedFields(allocator, decoded_headers.fields);
    try validateFieldSectionSize(decoded_headers.fields, max_field_section_size);
    headers_owned = false;
    return decodeMessageAfterHeaders(
        allocator,
        bytes,
        kind,
        max_field_section_size,
        field_decoder,
        decoded_headers,
        offset + headers_frame.consumed,
    );
}

fn decodeMessageAfterHeaders(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    kind: MessageStreamKind,
    max_field_section_size: u64,
    field_decoder: FieldSectionDecoder,
    decoded_headers: DecodedFieldSection,
    initial_consumed: usize,
) Error!DecodedMessage {
    errdefer Qpack.freeDecodedFields(allocator, decoded_headers.fields);
    var consumed = initial_consumed;
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    var trailers: []Qpack.HeaderField = &.{};
    errdefer Qpack.freeDecodedFields(allocator, trailers);
    var saw_trailers = false;
    var qpack_section_acknowledgments: usize =
        @intFromBool(decoded_headers.requires_acknowledgment);
    while (consumed < bytes.len) {
        const frame = try Frame.parse(bytes[consumed..]);
        consumed += frame.consumed;
        switch (frame.frame_type) {
            FrameType.data => {
                if (saw_trailers) return error.UnexpectedFrame;
                try body.appendSlice(allocator, frame.payload);
            },
            FrameType.headers => {
                if (saw_trailers) return error.UnexpectedFrame;
                const decoded_trailers = try field_decoder.decode(allocator, frame.payload);
                errdefer Qpack.freeDecodedFields(allocator, decoded_trailers.fields);
                try validateFieldSectionSize(decoded_trailers.fields, max_field_section_size);
                trailers = decoded_trailers.fields;
                qpack_section_acknowledgments +=
                    @intFromBool(decoded_trailers.requires_acknowledgment);
                saw_trailers = true;
            },
            FrameType.push_promise => {
                if (kind == .request or saw_trailers) return error.UnexpectedFrame;
                _ = try parsePushPromisePayload(frame.payload);
            },
            else => if (requestStreamForbiddenFrame(frame.frame_type)) return error.UnexpectedFrame,
        }
    }

    const body_storage: ?[]u8 = if (body.items.len == 0) storage: {
        body.deinit(allocator);
        break :storage null;
    } else try body.toOwnedSlice(allocator);

    return .{
        .headers = decoded_headers.fields,
        .trailers = trailers,
        .body = if (body_storage) |storage| storage else &.{},
        .body_storage = body_storage,
        .consumed = consumed,
        .qpack_section_acknowledgments = qpack_section_acknowledgments,
    };
}

fn appendHeaderField(out: []Qpack.HeaderField, count: *usize, field: Qpack.HeaderField) Error!void {
    if (count.* >= out.len) return error.InvalidFrame;
    out[count.*] = field;
    count.* += 1;
}

fn validateFieldSectionSize(headers: []const Qpack.HeaderField, max_field_section_size: u64) Error!void {
    var size: u64 = 0;
    for (headers) |header| {
        size = std.math.add(u64, size, header.name.len) catch return error.ExcessiveLoad;
        size = std.math.add(u64, size, header.value.len) catch return error.ExcessiveLoad;
        // RFC 9114 §4.2.2 carries over the HTTP/2/QPACK accounting rule: the
        // field section size is the uncompressed name/value bytes plus 32 bytes
        // per field.  Enforce the advertised limit after decoding so compressed
        // representations cannot bypass SETTINGS_MAX_FIELD_SECTION_SIZE.
        size = std.math.add(u64, size, 32) catch return error.ExcessiveLoad;
        if (size > max_field_section_size) return error.ExcessiveLoad;
    }
}

fn contentLength(headers: []const Qpack.HeaderField) Error!?usize {
    var found: ?usize = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
        var parts = std.mem.splitScalar(u8, header.value, ',');
        while (parts.next()) |raw_part| {
            const part = std.mem.trim(u8, raw_part, " \t");
            if (part.len == 0) return error.InvalidContentLength;
            for (part) |byte| {
                if (!std.ascii.isDigit(byte)) return error.InvalidContentLength;
            }
            const parsed = std.fmt.parseInt(usize, part, 10) catch return error.InvalidContentLength;
            if (found) |existing| {
                if (existing != parsed) return error.InvalidContentLength;
            } else {
                found = parsed;
            }
        }
    }
    return found;
}

fn validateRequestBodyForMethod(headers: []const Qpack.HeaderField, body: []const u8, trailers: []const Qpack.HeaderField) Error!void {
    var method: ?[]const u8 = null;
    var has_protocol = false;
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":method")) method = header.value;
        if (std.mem.eql(u8, header.name, ":protocol")) has_protocol = true;
    }
    if (method) |value| {
        if (std.mem.eql(u8, value, "CONNECT") and !has_protocol) {
            if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
            if ((try contentLength(headers)) != null) return error.InvalidContentLength;
        }
    }
}

fn validateContentLength(headers: []const Qpack.HeaderField, actual: usize) Error!void {
    if (try contentLength(headers)) |expected| {
        if (expected != actual) return error.InvalidContentLength;
    }
}

fn validateContentLengthForStatus(status: u16, headers: []const Qpack.HeaderField, actual: usize) Error!void {
    if (try contentLength(headers)) |expected| {
        if (status == 304 and actual == 0) return;
        if (expected != actual) return error.InvalidContentLength;
    }
}

fn validateResponseBodyForStatus(
    status: u16,
    headers: []const Qpack.HeaderField,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
) Error!void {
    if (!((status >= 100 and status < 200) or status == 204 or status == 304)) return;
    if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
    const declared_content_length = try contentLength(headers);
    if (status != 304 and declared_content_length != null) return error.InvalidContentLength;
}

const HeaderBlockKind = enum {
    request,
    response,
    trailers,
};

fn validateHeaderBlock(headers: []const Qpack.HeaderField, kind: HeaderBlockKind) Error!void {
    var saw_regular = false;
    var seen_method = false;
    var seen_scheme = false;
    var seen_path = false;
    var seen_authority = false;
    var seen_protocol = false;
    var seen_status = false;
    var method_value: ?[]const u8 = null;
    var scheme_value: ?[]const u8 = null;
    var path_value: ?[]const u8 = null;
    var authority_value: ?[]const u8 = null;
    var protocol_value: ?[]const u8 = null;
    var host_value: ?[]const u8 = null;

    for (headers) |header| {
        try validateHeaderName(header.name);
        try validateHeaderValue(header.value);
        const pseudo = std.mem.startsWith(u8, header.name, ":");
        if (pseudo) {
            if (saw_regular) return error.InvalidHeader;
            switch (kind) {
                .request => {
                    try markRequestPseudo(header.name, &seen_method, &seen_scheme, &seen_path, &seen_authority, &seen_protocol);
                    if (std.mem.eql(u8, header.name, ":method")) method_value = header.value;
                    if (std.mem.eql(u8, header.name, ":scheme")) scheme_value = header.value;
                    if (std.mem.eql(u8, header.name, ":path")) path_value = header.value;
                    if (std.mem.eql(u8, header.name, ":authority")) authority_value = header.value;
                    if (std.mem.eql(u8, header.name, ":protocol")) protocol_value = header.value;
                },
                .response => {
                    try markResponsePseudo(header.name, &seen_status);
                    if (std.mem.eql(u8, header.name, ":status")) {
                        if (header.value.len != 3) return error.InvalidStatus;
                        for (header.value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidStatus;
                        const parsed_status = std.fmt.parseInt(u16, header.value, 10) catch return error.InvalidStatus;
                        if (parsed_status < 100) return error.InvalidStatus;
                        if (parsed_status == 101) return error.InvalidStatus;
                    }
                },
                .trailers => return error.InvalidHeader,
            }
            continue;
        }
        saw_regular = true;

        if (kind == .trailers and forbiddenTrailerFieldName(header.name)) return error.InvalidHeader;
        if (std.mem.eql(u8, header.name, "host")) {
            if (host_value != null) return error.InvalidHeader;
            host_value = header.value;
        }
        if (connectionSpecificHeaderName(header.name)) return error.InvalidHeader;
        if (std.ascii.eqlIgnoreCase(header.name, "te")) {
            switch (kind) {
                .request => if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, header.value, " \t"), "trailers")) return error.InvalidHeader,
                .response, .trailers => return error.InvalidHeader,
            }
        }
    }

    switch (kind) {
        .request => {
            const method = method_value orelse return error.MissingMethod;
            try validateHttpToken(method);
            const is_connect = std.mem.eql(u8, method, "CONNECT");
            if (is_connect and !seen_protocol) {
                // RFC 9114 preserves the HTTP CONNECT authority-form special
                // case: traditional CONNECT carries :method and :authority, but
                // omits :scheme and :path. Extended CONNECT (:protocol present)
                // falls through to the regular request-target requirements.
                if (!seen_authority or seen_scheme or seen_path) return error.InvalidHeader;
                try validateConnectAuthority(authority_value orelse return error.InvalidHeader);
                return;
            }
            if (seen_protocol) {
                try validateHttpToken(protocol_value orelse return error.InvalidHeader);
                if (!is_connect) return error.InvalidHeader;
            }
            const scheme = scheme_value orelse return error.InvalidHeader;
            try validateUriScheme(scheme);
            const path = path_value orelse return error.MissingPath;
            try validateUriPath(method, path);
            if (authority_value) |authority| try validateRequestAuthority(authority);
            if (host_value) |host| try validateRequestAuthority(host);
            if (authority_value) |authority| {
                if (host_value) |host| {
                    if (!std.ascii.eqlIgnoreCase(authority, host)) return error.InvalidHeader;
                }
            }
            if ((std.mem.eql(u8, scheme, "http") or std.mem.eql(u8, scheme, "https")) and
                ((authority_value == null or authority_value.?.len == 0) and host_value == null))
            {
                return error.InvalidHeader;
            }
        },
        .response => if (!seen_status) return error.MissingStatus,
        .trailers => {},
    }
}

fn validateHttpToken(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidHeader;
    for (value) |byte| {
        if (!isHttpTchar(byte)) return error.InvalidHeader;
    }
}

fn isHttpTchar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn validateUriScheme(scheme: []const u8) Error!void {
    if (scheme.len == 0) return error.InvalidHeader;
    if (!std.ascii.isAlphabetic(scheme[0])) return error.InvalidHeader;
    for (scheme[1..]) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '+' or byte == '-' or byte == '.')) return error.InvalidHeader;
    }
}

fn validateUriPath(method: []const u8, path: []const u8) Error!void {
    if (path.len == 0) return error.InvalidHeader;
    if (std.mem.eql(u8, path, "*")) {
        if (!std.mem.eql(u8, method, "OPTIONS")) return error.InvalidHeader;
        return;
    }
    if (path[0] != '/') return error.InvalidHeader;
    var saw_fragment = false;
    for (path) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == '\\') return error.InvalidHeader;
        if (byte == '#') saw_fragment = true;
    }
    if (saw_fragment) return error.InvalidHeader;
}

fn validateRequestAuthority(authority: []const u8) Error!void {
    if (authority.len == 0) return error.InvalidHeader;
    for (authority) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == '/' or byte == '\\' or byte == '?' or byte == '#' or byte == '@') return error.InvalidHeader;
    }
    if (authority[0] == '[') {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidHeader;
        if (end <= 1) return error.InvalidHeader;
        if (end + 1 < authority.len and authority[end + 1] != ':') return error.InvalidHeader;
        if (end + 1 == authority.len) return;
        try validateAuthorityPort(authority[end + 2 ..]);
        return;
    }
    if (std.mem.indexOfScalar(u8, authority, '[') != null or std.mem.indexOfScalar(u8, authority, ']') != null) return error.InvalidHeader;
    if (std.mem.indexOfScalar(u8, authority, ':')) |colon| {
        if (colon == 0) return error.InvalidHeader;
        if (std.mem.indexOfScalar(u8, authority[colon + 1 ..], ':') != null) return error.InvalidHeader;
        try validateAuthorityPort(authority[colon + 1 ..]);
    }
}

fn validateConnectAuthority(authority: []const u8) Error!void {
    try validateRequestAuthority(authority);
    const port: []const u8 = if (authority[0] == '[') blk: {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidHeader;
        if (end <= 1 or end + 2 > authority.len or authority[end + 1] != ':') return error.InvalidHeader;
        break :blk authority[end + 2 ..];
    } else blk: {
        const colon = std.mem.lastIndexOfScalar(u8, authority, ':') orelse return error.InvalidHeader;
        if (colon == 0 or colon + 1 >= authority.len) return error.InvalidHeader;
        if (std.mem.indexOfScalar(u8, authority[0..colon], ':') != null) return error.InvalidHeader;
        break :blk authority[colon + 1 ..];
    };
    try validateAuthorityPort(port);
}

fn validateAuthorityPort(port: []const u8) Error!void {
    if (port.len == 0) return error.InvalidHeader;
    for (port) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidHeader;
    }
    const parsed_port = std.fmt.parseInt(u32, port, 10) catch return error.InvalidHeader;
    if (parsed_port > std.math.maxInt(u16)) return error.InvalidHeader;
}

fn validateHeaderName(name: []const u8) Error!void {
    if (name.len == 0) return error.InvalidHeader;
    if (name[0] == ':') {
        if (name.len == 1) return error.InvalidHeader;
        for (name[1..]) |byte| {
            if (!validHeaderNameByte(byte)) return error.InvalidHeader;
        }
        return;
    }
    for (name) |byte| {
        if (!validHeaderNameByte(byte)) return error.InvalidHeader;
    }
}

fn validateHeaderValue(value: []const u8) Error!void {
    for (value) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.InvalidHeader;
    }
}

fn validHeaderNameByte(byte: u8) bool {
    if (byte >= 'A' and byte <= 'Z') return false;
    return std.ascii.isLower(byte) or std.ascii.isDigit(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn markRequestPseudo(
    name: []const u8,
    seen_method: *bool,
    seen_scheme: *bool,
    seen_path: *bool,
    seen_authority: *bool,
    seen_protocol: *bool,
) Error!void {
    if (std.mem.eql(u8, name, ":method")) return markOnce(seen_method);
    if (std.mem.eql(u8, name, ":scheme")) return markOnce(seen_scheme);
    if (std.mem.eql(u8, name, ":path")) return markOnce(seen_path);
    if (std.mem.eql(u8, name, ":authority")) return markOnce(seen_authority);
    if (std.mem.eql(u8, name, ":protocol")) return markOnce(seen_protocol);
    return error.InvalidHeader;
}

fn markResponsePseudo(name: []const u8, seen_status: *bool) Error!void {
    if (std.mem.eql(u8, name, ":status")) return markOnce(seen_status);
    return error.InvalidHeader;
}

fn markOnce(seen: *bool) Error!void {
    if (seen.*) return error.InvalidHeader;
    seen.* = true;
}

fn forbiddenTrailerFieldName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "authorization") or
        std.ascii.eqlIgnoreCase(name, "cache-control") or
        std.ascii.eqlIgnoreCase(name, "content-encoding") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "content-range") or
        std.ascii.eqlIgnoreCase(name, "content-type") or
        std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "max-forwards") or
        std.ascii.eqlIgnoreCase(name, "set-cookie") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "te");
}

fn connectionSpecificHeaderName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade") or
        std.ascii.eqlIgnoreCase(name, "http2-settings");
}

pub const Datagram = struct {
    quarter_stream_id: u64,
    payload: []const u8,

    pub fn parse(bytes: []const u8) Error!Datagram {
        var cursor = wire.Cursor.init(bytes);
        const quarter_stream_id = try quic.varint.decode(&cursor);
        return .{ .quarter_stream_id = quarter_stream_id, .payload = bytes[cursor.pos..] };
    }

    pub fn write(self: Datagram, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        try quic.varint.encode(list, allocator, self.quarter_stream_id);
        try list.appendSlice(allocator, self.payload);
    }
};

test "HTTP/3 frame settings and qpack literal block" {
    const allocator = std.testing.allocator;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    const settings = [_]Setting{
        .{ .id = @intFromEnum(SettingId.h3_datagram), .value = 1 },
        .{ .id = @intFromEnum(SettingId.webtransport_max_sessions), .value = 16 },
    };
    try writeSettings(&payload, allocator, &settings);

    var encoded_frame: std.ArrayList(u8) = .empty;
    defer encoded_frame.deinit(allocator);
    try (Frame{ .frame_type = FrameType.settings, .payload = payload.items, .consumed = 0 }).write(&encoded_frame, allocator);
    const frame = try Frame.parse(encoded_frame.items);
    const parsed_settings = try parseSettings(allocator, frame.payload);
    defer allocator.free(parsed_settings);
    try std.testing.expectEqual(@as(u64, 1), parsed_settings[0].value);
    try std.testing.expectError(error.UnexpectedFrame, (Frame{
        .frame_type = 0x02, // HTTP/2 PRIORITY is reserved in HTTP/3.
        .payload = &.{},
        .consumed = 0,
    }).write(&encoded_frame, allocator));

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    const fields = [_]Qpack.HeaderField{ .{ .name = ":method", .value = "GET" }, .{ .name = ":path", .value = "/" } };
    try Qpack.encodeLiteralBlock(&block, allocator, &fields);
    try std.testing.expectEqual(@as(u8, 0xd1), block.items[2]); // static index 17, :method GET
    try std.testing.expectEqual(@as(u8, 0xc1), block.items[3]); // static index 1, :path /
    const decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer Qpack.freeDecodedFields(allocator, decoded);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
}

test "HTTP/3 frame header parses before payload arrives" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try quic.varint.encode(&encoded, allocator, FrameType.data);
    try quic.varint.encode(&encoded, allocator, 1_000_000);

    const header = try Frame.parseHeader(encoded.items);
    try std.testing.expectEqual(FrameType.data, header.frame_type);
    try std.testing.expectEqual(@as(usize, 1_000_000), header.payload_length);
    try std.testing.expectEqual(encoded.items.len, header.header_length);
    try std.testing.expectEqual(
        encoded.items.len + 1_000_000,
        try header.totalLength(),
    );
    try std.testing.expectError(
        error.BufferTooShort,
        Frame.parse(encoded.items),
    );

    for (0..encoded.items.len) |len| {
        try std.testing.expectError(
            error.BufferTooShort,
            Frame.parseHeader(encoded.items[0..len]),
        );
    }
}

test "HTTP/3 rejects reserved HTTP/2 frame types" {
    const allocator = std.testing.allocator;
    const reserved_frame_types = [_]u64{ 0x02, 0x06, 0x08, 0x09 };
    for (reserved_frame_types) |frame_type| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try std.testing.expectError(error.UnexpectedFrame, (Frame{ .frame_type = frame_type, .payload = "", .consumed = 0 }).write(&encoded, allocator));
        try quic.varint.encode(&encoded, allocator, frame_type);
        try quic.varint.encode(&encoded, allocator, 0);
        try std.testing.expectError(error.UnexpectedFrame, Frame.parse(encoded.items));
    }
}

test "HTTP/3 QPACK static name references and literal fallback" {
    const allocator = std.testing.allocator;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    const huffman = try Qpack.encodeHuffman(allocator, "www.example.com");
    defer allocator.free(huffman);
    try std.testing.expectEqualSlices(u8, &.{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff }, huffman);
    const decoded_huffman = try Qpack.decodeHuffman(allocator, huffman);
    defer allocator.free(decoded_huffman);
    try std.testing.expectEqualStrings("www.example.com", decoded_huffman);

    const fields = [_]Qpack.HeaderField{
        .{ .name = "content-type", .value = "application/problem+json" },
        .{ .name = "x-custom", .value = "value" },
    };
    try Qpack.encodeLiteralBlock(&block, allocator, &fields);
    try std.testing.expectEqual(@as(u8, 0x5f), block.items[2]); // static name ref with extended index, content-type

    const decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer Qpack.freeDecodedFields(allocator, decoded);
    try std.testing.expectEqualStrings("content-type", decoded[0].name);
    try std.testing.expectEqualStrings("application/problem+json", decoded[0].value);
    try std.testing.expectEqualStrings("x-custom", decoded[1].name);
    try std.testing.expectEqualStrings("value", decoded[1].value);
    try std.testing.expectEqualStrings(":status", Qpack.staticEntry(25).?.name);
    try std.testing.expectEqualStrings("200", Qpack.staticEntry(25).?.value);

    block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":StatuS", .value = "200" },
        .{ .name = "X-Proto", .value = "QUIC" },
    });
    const lower_decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer Qpack.freeDecodedFields(allocator, lower_decoded);
    try std.testing.expectEqualStrings(":status", lower_decoded[0].name);
    try std.testing.expectEqualStrings("200", lower_decoded[0].value);
    try std.testing.expectEqualStrings("x-proto", lower_decoded[1].name);
    try std.testing.expectEqualStrings("QUIC", lower_decoded[1].value);
}

test "HTTP/3 QPACK dynamic table applies RFC 9204 Appendix B encoder stream" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 220);
    defer table.deinit();

    const appendix_b2 = [_]u8{
        0x3f, 0xbd, 0x01, // Set Dynamic Table Capacity = 220.
        0xc0, 0x0f, // Insert static name index 0, value length 15.
        'w',  'w',
        'w',  '.',
        'e',  'x',
        'a',  'm',
        'p',  'l',
        'e',  '.',
        'c',  'o',
        'm',
        0xc1, 0x0c, // Insert static name index 1, value length 12.
        '/',  's',
        'a',  'm',
        'p',  'l',
        'e',  '/',
        'p',  'a',
        't',  'h',
    };
    try std.testing.expectEqual(
        appendix_b2.len,
        try Qpack.applyEncoderInstructions(&table, allocator, &appendix_b2),
    );
    try std.testing.expectEqual(@as(usize, 220), table.capacity);
    try std.testing.expectEqual(@as(usize, 106), table.current_size);
    try std.testing.expectEqual(@as(u64, 2), table.insert_count);
    try std.testing.expectEqual(@as(usize, 2), table.entryCount());
    try std.testing.expectEqualStrings(":authority", table.absolute(0).?.name);
    try std.testing.expectEqualStrings("www.example.com", table.absolute(0).?.value);
    try std.testing.expectEqualStrings(":path", table.relative(0).?.name);
    try std.testing.expectEqualStrings("/sample/path", table.relative(0).?.value);

    const appendix_b3 = [_]u8{
        0x4a, // Insert literal name, length 10.
        'c',
        'u',
        's',
        't',
        'o',
        'm',
        '-',
        'k',
        'e',
        'y',
        0x0c, // Value length 12.
        'c',
        'u',
        's',
        't',
        'o',
        'm',
        '-',
        'v',
        'a',
        'l',
        'u',
        'e',
    };
    try std.testing.expectEqual(
        appendix_b3.len,
        try Qpack.applyEncoderInstructions(&table, allocator, &appendix_b3),
    );
    try std.testing.expectEqual(@as(u64, 3), table.insert_count);
    try std.testing.expectEqual(@as(usize, 160), table.current_size);
    try std.testing.expectEqualStrings("custom-key", table.relative(0).?.name);
    try std.testing.expectEqualStrings("custom-value", table.relative(0).?.value);

    // Duplicate index zero must stabilize the source before insertion because
    // the insertion can evict an older entry.
    try std.testing.expectEqual(
        @as(usize, 1),
        try Qpack.applyEncoderInstructions(&table, allocator, &.{0x00}),
    );
    try std.testing.expectEqual(@as(u64, 4), table.insert_count);
    try std.testing.expectEqual(@as(usize, 214), table.current_size);
    try std.testing.expectEqualStrings("custom-key", table.absolute(3).?.name);
}

test "HTTP/3 QPACK dynamic match prefers exact then newest name before limit" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);

    _ = try table.insert("x-match", "old-exact");
    _ = try table.insert("x-match", "name-only");
    _ = try table.insert("x-other", "unrelated");
    _ = try table.insert("x-match", "new-exact");

    const exact = table.findMatchBefore(
        "x-match",
        "new-exact",
        table.insert_count,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(exact.full_match);
    try std.testing.expectEqual(@as(u64, 3), exact.absolute_index);
    try std.testing.expectEqual(
        @as(?u64, 3),
        table.findExact("x-match", "new-exact"),
    );

    const name_only = table.findMatchBefore(
        "x-match",
        "missing",
        table.insert_count,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(!name_only.full_match);
    try std.testing.expectEqual(@as(u64, 3), name_only.absolute_index);
    try std.testing.expect(
        table.findExact("x-match", "missing") == null,
    );

    // Excluding absolute index 3 must reveal the newest eligible name match,
    // while an older exact value still outranks that newer name-only entry.
    const limited_name = table.findMatchBefore(
        "x-match",
        "missing",
        3,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(!limited_name.full_match);
    try std.testing.expectEqual(@as(u64, 1), limited_name.absolute_index);
    const limited_exact = table.findMatchBefore(
        "x-match",
        "old-exact",
        3,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(limited_exact.full_match);
    try std.testing.expectEqual(@as(u64, 0), limited_exact.absolute_index);
}

fn checkLargeDynamicQpackEncodeAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var table = Qpack.DynamicTable.init(allocator, 4096);
    defer table.deinit();
    try table.setCapacity(4096);
    _ = try table.insert("x-large-block", "repeated");
    var fields: [65]Qpack.HeaderField = undefined;
    for (&fields) |*field| {
        field.* = .{ .name = "x-large-block", .value = "repeated" };
    }
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var references: std.ArrayList(u64) = .empty;
    defer references.deinit(allocator);
    try Qpack.encodeDynamicBlockKnownReceived(
        &encoded,
        allocator,
        &fields,
        table,
        table.insert_count,
        &references,
    );
    try std.testing.expectEqual(@as(usize, 1), references.items.len);
}

test "HTTP/3 QPACK large encode scratch is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkLargeDynamicQpackEncodeAllocationFailure,
        .{},
    );
}

test "HTTP/3 QPACK dynamic table evicts by capacity and rejects invalid instructions" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 96);
    defer table.deinit();
    try table.setCapacity(96);

    try std.testing.expectEqual(@as(u64, 0), try table.insert("a", "1"));
    try std.testing.expectEqual(@as(u64, 1), try table.insert("b", "2"));
    try std.testing.expectEqual(@as(u64, 2), try table.insert("c", "3"));
    try std.testing.expectEqual(@as(usize, 2), table.entryCount());
    try std.testing.expect(table.absolute(0) == null);
    try std.testing.expectEqualStrings("b", table.absolute(1).?.name);
    try std.testing.expectEqualStrings("c", table.relative(0).?.name);

    try table.setCapacity(34);
    try std.testing.expectEqual(@as(usize, 1), table.entryCount());
    try std.testing.expectEqualStrings("c", table.relative(0).?.name);
    try std.testing.expectError(error.QpackEncoderStreamError, table.setCapacity(97));

    // An entry larger than the current capacity is a connection error and
    // clears the decoder's table per RFC 9204 Section 3.2.2.
    try std.testing.expectError(error.QpackEncoderStreamError, table.insert("too", "large"));
    try std.testing.expectEqual(@as(usize, 0), table.entryCount());
    try std.testing.expectEqual(@as(usize, 0), table.current_size);
    try std.testing.expectEqual(@as(u64, 3), table.insert_count);

    try std.testing.expectError(
        error.QpackEncoderStreamError,
        Qpack.applyEncoderInstructions(&table, allocator, &.{0x80}),
    );
}

test "HTTP/3 QPACK encoder instructions round trip Huffman strings" {
    const allocator = std.testing.allocator;
    const instructions = [_]Qpack.EncoderInstruction{
        .{ .set_capacity = 4096 },
        .{ .insert_name_reference = .{
            .static = true,
            .name_index = 95,
            .value = "netz/1.0",
        } },
        .{ .insert_literal = .{
            .name = "x-long-custom-header-name",
            .value = "compressible compressible compressible",
        } },
        .{ .duplicate = 127 },
    };

    for (instructions) |instruction| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try Qpack.writeEncoderInstruction(&encoded, allocator, instruction);
        var decoded = try Qpack.decodeEncoderInstruction(allocator, encoded.items);
        defer decoded.deinit(allocator);
        try std.testing.expectEqual(encoded.items.len, decoded.consumed);

        switch (instruction) {
            .set_capacity => |expected| try std.testing.expectEqual(expected, decoded.instruction.set_capacity),
            .duplicate => |expected| try std.testing.expectEqual(expected, decoded.instruction.duplicate),
            .insert_name_reference => |expected| {
                const actual = decoded.instruction.insert_name_reference;
                try std.testing.expectEqual(expected.static, actual.static);
                try std.testing.expectEqual(expected.name_index, actual.name_index);
                try std.testing.expectEqualStrings(expected.value, actual.value);
            },
            .insert_literal => |expected| {
                const actual = decoded.instruction.insert_literal;
                try std.testing.expectEqualStrings(expected.name, actual.name);
                try std.testing.expectEqualStrings(expected.value, actual.value);
            },
        }
    }
}

test "HTTP/3 QPACK Required Insert Count wraps per RFC 9204" {
    try std.testing.expectEqual(@as(u64, 0), try Qpack.encodeRequiredInsertCount(0, 3));
    try std.testing.expectEqual(@as(u64, 3), try Qpack.encodeRequiredInsertCount(2, 6));
    try std.testing.expectEqual(@as(u64, 9), try Qpack.decodeRequiredInsertCount(4, 3, 10));
    try std.testing.expectEqual(@as(u64, 2), try Qpack.decodeRequiredInsertCount(3, 6, 2));
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        Qpack.encodeRequiredInsertCount(1, 0),
    );
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        Qpack.decodeRequiredInsertCount(7, 3, 10),
    );
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        Qpack.decodeRequiredInsertCount(1, 0, 0),
    );
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        Qpack.decodeRequiredInsertCount(
            1,
            std.math.maxInt(u64),
            std.math.maxInt(u64),
        ),
    );
}

test "HTTP/3 QPACK field section prefix detects blocking without allocation" {
    const allocator = std.testing.allocator;
    var encoder_table = Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-prefix", "blocked");

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = "x-prefix", .value = "blocked" },
    }, encoder_table);

    var decoder_table = Qpack.DynamicTable.init(allocator, 256);
    defer decoder_table.deinit();
    try decoder_table.setCapacity(256);
    // The prefix parser intentionally accepts no allocator, keeping this
    // receive-scheduling probe independent of heap availability.
    const prefix = try Qpack.decodeFieldSectionPrefix(
        block.items,
        decoder_table,
    );
    try std.testing.expectEqual(@as(u64, 1), prefix.required_insert_count);
    try std.testing.expect(prefix.required_insert_count > decoder_table.insert_count);
    try std.testing.expectEqual(@as(u64, 1), prefix.base);
    try std.testing.expect(prefix.consumed >= 2);
}

test "HTTP/3 QPACK dynamic block decodes RFC 9204 Appendix B post-base fields" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 220);
    defer table.deinit();
    try std.testing.expectEqual(
        @as(usize, 34),
        try Qpack.applyEncoderInstructions(&table, allocator, &.{
            0x3f, 0xbd, 0x01,
            0xc0, 0x0f, 'w',
            'w',  'w',  '.',
            'e',  'x',  'a',
            'm',  'p',  'l',
            'e',  '.',  'c',
            'o',  'm',  0xc1,
            0x0c, '/',  's',
            'a',  'm',  'p',
            'l',  'e',  '/',
            'p',  'a',  't',
            'h',
        }),
    );

    // RFC 9204 Appendix B.2, stream 4:
    // Encoded RIC=3 => Required Insert Count=2, S=1/DeltaBase=1 => Base=0.
    const appendix_b_field_section = [_]u8{ 0x03, 0x81, 0x10, 0x11 };
    var decoded = try Qpack.decodeDynamicBlock(allocator, &appendix_b_field_section, table);
    defer Qpack.freeDynamicBlock(allocator, &decoded);
    try std.testing.expectEqual(@as(u64, 2), decoded.required_insert_count);
    try std.testing.expectEqual(@as(u64, 0), decoded.base);
    try std.testing.expectEqual(@as(usize, 2), decoded.fields.len);
    try std.testing.expectEqualStrings(":authority", decoded.fields[0].name);
    try std.testing.expectEqualStrings("www.example.com", decoded.fields[0].value);
    try std.testing.expectEqualStrings(":path", decoded.fields[1].name);
    try std.testing.expectEqualStrings("/sample/path", decoded.fields[1].value);
}

test "HTTP/3 QPACK dynamic block round trips and reduces wire size" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-service-version", "2026.08.09-release-candidate");
    _ = try table.insert("x-region", "cn-north-1");

    const fields = [_]Qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "x-service-version", .value = "2026.08.09-release-candidate" },
        .{ .name = "x-region", .value = "cn-north-2" },
        .{ .name = "authorization", .value = "secret", .never_indexed = true },
    };
    var dynamic: std.ArrayList(u8) = .empty;
    defer dynamic.deinit(allocator);
    try Qpack.encodeDynamicBlock(&dynamic, allocator, &fields, table);

    var literal: std.ArrayList(u8) = .empty;
    defer literal.deinit(allocator);
    try Qpack.encodeLiteralBlock(&literal, allocator, &fields);
    try std.testing.expect(dynamic.items.len < literal.items.len);

    var decoded = try Qpack.decodeDynamicBlock(allocator, dynamic.items, table);
    defer Qpack.freeDynamicBlock(allocator, &decoded);
    try std.testing.expectEqual(fields.len, decoded.fields.len);
    for (fields, decoded.fields) |expected, actual| {
        try std.testing.expectEqualStrings(expected.name, actual.name);
        try std.testing.expectEqualStrings(expected.value, actual.value);
        try std.testing.expectEqual(expected.never_indexed, actual.never_indexed);
    }
}

test "HTTP/3 QPACK dynamic block distinguishes blocked and evicted references" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 96);
    defer table.deinit();
    try table.setCapacity(96);
    _ = try table.insert("a", "1");

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try Qpack.encodeDynamicBlock(&encoded, allocator, &.{
        .{ .name = "a", .value = "1" },
    }, table);

    var behind = Qpack.DynamicTable.init(allocator, 96);
    defer behind.deinit();
    try behind.setCapacity(96);
    try std.testing.expectError(
        error.QpackBlocked,
        Qpack.decodeDynamicBlock(allocator, encoded.items, behind),
    );

    _ = try table.insert("b", "2");
    _ = try table.insert("c", "3"); // Evicts absolute index zero.
    try std.testing.expect(table.absolute(0) == null);
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        Qpack.decodeDynamicBlock(allocator, encoded.items, table),
    );
}

test "HTTP/3 QPACK decoder instructions round trip and reject zero increment" {
    const allocator = std.testing.allocator;
    const instructions = [_]Qpack.DecoderInstruction{
        .{ .section_acknowledgment = 1337 },
        .{ .stream_cancellation = 1024 },
        .{ .insert_count_increment = 65 },
    };
    for (instructions) |instruction| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try Qpack.writeDecoderInstruction(&encoded, allocator, instruction);
        const decoded = try Qpack.decodeDecoderInstruction(encoded.items);
        try std.testing.expectEqual(encoded.items.len, decoded.consumed);
        switch (instruction) {
            .section_acknowledgment => |expected| try std.testing.expectEqual(
                expected,
                decoded.instruction.section_acknowledgment,
            ),
            .stream_cancellation => |expected| try std.testing.expectEqual(
                expected,
                decoded.instruction.stream_cancellation,
            ),
            .insert_count_increment => |expected| try std.testing.expectEqual(
                expected,
                decoded.instruction.insert_count_increment,
            ),
        }
    }
    try std.testing.expectError(
        error.QpackDecoderStreamError,
        Qpack.decodeDecoderInstruction(&.{0x00}),
    );
    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try std.testing.expectError(
        error.QpackDecoderStreamError,
        Qpack.writeDecoderInstruction(&invalid, allocator, .{ .insert_count_increment = 0 }),
    );
}

fn checkQpackDynamicDecodeAllocationFailure(allocator: std.mem.Allocator) !void {
    var table = Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-name", "x-value");

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try Qpack.encodeDynamicBlock(&encoded, allocator, &.{
        .{ .name = "x-name", .value = "x-value" },
        .{ .name = "x-name", .value = "different" },
        .{ .name = "x-literal", .value = "materialized" },
    }, table);
    var decoded = try Qpack.decodeDynamicBlock(allocator, encoded.items, table);
    Qpack.freeDynamicBlock(allocator, &decoded);
}

test "HTTP/3 QPACK dynamic decode is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkQpackDynamicDecodeAllocationFailure,
        .{},
    );
}

test "HTTP/3 priority field and PRIORITY_UPDATE frame" {
    const allocator = std.testing.allocator;
    const parsed = Priority.parse("u=1, foo=bar, i=?1");
    try std.testing.expectEqual(@as(u3, 1), parsed.urgency);
    try std.testing.expect(parsed.incremental);
    var field_buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("u=1, i", parsed.serialize(&field_buf));
    try std.testing.expectEqual(@as(u3, 3), Priority.parse("u=9, i=?0").urgency);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePriorityUpdateFrame(&encoded, allocator, 8, parsed);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.priority_update_request, frame.frame_type);
    const payload = try parsePriorityUpdatePayload(frame.payload);
    try std.testing.expectEqual(@as(u64, 8), payload.prioritized_element_id);
    try std.testing.expectEqual(@as(u3, 1), payload.priority().urgency);
    try std.testing.expect(payload.priority().incremental);

    var control = ControlState{};
    defer control.deinit(allocator);
    var settings_payload: std.ArrayList(u8) = .empty;
    defer settings_payload.deinit(allocator);
    try writeControlStreamPrefix(&settings_payload, allocator);
    try writeSettingsFrame(&settings_payload, allocator, .{});
    try control.applyControlStreamBytes(allocator, settings_payload.items);
    try control.applyFrame(allocator, frame);
    try std.testing.expectEqual(@as(u64, 8), control.latest_priority_update.?.prioritized_element_id);
    try std.testing.expectEqual(
        @as(u3, 1),
        control.requestPriorityUpdate(8).?.priority().urgency,
    );

    var second_request: std.ArrayList(u8) = .empty;
    defer second_request.deinit(allocator);
    try writePriorityUpdateFrame(
        &second_request,
        allocator,
        12,
        .{ .urgency = 5 },
    );
    try control.applyFrame(
        allocator,
        try Frame.parse(second_request.items),
    );
    try std.testing.expectEqual(
        @as(u3, 1),
        control.requestPriorityUpdate(8).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        control.requestPriorityUpdate(12).?.priority().urgency,
    );

    var push_priority: std.ArrayList(u8) = .empty;
    defer push_priority.deinit(allocator);
    try writePushPriorityUpdateFrame(
        &push_priority,
        allocator,
        3,
        .{ .urgency = 2, .incremental = true },
    );
    try control.applyFrame(
        allocator,
        try Frame.parse(push_priority.items),
    );
    try std.testing.expectEqual(
        @as(u3, 2),
        control.pushPriorityUpdate(3).?.priority().urgency,
    );
    try std.testing.expect(
        control.pushPriorityUpdate(3).?.priority().incremental,
    );

    try std.testing.expectError(error.UnexpectedFrame, writePriorityUpdateFrame(&encoded, allocator, 1, parsed));
    var invalid_priority: std.ArrayList(u8) = .empty;
    defer invalid_priority.deinit(allocator);
    try writePriorityUpdateFrameRaw(&invalid_priority, allocator, FrameType.priority_update_request, 1, "u=1");
    const invalid_frame = try Frame.parse(invalid_priority.items);
    try std.testing.expectError(error.UnexpectedFrame, control.applyFrame(allocator, invalid_frame));
}

fn checkPriorityUpdateStateAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var control = ControlState{ .settings = .{ .received = true } };
    defer control.deinit(allocator);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 1 },
    );
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    encoded.clearRetainingCapacity();
    try writePriorityUpdateFrame(
        &encoded,
        allocator,
        4,
        .{ .urgency = 5, .incremental = true },
    );
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    encoded.clearRetainingCapacity();
    try writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 2 },
    );
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    try std.testing.expectEqual(
        @as(u3, 2),
        control.requestPriorityUpdate(0).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        control.requestPriorityUpdate(4).?.priority().urgency,
    );
}

test "HTTP/3 per-element priority state is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkPriorityUpdateStateAllocationFailure,
        .{},
    );
}

test "HTTP/3 control stream rejects request frames" {
    const allocator = std.testing.allocator;
    var control = ControlState{};
    defer control.deinit(allocator);
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(allocator);
    try writeControlStreamPrefix(&stream, allocator);
    try writeSettingsFrame(&stream, allocator, .{});
    try (Frame{ .frame_type = FrameType.data, .payload = "forbidden", .consumed = 0 }).write(&stream, allocator);
    try std.testing.expectError(error.UnexpectedFrame, control.applyControlStreamBytes(allocator, stream.items));

    var initialized = ControlState{ .settings = .{ .received = true } };
    try std.testing.expectError(error.UnexpectedFrame, initialized.applyFrame(allocator, .{
        .frame_type = FrameType.headers,
        .payload = &.{},
        .consumed = 0,
    }));
    try std.testing.expectError(error.UnexpectedFrame, initialized.applyFrame(allocator, .{
        .frame_type = FrameType.push_promise,
        .payload = &.{},
        .consumed = 0,
    }));
}

test "HTTP/3 typed settings state tracks negotiation" {
    const allocator = std.testing.allocator;
    const defaults = Settings{};
    try std.testing.expectEqual(std.math.maxInt(u64), defaults.max_field_section_size);
    var default_payload: std.ArrayList(u8) = .empty;
    defer default_payload.deinit(allocator);
    try defaults.writePayload(&default_payload, allocator);
    try std.testing.expectEqual(@as(usize, 0), default_payload.items.len);
    try (Settings{
        .qpack_max_table_capacity = 1,
    }).writePayload(&default_payload, allocator);
    default_payload.clearRetainingCapacity();
    try (Settings{
        .qpack_blocked_streams = 128,
    }).writePayload(&default_payload, allocator);
    try std.testing.expect(default_payload.items.len != 0);
    default_payload.clearRetainingCapacity();
    try std.testing.expectError(error.QpackDynamicTableUnsupported, (Settings{
        .qpack_blocked_streams = 129,
    }).writePayload(&default_payload, allocator));

    const local = Settings{
        .max_field_section_size = 32 * 1024,
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .webtransport_max_sessions = 16,
    };

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try local.writePayload(&payload, allocator);
    const raw = try parseSettings(allocator, payload.items);
    defer allocator.free(raw);
    const decoded = Settings.fromList(raw);

    try std.testing.expectEqual(@as(u64, 32 * 1024), decoded.max_field_section_size);
    try std.testing.expect(decoded.enable_connect_protocol);
    try std.testing.expect(decoded.h3_datagram);
    try std.testing.expectEqual(@as(u64, 16), decoded.webtransport_max_sessions);

    var state = SettingsState{};
    try std.testing.expect(!state.ready());
    state.markSent(local);
    try std.testing.expect(!state.ready());
    state.markReceived(decoded);
    try std.testing.expect(state.ready());
    try std.testing.expect(state.peer.h3_datagram);
}

test "HTTP/3 control stream enforces SETTINGS first and GOAWAY monotonicity" {
    const allocator = std.testing.allocator;

    var local_control = ControlState{};
    var stream_bytes: std.ArrayList(u8) = .empty;
    defer stream_bytes.deinit(allocator);
    try local_control.writeSettingsStream(&stream_bytes, allocator, .{
        .h3_datagram = true,
        .webtransport_max_sessions = 2,
    });
    try local_control.writeGoAway(&stream_bytes, allocator, 12);
    try std.testing.expectError(error.GoAwayIdIncreased, local_control.writeGoAway(&stream_bytes, allocator, 16));

    var peer_control = ControlState{};
    try peer_control.applyControlStreamBytes(allocator, stream_bytes.items);
    try std.testing.expectEqual(@as(?u64, 0), peer_control.peer_control_stream_id);
    try peer_control.registerControlStream(0);
    try std.testing.expectError(error.StreamCreationError, peer_control.registerControlStream(4));
    try std.testing.expect(peer_control.settings.received);
    try std.testing.expect(peer_control.settings.peer.h3_datagram);
    try std.testing.expectEqual(@as(u64, 2), peer_control.settings.peer.webtransport_max_sessions);
    try std.testing.expectEqual(@as(?u64, 12), peer_control.peer_goaway_id);
    try std.testing.expect(peer_control.acceptsRequestStream(8));
    try std.testing.expect(!peer_control.acceptsRequestStream(12));

    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try writeControlStreamPrefix(&invalid, allocator);
    var goaway_payload: std.ArrayList(u8) = .empty;
    defer goaway_payload.deinit(allocator);
    try quic.varint.encode(&goaway_payload, allocator, 0);
    try (Frame{ .frame_type = FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&invalid, allocator);
    var missing_settings = ControlState{};
    try std.testing.expectError(error.MissingSettings, missing_settings.applyControlStreamBytes(allocator, invalid.items));

    var bad_settings: std.ArrayList(u8) = .empty;
    defer bad_settings.deinit(allocator);
    try quic.varint.encode(&bad_settings, allocator, 0x04);
    try quic.varint.encode(&bad_settings, allocator, 1);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, bad_settings.items));

    bad_settings.clearRetainingCapacity();
    try quic.varint.encode(&bad_settings, allocator, @intFromEnum(SettingId.h3_datagram));
    try quic.varint.encode(&bad_settings, allocator, 2);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, bad_settings.items));

    try std.testing.expectError(error.InvalidSetting, writeSettings(&bad_settings, allocator, &[_]Setting{
        .{ .id = @intFromEnum(SettingId.h3_datagram), .value = 1 },
        .{ .id = @intFromEnum(SettingId.h3_datagram), .value = 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, writeSettings(&bad_settings, allocator, &[_]Setting{.{ .id = 0x04, .value = 0 }}));

    var excessive_settings: std.ArrayList(u8) = .empty;
    defer excessive_settings.deinit(allocator);
    try excessive_settings.appendNTimes(allocator, 0, max_settings_payload_size + 1);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, excessive_settings.items));

    var duplicate_settings = ControlState{};
    var duplicate: std.ArrayList(u8) = .empty;
    defer duplicate.deinit(allocator);
    try duplicate_settings.writeSettingsStream(&duplicate, allocator, .{});
    try writeSettingsFrame(&duplicate, allocator, .{});
    try std.testing.expectError(error.DuplicateSettings, duplicate_settings.applyControlStreamBytes(allocator, duplicate.items));
}

test "HTTP/3 push control frames and state" {
    const allocator = std.testing.allocator;

    var cancel: std.ArrayList(u8) = .empty;
    defer cancel.deinit(allocator);
    try writeCancelPushFrame(&cancel, allocator, 7);
    const cancel_frame = try Frame.parse(cancel.items);
    try std.testing.expectEqual(FrameType.cancel_push, cancel_frame.frame_type);
    try std.testing.expectEqual(@as(u64, 7), try parseCancelPushPayload(cancel_frame.payload));

    var max_push: std.ArrayList(u8) = .empty;
    defer max_push.deinit(allocator);
    var control = ControlState{};
    defer control.deinit(allocator);
    try control.writeMaxPushId(&max_push, allocator, 4);
    try std.testing.expectEqual(@as(?u64, 4), control.local_max_push_id);
    try control.writeMaxPushId(&max_push, allocator, 8);
    try std.testing.expectEqual(@as(?u64, 8), control.local_max_push_id);
    try std.testing.expectError(error.MaxPushIdReduced, control.writeMaxPushId(&max_push, allocator, 2));

    var peer_control = ControlState{ .settings = .{ .received = true } };
    defer peer_control.deinit(allocator);
    const first = try Frame.parse(max_push.items);
    try peer_control.applyFrame(allocator, first);
    try std.testing.expectEqual(@as(?u64, 4), peer_control.peer_max_push_id);
    const second = try Frame.parse(max_push.items[first.consumed..]);
    try peer_control.applyFrame(allocator, second);
    try std.testing.expectEqual(@as(?u64, 8), peer_control.peer_max_push_id);

    var reduced: std.ArrayList(u8) = .empty;
    defer reduced.deinit(allocator);
    try writeMaxPushIdFrame(&reduced, allocator, 1);
    const reduced_frame = try Frame.parse(reduced.items);
    try std.testing.expectError(error.MaxPushIdReduced, peer_control.applyFrame(allocator, reduced_frame));

    try peer_control.applyFrame(allocator, cancel_frame);
    try std.testing.expectEqual(
        @as(?u64, 7),
        peer_control.peer_cancelled_push_id,
    );
    var second_cancel: std.ArrayList(u8) = .empty;
    defer second_cancel.deinit(allocator);
    try writeCancelPushFrame(&second_cancel, allocator, 3);
    try peer_control.applyFrame(
        allocator,
        try Frame.parse(second_cancel.items),
    );
    // Duplicate cancellation is idempotent; distinct IDs remain queryable.
    try peer_control.applyFrame(allocator, cancel_frame);
    try std.testing.expect(peer_control.pushCancelled(7));
    try std.testing.expect(peer_control.pushCancelled(3));
    try std.testing.expectEqual(
        @as(usize, 2),
        peer_control.peer_cancelled_push_ids.items.len,
    );
}

test "HTTP/3 PUSH_PROMISE frame payload and limit validation" {
    const allocator = std.testing.allocator;
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try Qpack.encodeLiteralBlock(&field_section, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/pushed.css" },
        .{ .name = ":authority", .value = "example.test" },
    });

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePushPromiseFrame(&encoded, allocator, 3, field_section.items);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.push_promise, frame.frame_type);
    const promise = try parsePushPromisePayload(frame.payload);
    try std.testing.expectEqual(@as(u64, 3), promise.push_id);
    const decoded = try Qpack.decodeLiteralBlock(allocator, promise.field_section);
    defer Qpack.freeDecodedFields(allocator, decoded);
    try std.testing.expectEqualStrings("/pushed.css", decoded[2].value);

    try validatePushPromise(.{ .local_max_push_id = 3 }, promise.push_id);
    try std.testing.expectError(error.PushIdExceeded, validatePushPromise(.{}, promise.push_id));
    try std.testing.expectError(error.PushIdExceeded, validatePushPromise(.{ .local_max_push_id = 2 }, promise.push_id));

    var dynamic_table = Qpack.DynamicTable.init(allocator, 0);
    defer dynamic_table.deinit();
    var decoded_promise = try decodePushPromiseWithDynamicTable(
        allocator,
        frame.payload,
        .{},
        dynamic_table,
    );
    defer decoded_promise.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), decoded_promise.push_id);
    try std.testing.expectEqualStrings(
        "/pushed.css",
        decoded_promise.request.path,
    );

    var response_with_push: std.ArrayList(u8) = .empty;
    defer response_with_push.deinit(allocator);
    try writePushPromiseFrame(&response_with_push, allocator, 3, field_section.items);
    var response_headers: std.ArrayList(u8) = .empty;
    defer response_headers.deinit(allocator);
    try Qpack.encodeLiteralBlock(&response_headers, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = response_headers.items, .consumed = 0 }).write(&response_with_push, allocator);
    try validateResponsePushPromises(.{ .local_max_push_id = 3 }, response_with_push.items);
    try std.testing.expectError(error.PushIdExceeded, validateResponsePushPromises(.{}, response_with_push.items));
    try std.testing.expectError(error.PushIdExceeded, validateResponsePushPromises(.{ .local_max_push_id = 2 }, response_with_push.items));
}

test "HTTP/3 enforces SETTINGS_MAX_FIELD_SECTION_SIZE" {
    const allocator = std.testing.allocator;

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (Request{
        .method = "GET",
        .path = "/limited",
        .authority = "example.com",
    }).write(&request_bytes, allocator);
    var decoded_request = try decodeRequest(allocator, request_bytes.items);
    decoded_request.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, decodeRequestWithSettings(allocator, request_bytes.items, .{
        .max_field_section_size = 1,
    }));
    var rejected_request_write: std.ArrayList(u8) = .empty;
    defer rejected_request_write.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, (Request{
        .method = "GET",
        .path = "/limited",
        .authority = "example.com",
    }).writeWithSettings(&rejected_request_write, allocator, .{
        .max_field_section_size = 1,
    }));

    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (Response{
        .status = 200,
        .trailers = &.{.{ .name = "grpc-status", .value = "0" }},
    }).write(&response_bytes, allocator);
    var decoded_response = try decodeResponseWithSettings(allocator, response_bytes.items, .{
        .max_field_section_size = 44,
    });
    decoded_response.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, decodeResponseWithSettings(allocator, response_bytes.items, .{
        .max_field_section_size = 43,
    }));

    var rejected_response_write: std.ArrayList(u8) = .empty;
    defer rejected_response_write.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, writeResponseSequenceWithSettings(&rejected_response_write, allocator, &.{.{
        .status = 103,
    }}, .{
        .status = 200,
    }, .{
        .max_field_section_size = 41,
    }));
}

fn checkPushCancellationStateAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var control = ControlState{ .settings = .{ .received = true } };
    defer control.deinit(allocator);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeCancelPushFrame(&encoded, allocator, 1);
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    encoded.clearRetainingCapacity();
    try writeCancelPushFrame(&encoded, allocator, 3);
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    try std.testing.expect(control.pushCancelled(1));
    try std.testing.expect(control.pushCancelled(3));
    try std.testing.expectEqual(
        @as(usize, 2),
        control.peer_cancelled_push_ids.items.len,
    );
}

test "HTTP/3 per-ID push cancellation is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkPushCancellationStateAllocationFailure,
        .{},
    );
}

test "HTTP/3 rejects malformed structured frame payloads" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidFrame, parseGoAwayPayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parseCancelPushPayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parseMaxPushIdPayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parsePushPromisePayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parsePriorityUpdatePayload(&.{}));

    const truncated_two_byte_varint = [_]u8{0x40};
    try std.testing.expectError(error.InvalidFrame, parseGoAwayPayload(&truncated_two_byte_varint));
    try std.testing.expectError(error.InvalidFrame, parsePushPromisePayload(&truncated_two_byte_varint));
    try std.testing.expectError(error.InvalidFrame, parsePriorityUpdatePayload(&truncated_two_byte_varint));

    var malformed_frame_write: std.ArrayList(u8) = .empty;
    defer malformed_frame_write.deinit(allocator);
    try std.testing.expectError(error.InvalidFrame, (Frame{ .frame_type = FrameType.goaway, .payload = &.{}, .consumed = 0 }).write(&malformed_frame_write, allocator));

    var malformed_response: std.ArrayList(u8) = .empty;
    defer malformed_response.deinit(allocator);
    try quic.varint.encode(&malformed_response, allocator, FrameType.push_promise);
    try quic.varint.encode(&malformed_response, allocator, 0);
    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_response, allocator);
    try std.testing.expectError(error.InvalidFrame, decodeResponse(allocator, malformed_response.items));

    var malformed_settings: std.ArrayList(u8) = .empty;
    defer malformed_settings.deinit(allocator);
    try quic.varint.encode(&malformed_settings, allocator, @intFromEnum(SettingId.h3_datagram));
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, malformed_settings.items));
}

test "HTTP/3 datagram" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Datagram{ .quarter_stream_id = 4, .payload = "capsule" }).write(&encoded, allocator);
    const parsed = try Datagram.parse(encoded.items);
    try std.testing.expectEqual(@as(u64, 4), parsed.quarter_stream_id);
    try std.testing.expectEqualStrings("capsule", parsed.payload);
}

test "HTTP/3 request encode decode" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try (Request{
        .method = "POST",
        .path = "/submit",
        .authority = "example.com",
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "hello",
    }).write(&encoded, allocator);

    var decoded = try decodeRequest(allocator, encoded.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("POST", decoded.method);
    try std.testing.expectEqualStrings("/submit", decoded.path);
    try std.testing.expectEqualStrings("example.com", decoded.authority.?);
    try std.testing.expectEqualStrings("hello", decoded.body);
    try std.testing.expectEqualStrings("5", findHeader(decoded.headers, "content-length") orelse return error.MissingHeader);

    encoded.clearRetainingCapacity();
    try (Request{
        .method = "POST",
        .path = "/empty",
        .authority = "example.com",
    }).write(&encoded, allocator);
    var empty_post = try decodeRequest(allocator, encoded.items);
    defer empty_post.deinit(allocator);
    try std.testing.expectEqualStrings("0", findHeader(empty_post.headers, "content-length") orelse return error.MissingHeader);

    encoded.clearRetainingCapacity();
    try (Request{
        .method = "GET",
        .path = "/no-length",
        .authority = "example.com",
    }).write(&encoded, allocator);
    var get = try decodeRequest(allocator, encoded.items);
    defer get.deinit(allocator);
    try std.testing.expect(findHeader(get.headers, "content-length") == null);
}

test "HTTP/3 dynamic QPACK request decode preserves message semantics and acknowledgment count" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-request-id", "request-20260809");
    _ = try table.insert("x-trailer", "complete");

    const headers = [_]Qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/dynamic" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "4" },
        .{ .name = "x-request-id", .value = "request-20260809" },
    };
    const trailers = [_]Qpack.HeaderField{
        .{ .name = "x-trailer", .value = "complete" },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &headers, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    try (Frame{
        .frame_type = FrameType.data,
        .payload = "body",
        .consumed = 0,
    }).write(&encoded, allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &trailers, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);

    var decoded = try decodeRequestWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("POST", decoded.method);
    try std.testing.expectEqualStrings("/dynamic", decoded.path);
    try std.testing.expectEqualStrings("https", decoded.scheme);
    try std.testing.expectEqualStrings("example.com", decoded.authority.?);
    try std.testing.expectEqualStrings("body", decoded.body);
    try std.testing.expectEqual(@as(usize, 1), decoded.trailers.len);
    try std.testing.expectEqualStrings("complete", decoded.trailers[0].value);
    try std.testing.expectEqual(@as(usize, 2), decoded.qpack_section_acknowledgments);
}

test "HTTP/3 dynamic QPACK response counts informational and final acknowledgments" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-release", "netz-2026");

    const informational = [_]Qpack.HeaderField{
        .{ .name = ":status", .value = "103" },
        .{ .name = "x-release", .value = "netz-2026" },
    };
    const final = [_]Qpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "2" },
        .{ .name = "x-release", .value = "netz-2026" },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &informational, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &final, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    try (Frame{
        .frame_type = FrameType.data,
        .payload = "ok",
        .consumed = 0,
    }).write(&encoded, allocator);

    var decoded = try decodeResponseWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), decoded.status);
    try std.testing.expectEqualStrings("ok", decoded.body);
    try std.testing.expectEqual(@as(usize, 2), decoded.qpack_section_acknowledgments);
}

test "HTTP/3 dynamic heads decode before DATA and own fields" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-owned", "dynamic-value");

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/stream-head" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "content-length", .value = "1000000" },
        .{ .name = "x-owned", .value = "dynamic-value" },
    }, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&request_bytes, allocator);
    const request_head_bytes = request_bytes.items.len;
    try quic.varint.encode(&request_bytes, allocator, FrameType.data);
    try quic.varint.encode(&request_bytes, allocator, 1_000_000);

    var request_head = try decodeRequestHeadWithDynamicTable(
        allocator,
        request_bytes.items,
        .{},
        table,
    );
    defer request_head.deinit(allocator);
    try std.testing.expectEqualStrings("POST", request_head.method);
    try std.testing.expectEqualStrings("/stream-head", request_head.path);
    try std.testing.expectEqual(
        @as(?usize, 1_000_000),
        request_head.content_length,
    );
    try std.testing.expectEqual(request_head_bytes, request_head.consumed);
    try std.testing.expectEqual(
        @as(usize, 1),
        request_head.qpack_section_acknowledgments,
    );
    @memset(block.items, 0);
    try std.testing.expectEqualStrings(
        "dynamic-value",
        ownedFieldValue(request_head.headers, "x-owned").?,
    );

    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "103" },
        .{ .name = "x-owned", .value = "dynamic-value" },
    }, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&response_bytes, allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "8" },
        .{ .name = "x-owned", .value = "dynamic-value" },
    }, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&response_bytes, allocator);
    const response_head_bytes = response_bytes.items.len;

    var response_head = try decodeResponseHeadWithDynamicTable(
        allocator,
        response_bytes.items,
        .{},
        table,
    );
    defer response_head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response_head.status);
    try std.testing.expectEqual(@as(?usize, 8), response_head.content_length);
    try std.testing.expectEqual(response_head_bytes, response_head.consumed);
    try std.testing.expectEqual(
        @as(usize, 2),
        response_head.qpack_section_acknowledgments,
    );
}

fn checkDynamicQpackHeadAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-owned", "dynamic-value");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/oom-head" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "x-owned", .value = "dynamic-value" },
    }, table);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    var head = try decodeRequestHeadWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    head.deinit(allocator);
}

test "HTTP/3 dynamic head decoding is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkDynamicQpackHeadAllocationFailure,
        .{},
    );
}

fn checkDynamicQpackMessageAllocationFailure(allocator: std.mem.Allocator) !void {
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-transaction", "owned-dynamic-value");

    const headers = [_]Qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/oom" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "4" },
        .{ .name = "x-transaction", .value = "owned-dynamic-value" },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &headers, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    try (Frame{
        .frame_type = FrameType.data,
        .payload = "body",
        .consumed = 0,
    }).write(&encoded, allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = "x-transaction", .value = "owned-dynamic-value" },
    }, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);

    var decoded = try decodeRequestWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    decoded.deinit(allocator);
}

test "HTTP/3 dynamic QPACK message decode is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkDynamicQpackMessageAllocationFailure,
        .{},
    );
}

test "HTTP/3 message aggregates DATA frames and trailing HEADERS" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/multi" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "11" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&encoded, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "hello ", .consumed = 0 }).write(&encoded, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "world", .consumed = 0 }).write(&encoded, allocator);

    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = "grpc-status", .value = "0" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&encoded, allocator);

    var decoded = try decodeRequest(allocator, encoded.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("POST", decoded.method);
    try std.testing.expectEqualStrings("hello world", decoded.body);
    try std.testing.expectEqual(@as(usize, 1), decoded.trailers.len);
    try std.testing.expectEqualStrings("grpc-status", decoded.trailers[0].name);
    try std.testing.expectEqual(@as(usize, encoded.items.len), decoded.consumed);
}

test "HTTP/3 message rejects bad frame order and content length" {
    const allocator = std.testing.allocator;

    var data_first: std.ArrayList(u8) = .empty;
    defer data_first.deinit(allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "oops", .consumed = 0 }).write(&data_first, allocator);
    try std.testing.expectError(error.ExpectedHeadersFrame, decodeRequest(allocator, data_first.items));

    var signed_length_request: std.ArrayList(u8) = .empty;
    defer signed_length_request.deinit(allocator);
    var signed_block: std.ArrayList(u8) = .empty;
    defer signed_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&signed_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/signed-length" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "+4" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = signed_block.items, .consumed = 0 }).write(&signed_length_request, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "1234", .consumed = 0 }).write(&signed_length_request, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeRequest(allocator, signed_length_request.items));

    var connect_with_length = std.ArrayList(u8).empty;
    defer connect_with_length.deinit(allocator);
    signed_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&signed_block, allocator, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "proxy.example.com:443" },
        .{ .name = "content-length", .value = "0" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = signed_block.items, .consumed = 0 }).write(&connect_with_length, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeRequest(allocator, connect_with_length.items));

    var invalid_length: std.ArrayList(u8) = .empty;
    defer invalid_length.deinit(allocator);
    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/bad-length" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "5" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&invalid_length, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "1234", .consumed = 0 }).write(&invalid_length, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeRequest(allocator, invalid_length.items));

    var low_status: std.ArrayList(u8) = .empty;
    defer low_status.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "099" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&low_status, allocator);
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, low_status.items));

    var malformed_status: std.ArrayList(u8) = .empty;
    defer malformed_status.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "0200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_status, allocator);
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, malformed_status.items));

    malformed_status.clearRetainingCapacity();
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "20x" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_status, allocator);
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, malformed_status.items));

    malformed_status.clearRetainingCapacity();
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "101" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_status, allocator);
    // HTTP/3 has no HTTP/1.1 Upgrade/Switching Protocols path.  Reject 101 at
    // the header-validation boundary instead of silently treating it as a
    // skippable informational response.
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, malformed_status.items));

    var informational_response: std.ArrayList(u8) = .empty;
    defer informational_response.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "103" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&informational_response, allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&informational_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "final", .consumed = 0 }).write(&informational_response, allocator);
    var informational_decoded = try decodeResponse(allocator, informational_response.items);
    defer informational_decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), informational_decoded.status);
    try std.testing.expectEqualStrings("final", informational_decoded.body);

    var extension_prefaced_response: std.ArrayList(u8) = .empty;
    defer extension_prefaced_response.deinit(allocator);
    try (Frame{ .frame_type = 0x21, .payload = "extension", .consumed = 0 }).write(&extension_prefaced_response, allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&extension_prefaced_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "response-ext", .consumed = 0 }).write(&extension_prefaced_response, allocator);
    var extension_decoded = try decodeResponse(allocator, extension_prefaced_response.items);
    defer extension_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("response-ext", extension_decoded.body);

    var pushed_response: std.ArrayList(u8) = .empty;
    defer pushed_response.deinit(allocator);
    try writePushPromiseFrame(&pushed_response, allocator, 0, "promised-headers");
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&pushed_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "pushed-ok", .consumed = 0 }).write(&pushed_response, allocator);
    var pushed_decoded = try decodeResponse(allocator, pushed_response.items);
    defer pushed_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("pushed-ok", pushed_decoded.body);

    var client_push_promise: std.ArrayList(u8) = .empty;
    defer client_push_promise.deinit(allocator);
    try writePushPromiseFrame(&client_push_promise, allocator, 0, "illegal-client-push");
    try std.testing.expectError(error.ExpectedHeadersFrame, decodeRequest(allocator, client_push_promise.items));

    var informational_only = std.ArrayList(u8).empty;
    defer informational_only.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "103" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&informational_only, allocator);
    try std.testing.expectError(error.MissingStatus, decodeResponse(allocator, informational_only.items));

    var written_sequence: std.ArrayList(u8) = .empty;
    defer written_sequence.deinit(allocator);
    try writeResponseSequence(&written_sequence, allocator, &.{.{
        .status = 103,
        .headers = &.{.{ .name = "link", .value = "</style.css>; rel=preload" }},
    }}, .{ .status = 200, .body = "sequence-final" });
    var sequence_decoded = try decodeResponse(allocator, written_sequence.items);
    defer sequence_decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), sequence_decoded.status);
    try std.testing.expectEqualStrings("sequence-final", sequence_decoded.body);
    try std.testing.expectError(error.InvalidStatus, (InformationalResponse{ .status = 200 }).write(&written_sequence, allocator));
    try std.testing.expectError(error.InvalidContentLength, (InformationalResponse{
        .status = 103,
        .headers = &.{.{ .name = "content-length", .value = "1" }},
    }).write(&written_sequence, allocator));

    var signed_length_response: std.ArrayList(u8) = .empty;
    defer signed_length_response.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "+4" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&signed_length_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "1234", .consumed = 0 }).write(&signed_length_response, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeResponse(allocator, signed_length_response.items));

    var no_content_body: std.ArrayList(u8) = .empty;
    defer no_content_body.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "204" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&no_content_body, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "body", .consumed = 0 }).write(&no_content_body, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeResponse(allocator, no_content_body.items));

    var not_modified_length: std.ArrayList(u8) = .empty;
    defer not_modified_length.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":status", .value = "304" },
        .{ .name = "content-length", .value = "123" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&not_modified_length, allocator);
    var not_modified = try decodeResponse(allocator, not_modified_length.items);
    defer not_modified.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 304), not_modified.status);

    var bad_order: std.ArrayList(u8) = .empty;
    defer bad_order.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":status", .value = "200" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&bad_order, allocator);
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&bad_order, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "late", .consumed = 0 }).write(&bad_order, allocator);
    try std.testing.expectError(error.UnexpectedFrame, decodeResponse(allocator, bad_order.items));

    var forbidden: std.ArrayList(u8) = .empty;
    defer forbidden.deinit(allocator);
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&forbidden, allocator);
    try (Frame{ .frame_type = FrameType.settings, .payload = &.{}, .consumed = 0 }).write(&forbidden, allocator);
    try std.testing.expectError(error.UnexpectedFrame, decodeResponse(allocator, forbidden.items));
}

test "HTTP/3 validates pseudo headers and connection-specific fields" {
    const allocator = std.testing.allocator;

    const Helper = struct {
        fn writeRequestBlock(list: *std.ArrayList(u8), gpa: std.mem.Allocator, fields: []const Qpack.HeaderField) !void {
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(gpa);
            try Qpack.encodeLiteralBlock(&block, gpa, fields);
            try (Frame{ .frame_type = FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, gpa);
        }

        fn writeRequestWithTrailers(
            list: *std.ArrayList(u8),
            gpa: std.mem.Allocator,
            fields: []const Qpack.HeaderField,
            trailers: []const Qpack.HeaderField,
        ) !void {
            try writeRequestBlock(list, gpa, fields);
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(gpa);
            try Qpack.encodeLiteralBlock(&block, gpa, trailers);
            try (Frame{ .frame_type = FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, gpa);
        }
    };

    const valid_request = [_]Qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };

    var uppercase: std.ArrayList(u8) = .empty;
    defer uppercase.deinit(allocator);
    try Helper.writeRequestBlock(&uppercase, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "Content-Type", .value = "text/plain" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, uppercase.items));

    var duplicate_pseudo: std.ArrayList(u8) = .empty;
    defer duplicate_pseudo.deinit(allocator);
    try Helper.writeRequestBlock(&duplicate_pseudo, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, duplicate_pseudo.items));

    var connection_specific: std.ArrayList(u8) = .empty;
    defer connection_specific.deinit(allocator);
    try Helper.writeRequestBlock(&connection_specific, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "transfer-encoding", .value = "chunked" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, connection_specific.items));

    var bad_te: std.ArrayList(u8) = .empty;
    defer bad_te.deinit(allocator);
    try Helper.writeRequestBlock(&bad_te, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "te", .value = "gzip" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, bad_te.items));

    var good_te: std.ArrayList(u8) = .empty;
    defer good_te.deinit(allocator);
    try Helper.writeRequestBlock(&good_te, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "te", .value = "trailers" },
    });
    var decoded = try decodeRequest(allocator, good_te.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("GET", decoded.method);

    var missing_authority = std.ArrayList(u8).empty;
    defer missing_authority.deinit(allocator);
    try Helper.writeRequestBlock(&missing_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, missing_authority.items));

    var host_authority = std.ArrayList(u8).empty;
    defer host_authority.deinit(allocator);
    try Helper.writeRequestBlock(&host_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "host", .value = "example.com" },
    });
    var host_decoded = try decodeRequest(allocator, host_authority.items);
    defer host_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("GET", host_decoded.method);
    try std.testing.expectEqualStrings("example.com", host_decoded.authority.?);

    var mismatched_authority = std.ArrayList(u8).empty;
    defer mismatched_authority.deinit(allocator);
    try Helper.writeRequestBlock(&mismatched_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "origin.example" },
        .{ .name = "host", .value = "proxy.example" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, mismatched_authority.items));

    var invalid_path = std.ArrayList(u8).empty;
    defer invalid_path.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_path, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "relative" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_path.items));

    var query_only_path = std.ArrayList(u8).empty;
    defer query_only_path.deinit(allocator);
    try Helper.writeRequestBlock(&query_only_path, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "?only=query" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, query_only_path.items));

    var options_asterisk = std.ArrayList(u8).empty;
    defer options_asterisk.deinit(allocator);
    try Helper.writeRequestBlock(&options_asterisk, allocator, &.{
        .{ .name = ":method", .value = "OPTIONS" },
        .{ .name = ":path", .value = "*" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    var options_decoded = try decodeRequest(allocator, options_asterisk.items);
    defer options_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("OPTIONS", options_decoded.method);
    try std.testing.expectEqualStrings("*", options_decoded.path);

    var lowercase_options_asterisk = std.ArrayList(u8).empty;
    defer lowercase_options_asterisk.deinit(allocator);
    try Helper.writeRequestBlock(&lowercase_options_asterisk, allocator, &.{
        .{ .name = ":method", .value = "options" },
        .{ .name = ":path", .value = "*" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, lowercase_options_asterisk.items));

    var invalid_authority = std.ArrayList(u8).empty;
    defer invalid_authority.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "user@example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_authority.items));

    var invalid_method_token = std.ArrayList(u8).empty;
    defer invalid_method_token.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_method_token, allocator, &.{
        .{ .name = ":method", .value = "GET /" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_method_token.items));

    var empty_path = std.ArrayList(u8).empty;
    defer empty_path.deinit(allocator);
    try Helper.writeRequestBlock(&empty_path, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, empty_path.items));

    var plain_connect = std.ArrayList(u8).empty;
    defer plain_connect.deinit(allocator);
    try (Request{
        .method = "CONNECT",
        .path = "/must-be-omitted",
        .authority = "proxy.example.com:443",
    }).write(&plain_connect, allocator);
    var connect_decoded = try decodeRequest(allocator, plain_connect.items);
    defer connect_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("CONNECT", connect_decoded.method);
    try std.testing.expectEqualStrings("", connect_decoded.path);
    try std.testing.expectEqualStrings("", connect_decoded.scheme);

    try std.testing.expectError(error.InvalidContentLength, (Request{
        .method = "CONNECT",
        .path = "/must-be-omitted",
        .authority = "proxy.example.com:443",
        .headers = &.{.{ .name = "content-length", .value = "0" }},
    }).write(&plain_connect, allocator));

    try std.testing.expectError(error.InvalidContentLength, (Request{
        .method = "CONNECT",
        .path = "/must-be-omitted",
        .authority = "proxy.example.com:443",
        .body = "tunnel bytes",
    }).write(&plain_connect, allocator));

    var lowercase_connect = std.ArrayList(u8).empty;
    defer lowercase_connect.deinit(allocator);
    try (Request{
        .method = "connect",
        .path = "/ordinary-extension-method",
        .scheme = "https",
        .authority = "example.com",
        .headers = &.{.{ .name = "content-length", .value = "4" }},
        .body = "body",
    }).write(&lowercase_connect, allocator);
    var lowercase_decoded = try decodeRequest(allocator, lowercase_connect.items);
    defer lowercase_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("connect", lowercase_decoded.method);
    try std.testing.expectEqualStrings("body", lowercase_decoded.body);

    var extended_connect_missing_target = std.ArrayList(u8).empty;
    defer extended_connect_missing_target.deinit(allocator);
    try Helper.writeRequestBlock(&extended_connect_missing_target, allocator, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, extended_connect_missing_target.items));

    var extended_connect = std.ArrayList(u8).empty;
    defer extended_connect.deinit(allocator);
    try (Request{
        .method = "CONNECT",
        .path = "/wt",
        .scheme = "https",
        .authority = "example.com",
        .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
    }).write(&extended_connect, allocator);
    try std.testing.expectError(error.ExtendedConnectDisabled, decodeRequestWithSettings(allocator, extended_connect.items, .{}));
    var extended_decoded = try decodeRequestWithSettings(allocator, extended_connect.items, .{ .enable_connect_protocol = true });
    defer extended_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("CONNECT", extended_decoded.method);
    try std.testing.expectEqualStrings("webtransport", findHeader(extended_decoded.headers, ":protocol").?);

    var invalid_protocol_token = std.ArrayList(u8).empty;
    defer invalid_protocol_token.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_protocol_token, allocator, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "web transport" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_protocol_token.items));

    var bad_protocol_method = std.ArrayList(u8).empty;
    defer bad_protocol_method.deinit(allocator);
    try Helper.writeRequestBlock(&bad_protocol_method, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, bad_protocol_method.items));

    var bad_value = std.ArrayList(u8).empty;
    defer bad_value.deinit(allocator);
    try Helper.writeRequestBlock(&bad_value, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "x-bad", .value = "ok\r\ninjected: yes" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, bad_value.items));

    var pseudo_trailer: std.ArrayList(u8) = .empty;
    try std.testing.expectError(error.InvalidContentLength, (Request{
        .method = "POST",
        .path = "/upload",
        .authority = "example.com",
        .headers = &.{.{ .name = "content-length", .value = "5" }},
        .body = "body",
    }).write(&pseudo_trailer, allocator));

    try std.testing.expectError(error.InvalidHeader, (Request{
        .method = "POST",
        .path = "/upload",
        .authority = "example.com",
        .body = "body",
        .trailers = &.{.{ .name = "content-length", .value = "4" }},
    }).write(&pseudo_trailer, allocator));

    try std.testing.expectError(error.InvalidHeader, (Response{
        .status = 200,
        .body = "ok",
        .trailers = &.{.{ .name = "set-cookie", .value = "a=b" }},
    }).write(&pseudo_trailer, allocator));

    defer pseudo_trailer.deinit(allocator);
    try Helper.writeRequestWithTrailers(&pseudo_trailer, allocator, &valid_request, &.{
        .{ .name = ":status", .value = "200" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, pseudo_trailer.items));

    try std.testing.expectError(error.InvalidHeader, (Request{
        .method = "GET",
        .path = "/",
        .headers = &.{.{ .name = "Connection", .value = "close" }},
    }).write(&pseudo_trailer, allocator));
}

test "HTTP/3 response encode decode" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try (Response{
        .status = 201,
        .headers = &.{.{ .name = "server", .value = "netz" }},
        .body = "created",
    }).write(&encoded, allocator);
    var default_length = try decodeResponse(allocator, encoded.items);
    defer default_length.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 201), default_length.status);
    try std.testing.expectEqualStrings("created", default_length.body);
    try std.testing.expectEqualStrings("7", findHeader(default_length.headers, "content-length") orelse return error.MissingHeader);

    encoded.clearRetainingCapacity();
    const response = Response{
        .status = 201,
        .headers = &.{
            .{ .name = "server", .value = "netz" },
            .{ .name = "content-length", .value = "7" },
        },
        .body = "created",
        .trailers = &.{.{ .name = "checksum", .value = "ok" }},
    };
    try std.testing.expect(response.successful());
    try response.write(&encoded, allocator);

    var decoded = try decodeResponse(allocator, encoded.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 201), decoded.status);
    try std.testing.expect(decoded.successful());
    try std.testing.expectEqualStrings("created", decoded.body);
    try std.testing.expectEqual(@as(usize, 1), decoded.trailers.len);
    try std.testing.expectEqualStrings("checksum", decoded.trailers[0].name);
    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = "5" }},
        .body = "ok",
    }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 204,
        .body = "body",
    }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidStatus, (Response{
        .status = 103,
    }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidStatus, (Response{
        .status = 103,
        .headers = &.{.{ .name = "content-length", .value = "0" }},
    }).write(&encoded, allocator));
    try (Response{
        .status = 304,
        .headers = &.{.{ .name = "content-length", .value = "123" }},
    }).write(&encoded, allocator);
}

test {
    _ = runtime;
}
