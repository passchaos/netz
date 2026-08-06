const std = @import("std");
const wire = @import("../internal/wire.zig");
const quic = @import("../quic/mod.zig");

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
    ExpectedHeadersFrame,
    UnexpectedFrame,
    MissingMethod,
    MissingPath,
    MissingStatus,
    InvalidStatus,
    InvalidHeader,
    InvalidPriorityUpdate,
    StreamCreationError,
    InvalidContentLength,
    IntegerOverflow,
    QpackDynamicTableUnsupported,
} || std.mem.Allocator.Error;

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
    frame_type: u64,
    payload: []const u8,
    consumed: usize,

    pub fn parse(bytes: []const u8) Error!Frame {
        var cursor = wire.Cursor.init(bytes);
        const frame_type = try quic.varint.decode(&cursor);
        try validateFrameType(frame_type);
        const len = try quic.varint.decode(&cursor);
        const payload_len = std.math.cast(usize, len) orelse return error.IntegerOverflow;
        const payload = try cursor.readSlice(payload_len);
        return .{ .frame_type = frame_type, .payload = payload, .consumed = cursor.pos };
    }

    pub fn write(self: Frame, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
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
    qpack_max_table_capacity: u64 = 0,
    max_field_section_size: u64 = 16 * 1024,
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
        if (self.qpack_max_table_capacity != 0) try writeSetting(list, allocator, .qpack_max_table_capacity, self.qpack_max_table_capacity);
        if (self.max_field_section_size != 16 * 1024) try writeSetting(list, allocator, .max_field_section_size, self.max_field_section_size);
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
    settings: SettingsState = .{},
    peer_goaway_id: ?u64 = null,
    local_goaway_id: ?u64 = null,
    peer_max_push_id: ?u64 = null,
    local_max_push_id: ?u64 = null,
    peer_control_stream_id: ?u64 = null,
    latest_priority_update: ?PriorityUpdatePayload = null,
    peer_qpack_encoder_stream_id: ?u64 = null,
    peer_qpack_decoder_stream_id: ?u64 = null,

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
            FrameType.cancel_push => _ = try parseSingleVarintPayload(frame.payload),
            FrameType.priority_update_request => {
                const priority_update = try parsePriorityUpdatePayload(frame.payload);
                try validateRequestStreamId(priority_update.prioritized_element_id);
                self.latest_priority_update = priority_update;
            },
            FrameType.priority_update_push => {
                self.latest_priority_update = try parsePriorityUpdatePayload(frame.payload);
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
};

pub const PushPromisePayload = struct {
    push_id: u64,
    field_section: []const u8,
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

pub fn parsePushPromisePayload(payload: []const u8) Error!PushPromisePayload {
    var cursor = wire.Cursor.init(payload);
    const push_id = try quic.varint.decode(&cursor);
    return .{ .push_id = push_id, .field_section = payload[cursor.pos..] };
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
    const id = try quic.varint.decode(&cursor);
    return .{ .prioritized_element_id = id, .field_value = payload[cursor.pos..] };
}

fn validateRequestStreamId(stream_id: u64) Error!void {
    if ((stream_id & 0x3) != 0) return error.UnexpectedFrame;
}

pub fn validatePushPromise(control: ControlState, push_id: u64) Error!void {
    const max_push_id = control.local_max_push_id orelse return error.PushIdExceeded;
    if (push_id > max_push_id) return error.PushIdExceeded;
}

fn writeSingleVarintFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, frame_type: u64, value: u64) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try quic.varint.encode(&payload, allocator, value);
    try (Frame{ .frame_type = frame_type, .payload = payload.items, .consumed = 0 }).write(list, allocator);
}

fn parseSingleVarintPayload(payload: []const u8) Error!u64 {
    var cursor = wire.Cursor.init(payload);
    const value = try quic.varint.decode(&cursor);
    if (!cursor.eof()) return error.InvalidFrame;
    return value;
}

pub fn parseSettings(allocator: std.mem.Allocator, payload: []const u8) Error![]Setting {
    var cursor = wire.Cursor.init(payload);
    var settings: std.ArrayList(Setting) = .empty;
    errdefer settings.deinit(allocator);
    while (!cursor.eof()) {
        const id = try quic.varint.decode(&cursor);
        const value = try quic.varint.decode(&cursor);
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

pub fn writeSettings(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: []const Setting) !void {
    for (settings) |setting| {
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
    };

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
            if (findStaticMatch(field.name, field.value)) |match| {
                if (match.full_match) {
                    try encodePrefixedInteger(list, allocator, 6, 0xc0, match.index);
                } else {
                    try encodePrefixedInteger(list, allocator, 4, 0x50, match.index);
                    try encodeString(list, allocator, field.value);
                }
            } else {
                try encodePrefixedInteger(list, allocator, 3, 0x20, field.name.len);
                try list.appendSlice(allocator, field.name);
                try encodeString(list, allocator, field.value);
            }
        }
    }

    pub fn decodeLiteralBlock(allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
        var cursor = wire.Cursor.init(block);
        const required_insert_count = try decodePrefixedInteger(&cursor, 8, try cursor.readByte());
        const base = try decodePrefixedInteger(&cursor, 7, try cursor.readByte());
        if (required_insert_count != 0 or base != 0) return error.QpackDynamicTableUnsupported;

        var fields: std.ArrayList(HeaderField) = .empty;
        errdefer fields.deinit(allocator);
        while (!cursor.eof()) {
            const first = try cursor.readByte();
            if ((first & 0xc0) == 0xc0) {
                const index = try decodePrefixedInteger(&cursor, 6, first);
                const entry = staticEntry(index) orelse return error.InvalidFrame;
                try fields.append(allocator, entry);
            } else if ((first & 0xc0) == 0x40) {
                const is_static = (first & 0x10) != 0;
                const index = try decodePrefixedInteger(&cursor, 4, first);
                const value = try decodeString(&cursor);
                if (!is_static) return error.QpackDynamicTableUnsupported;
                const entry = staticEntry(index) orelse return error.InvalidFrame;
                try fields.append(allocator, .{ .name = entry.name, .value = value });
            } else if ((first & 0xe0) == 0x20) {
                const name_len = try decodePrefixedInteger(&cursor, 3, first);
                if ((first & 0x08) != 0) return error.QpackDynamicTableUnsupported;
                const name = try cursor.readSlice(name_len);
                const value = try decodeString(&cursor);
                try fields.append(allocator, .{ .name = name, .value = value });
            } else {
                return error.QpackDynamicTableUnsupported;
            }
        }
        return fields.toOwnedSlice(allocator);
    }

    fn encodeString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
        try encodePrefixedInteger(list, allocator, 7, 0x00, value.len);
        try list.appendSlice(allocator, value);
    }

    fn decodeString(cursor: *wire.Cursor) ![]const u8 {
        const first = try cursor.readByte();
        if ((first & 0x80) != 0) return error.QpackDynamicTableUnsupported;
        const len = try decodePrefixedInteger(cursor, 7, first);
        return cursor.readSlice(len);
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
        var fields_buf: [64]Qpack.HeaderField = undefined;
        const fields = try self.headerFields(&fields_buf);
        try validateHeaderBlock(fields, .request);
        try validateHeaderBlock(self.trailers, .trailers);
        try writeHeadersAndData(list, allocator, fields, self.body, self.trailers);
    }
};

fn requestHasProtocolPseudo(headers: []const Qpack.HeaderField) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":protocol")) return true;
    }
    return false;
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
        const status = std.fmt.bufPrint(status_buf, "{d}", .{self.status}) catch return error.InvalidStatus;
        try appendHeaderField(out, &count, .{ .name = ":status", .value = status });
        for (self.headers) |header| try appendHeaderField(out, &count, header);
        return out[0..count];
    }

    pub fn write(self: Response, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var status_buf: [3]u8 = undefined;
        const fields = try self.headerFields(&fields_buf, &status_buf);
        try validateHeaderBlock(fields, .response);
        try validateHeaderBlock(self.trailers, .trailers);
        try writeHeadersAndData(list, allocator, fields, self.body, self.trailers);
    }
};

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

    /// Release arrays and body storage owned by `decodeRequest`. Header field
    /// names/values still borrow from the encoded stream bytes; callers must
    /// keep those bytes alive while reading `headers` or `trailers`.
    pub fn deinit(self: *DecodedRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
        allocator.free(self.trailers);
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

    pub fn successful(self: DecodedResponse) bool {
        return self.status >= 200 and self.status < 300;
    }

    /// Release arrays and body storage owned by `decodeResponse`. Header field
    /// names/values still borrow from the encoded stream bytes; callers must
    /// keep those bytes alive while reading `headers` or `trailers`.
    pub fn deinit(self: *DecodedResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
        allocator.free(self.trailers);
        if (self.body_storage) |body| allocator.free(body);
        self.* = undefined;
    }
};

pub fn decodeRequest(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedRequest {
    var message = try decodeMessage(allocator, bytes);
    errdefer message.deinit(allocator);

    try validateHeaderBlock(message.headers, .request);
    try validateHeaderBlock(message.trailers, .trailers);
    try validateContentLength(message.headers, message.body.len);

    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    for (message.headers) |header| {
        if (std.mem.eql(u8, header.name, ":method")) method = header.value else if (std.mem.eql(u8, header.name, ":path")) path = header.value else if (std.mem.eql(u8, header.name, ":scheme")) scheme = header.value else if (std.mem.eql(u8, header.name, ":authority")) authority = header.value;
    }
    const method_value = method orelse return error.MissingMethod;
    const plain_connect = std.mem.eql(u8, method_value, "CONNECT") and !requestHasProtocolPseudo(message.headers);

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
    };
}

pub fn decodeResponse(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedResponse {
    var message = try decodeMessage(allocator, bytes);
    errdefer message.deinit(allocator);

    try validateHeaderBlock(message.headers, .response);
    try validateHeaderBlock(message.trailers, .trailers);
    try validateContentLength(message.headers, message.body.len);

    var status: ?u16 = null;
    for (message.headers) |header| {
        if (std.mem.eql(u8, header.name, ":status")) {
            status = std.fmt.parseInt(u16, header.value, 10) catch return error.InvalidStatus;
            if (status.? < 100 or status.? > 999) return error.InvalidStatus;
        }
    }

    return .{
        .status = status orelse return error.MissingStatus,
        .headers = message.headers,
        .trailers = message.trailers,
        .body = message.body,
        .body_storage = message.body_storage,
        .consumed = message.consumed,
    };
}

const DecodedMessage = struct {
    headers: []Qpack.HeaderField,
    trailers: []Qpack.HeaderField = &.{},
    body: []const u8,
    body_storage: ?[]u8 = null,
    consumed: usize,

    fn deinit(self: *DecodedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
        allocator.free(self.trailers);
        if (self.body_storage) |body| allocator.free(body);
        self.* = undefined;
    }
};

fn writeHeadersAndData(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const Qpack.HeaderField,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
) Error!void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&block, allocator, fields);
    try (Frame{ .frame_type = FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, allocator);
    if (body.len > 0) {
        try (Frame{ .frame_type = FrameType.data, .payload = body, .consumed = 0 }).write(list, allocator);
    }
    if (trailers.len > 0) {
        block.clearRetainingCapacity();
        try Qpack.encodeLiteralBlock(&block, allocator, trailers);
        try (Frame{ .frame_type = FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, allocator);
    }
}

fn decodeMessage(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedMessage {
    const headers_frame = try Frame.parse(bytes);
    if (headers_frame.frame_type != FrameType.headers) return error.ExpectedHeadersFrame;
    const headers = try Qpack.decodeLiteralBlock(allocator, headers_frame.payload);
    errdefer allocator.free(headers);

    var consumed = headers_frame.consumed;
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    var trailers: []Qpack.HeaderField = &.{};
    errdefer allocator.free(trailers);
    var saw_trailers = false;
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
                trailers = try Qpack.decodeLiteralBlock(allocator, frame.payload);
                saw_trailers = true;
            },
            FrameType.cancel_push,
            FrameType.settings,
            FrameType.push_promise,
            FrameType.goaway,
            FrameType.max_push_id,
            FrameType.priority_update_request,
            FrameType.priority_update_push,
            => return error.UnexpectedFrame,
            else => {},
        }
    }

    const body_storage: ?[]u8 = if (body.items.len == 0) storage: {
        body.deinit(allocator);
        break :storage null;
    } else try body.toOwnedSlice(allocator);

    return .{
        .headers = headers,
        .trailers = trailers,
        .body = if (body_storage) |storage| storage else &.{},
        .body_storage = body_storage,
        .consumed = consumed,
    };
}

fn appendHeaderField(out: []Qpack.HeaderField, count: *usize, field: Qpack.HeaderField) Error!void {
    if (count.* >= out.len) return error.InvalidFrame;
    out[count.*] = field;
    count.* += 1;
}

fn contentLength(headers: []const Qpack.HeaderField) Error!?usize {
    var found: ?usize = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
        var parts = std.mem.splitScalar(u8, header.value, ',');
        while (parts.next()) |raw_part| {
            const part = std.mem.trim(u8, raw_part, " \t");
            if (part.len == 0) return error.InvalidContentLength;
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

fn validateContentLength(headers: []const Qpack.HeaderField, actual: usize) Error!void {
    if (try contentLength(headers)) |expected| {
        if (expected != actual) return error.InvalidContentLength;
    }
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
        if (!std.ascii.eqlIgnoreCase(method, "OPTIONS")) return error.InvalidHeader;
        return;
    }
    if (path[0] != '/' and path[0] != '?') return error.InvalidHeader;
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

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    const fields = [_]Qpack.HeaderField{ .{ .name = ":method", .value = "GET" }, .{ .name = ":path", .value = "/" } };
    try Qpack.encodeLiteralBlock(&block, allocator, &fields);
    try std.testing.expectEqual(@as(u8, 0xd1), block.items[2]); // static index 17, :method GET
    try std.testing.expectEqual(@as(u8, 0xc1), block.items[3]); // static index 1, :path /
    const decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
}

test "HTTP/3 rejects reserved HTTP/2 frame types" {
    const allocator = std.testing.allocator;
    const reserved_frame_types = [_]u64{ 0x02, 0x06, 0x08, 0x09 };
    for (reserved_frame_types) |frame_type| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try (Frame{ .frame_type = frame_type, .payload = "", .consumed = 0 }).write(&encoded, allocator);
        try std.testing.expectError(error.UnexpectedFrame, Frame.parse(encoded.items));
    }
}

test "HTTP/3 QPACK static name references and literal fallback" {
    const allocator = std.testing.allocator;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    const fields = [_]Qpack.HeaderField{
        .{ .name = "content-type", .value = "application/problem+json" },
        .{ .name = "x-custom", .value = "value" },
    };
    try Qpack.encodeLiteralBlock(&block, allocator, &fields);
    try std.testing.expectEqual(@as(u8, 0x5f), block.items[2]); // static name ref with extended index, content-type

    const decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("content-type", decoded[0].name);
    try std.testing.expectEqualStrings("application/problem+json", decoded[0].value);
    try std.testing.expectEqualStrings("x-custom", decoded[1].name);
    try std.testing.expectEqualStrings("value", decoded[1].value);
    try std.testing.expectEqualStrings(":status", Qpack.staticEntry(25).?.name);
    try std.testing.expectEqualStrings("200", Qpack.staticEntry(25).?.value);
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
    var settings_payload: std.ArrayList(u8) = .empty;
    defer settings_payload.deinit(allocator);
    try writeControlStreamPrefix(&settings_payload, allocator);
    try writeSettingsFrame(&settings_payload, allocator, .{});
    try control.applyControlStreamBytes(allocator, settings_payload.items);
    try control.applyFrame(allocator, frame);
    try std.testing.expectEqual(@as(u64, 8), control.latest_priority_update.?.prioritized_element_id);

    try std.testing.expectError(error.UnexpectedFrame, writePriorityUpdateFrame(&encoded, allocator, 1, parsed));
    var invalid_priority: std.ArrayList(u8) = .empty;
    defer invalid_priority.deinit(allocator);
    try writePriorityUpdateFrameRaw(&invalid_priority, allocator, FrameType.priority_update_request, 1, "u=1");
    const invalid_frame = try Frame.parse(invalid_priority.items);
    try std.testing.expectError(error.UnexpectedFrame, control.applyFrame(allocator, invalid_frame));
}

test "HTTP/3 control stream rejects request frames" {
    const allocator = std.testing.allocator;
    var control = ControlState{};
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
    try writeSettings(&bad_settings, allocator, &[_]Setting{.{ .id = 0x04, .value = 1 }});
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, bad_settings.items));

    bad_settings.clearRetainingCapacity();
    try writeSettings(&bad_settings, allocator, &[_]Setting{.{ .id = @intFromEnum(SettingId.h3_datagram), .value = 2 }});
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, bad_settings.items));

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
    try control.writeMaxPushId(&max_push, allocator, 4);
    try std.testing.expectEqual(@as(?u64, 4), control.local_max_push_id);
    try control.writeMaxPushId(&max_push, allocator, 8);
    try std.testing.expectEqual(@as(?u64, 8), control.local_max_push_id);
    try std.testing.expectError(error.MaxPushIdReduced, control.writeMaxPushId(&max_push, allocator, 2));

    var peer_control = ControlState{ .settings = .{ .received = true } };
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
}

test "HTTP/3 PUSH_PROMISE frame payload and limit validation" {
    const allocator = std.testing.allocator;
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try Qpack.encodeLiteralBlock(&field_section, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/pushed.css" },
    });

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePushPromiseFrame(&encoded, allocator, 3, field_section.items);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.push_promise, frame.frame_type);
    const promise = try parsePushPromisePayload(frame.payload);
    try std.testing.expectEqual(@as(u64, 3), promise.push_id);
    const decoded = try Qpack.decodeLiteralBlock(allocator, promise.field_section);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("/pushed.css", decoded[1].value);

    try validatePushPromise(.{ .local_max_push_id = 3 }, promise.push_id);
    try std.testing.expectError(error.PushIdExceeded, validatePushPromise(.{}, promise.push_id));
    try std.testing.expectError(error.PushIdExceeded, validatePushPromise(.{ .local_max_push_id = 2 }, promise.push_id));
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

    var extended_connect_missing_target = std.ArrayList(u8).empty;
    defer extended_connect_missing_target.deinit(allocator);
    try Helper.writeRequestBlock(&extended_connect_missing_target, allocator, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, extended_connect_missing_target.items));

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
}

test {
    _ = runtime;
}
