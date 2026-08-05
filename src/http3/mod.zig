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
    ExpectedHeadersFrame,
    MissingMethod,
    MissingPath,
    MissingStatus,
    InvalidStatus,
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

pub const SettingId = enum(u64) {
    qpack_max_table_capacity = 0x01,
    max_field_section_size = 0x06,
    qpack_blocked_streams = 0x07,
    enable_connect_protocol = 0x08,
    h3_datagram = 0x33,
    webtransport_max_sessions = 0x2b603742,
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
    webtransport_max_sessions: u64 = 0,

    pub fn fromList(settings: []const Setting) Settings {
        var out: Settings = .{};
        for (settings) |setting| {
            switch (setting.id) {
                @intFromEnum(SettingId.qpack_max_table_capacity) => out.qpack_max_table_capacity = setting.value,
                @intFromEnum(SettingId.max_field_section_size) => out.max_field_section_size = setting.value,
                @intFromEnum(SettingId.qpack_blocked_streams) => out.qpack_blocked_streams = setting.value,
                @intFromEnum(SettingId.enable_connect_protocol) => out.enable_connect_protocol = setting.value != 0,
                @intFromEnum(SettingId.h3_datagram) => out.h3_datagram = setting.value != 0,
                @intFromEnum(SettingId.webtransport_max_sessions) => out.webtransport_max_sessions = setting.value,
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
        if (self.webtransport_max_sessions != 0) try writeSetting(list, allocator, .webtransport_max_sessions, self.webtransport_max_sessions);
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

    pub fn applyControlStreamBytes(self: *ControlState, allocator: std.mem.Allocator, bytes: []const u8) Error!void {
        var cursor = wire.Cursor.init(bytes);
        const stream_type: StreamType = @enumFromInt(try quic.varint.decode(&cursor));
        if (stream_type != .control) return error.InvalidStreamType;

        while (!cursor.eof()) {
            const frame = try Frame.parse(bytes[cursor.pos..]);
            cursor.pos += frame.consumed;
            try self.applyFrame(allocator, frame);
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
            else => {}, // Unknown extension frames on the control stream are ignored.
        }
    }

    pub fn acceptsRequestStream(self: ControlState, stream_id: u64) bool {
        const goaway_id = self.peer_goaway_id orelse return true;
        return stream_id < goaway_id;
    }
};

pub fn writeControlStreamPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    try quic.varint.encode(list, allocator, @intFromEnum(StreamType.control));
}

pub fn writeSettingsFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: Settings) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try settings.writePayload(&payload, allocator);
    try (Frame{ .frame_type = FrameType.settings, .payload = payload.items, .consumed = 0 }).write(list, allocator);
}

pub fn parseGoAwayPayload(payload: []const u8) Error!u64 {
    var cursor = wire.Cursor.init(payload);
    const stream_id = try quic.varint.decode(&cursor);
    if (!cursor.eof()) return error.InvalidFrame;
    return stream_id;
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

    pub fn encodePrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator, required_insert_count: u64, base: u64) !void {
        try quic.varint.encode(list, allocator, required_insert_count);
        try quic.varint.encode(list, allocator, base);
    }

    /// Minimal QPACK encoder for deterministic tests and bootstrap clients. It
    /// emits literal field lines without Huffman coding or dynamic references,
    /// which keeps decoding stateless and avoids head-of-line blocking.
    pub fn encodeLiteralBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const HeaderField) !void {
        try encodePrefix(list, allocator, 0, 0);
        for (fields) |field| {
            try list.append(allocator, 0x20); // literal field line with literal name, no indexing
            try encodeString(list, allocator, field.name);
            try encodeString(list, allocator, field.value);
        }
    }

    pub fn decodeLiteralBlock(allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
        var cursor = wire.Cursor.init(block);
        const required_insert_count = try quic.varint.decode(&cursor);
        const base = try quic.varint.decode(&cursor);
        if (required_insert_count != 0 or base != 0) return error.QpackDynamicTableUnsupported;

        var fields: std.ArrayList(HeaderField) = .empty;
        errdefer fields.deinit(allocator);
        while (!cursor.eof()) {
            const first = try cursor.readByte();
            if ((first & 0xe0) != 0x20) return error.QpackDynamicTableUnsupported;
            const name = try decodeString(&cursor);
            const value = try decodeString(&cursor);
            try fields.append(allocator, .{ .name = name, .value = value });
        }
        return fields.toOwnedSlice(allocator);
    }

    fn encodeString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
        if (value.len > 0x7f) return error.InvalidFrame;
        try list.append(allocator, @intCast(value.len));
        try list.appendSlice(allocator, value);
    }

    fn decodeString(cursor: *wire.Cursor) ![]const u8 {
        const first = try cursor.readByte();
        if ((first & 0x80) != 0) return error.QpackDynamicTableUnsupported;
        return cursor.readSlice(first & 0x7f);
    }
};

pub const Request = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8 = "https",
    authority: ?[]const u8 = null,
    headers: []const Qpack.HeaderField = &.{},
    body: []const u8 = &.{},

    pub fn headerFields(self: Request, out: []Qpack.HeaderField) Error![]Qpack.HeaderField {
        var count: usize = 0;
        try appendHeaderField(out, &count, .{ .name = ":method", .value = self.method });
        try appendHeaderField(out, &count, .{ .name = ":path", .value = self.path });
        try appendHeaderField(out, &count, .{ .name = ":scheme", .value = self.scheme });
        if (self.authority) |authority| try appendHeaderField(out, &count, .{ .name = ":authority", .value = authority });
        for (self.headers) |header| try appendHeaderField(out, &count, header);
        return out[0..count];
    }

    pub fn write(self: Request, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        const fields = try self.headerFields(&fields_buf);
        try writeHeadersAndData(list, allocator, fields, self.body);
    }
};

pub const Response = struct {
    status: u16,
    headers: []const Qpack.HeaderField = &.{},
    body: []const u8 = &.{},

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
        try writeHeadersAndData(list, allocator, fields, self.body);
    }
};

pub const DecodedRequest = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    headers: []Qpack.HeaderField,
    body: []const u8,
    consumed: usize,

    pub fn deinit(self: *DecodedRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
        self.* = undefined;
    }
};

pub const DecodedResponse = struct {
    status: u16,
    headers: []Qpack.HeaderField,
    body: []const u8,
    consumed: usize,

    pub fn successful(self: DecodedResponse) bool {
        return self.status >= 200 and self.status < 300;
    }

    pub fn deinit(self: *DecodedResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
        self.* = undefined;
    }
};

pub fn decodeRequest(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedRequest {
    var message = try decodeMessage(allocator, bytes);
    errdefer message.deinit(allocator);

    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var scheme: []const u8 = "https";
    var authority: ?[]const u8 = null;
    for (message.headers) |header| {
        if (std.mem.eql(u8, header.name, ":method")) method = header.value else if (std.mem.eql(u8, header.name, ":path")) path = header.value else if (std.mem.eql(u8, header.name, ":scheme")) scheme = header.value else if (std.mem.eql(u8, header.name, ":authority")) authority = header.value;
    }

    return .{
        .method = method orelse return error.MissingMethod,
        .path = path orelse return error.MissingPath,
        .scheme = scheme,
        .authority = authority,
        .headers = message.headers,
        .body = message.body,
        .consumed = message.consumed,
    };
}

pub fn decodeResponse(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedResponse {
    var message = try decodeMessage(allocator, bytes);
    errdefer message.deinit(allocator);

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
        .body = message.body,
        .consumed = message.consumed,
    };
}

const DecodedMessage = struct {
    headers: []Qpack.HeaderField,
    body: []const u8,
    consumed: usize,

    fn deinit(self: *DecodedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
        self.* = undefined;
    }
};

fn writeHeadersAndData(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const Qpack.HeaderField,
    body: []const u8,
) Error!void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&block, allocator, fields);
    try (Frame{ .frame_type = FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, allocator);
    if (body.len > 0) {
        try (Frame{ .frame_type = FrameType.data, .payload = body, .consumed = 0 }).write(list, allocator);
    }
}

fn decodeMessage(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedMessage {
    const headers_frame = try Frame.parse(bytes);
    if (headers_frame.frame_type != FrameType.headers) return error.ExpectedHeadersFrame;
    const headers = try Qpack.decodeLiteralBlock(allocator, headers_frame.payload);
    errdefer allocator.free(headers);

    var consumed = headers_frame.consumed;
    var body: []const u8 = &.{};
    while (consumed < bytes.len) {
        const frame = try Frame.parse(bytes[consumed..]);
        consumed += frame.consumed;
        switch (frame.frame_type) {
            FrameType.data => body = frame.payload,
            FrameType.headers => break,
            else => {},
        }
    }

    return .{ .headers = headers, .body = body, .consumed = consumed };
}

fn appendHeaderField(out: []Qpack.HeaderField, count: *usize, field: Qpack.HeaderField) Error!void {
    if (count.* >= out.len) return error.InvalidFrame;
    out[count.*] = field;
    count.* += 1;
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
    const decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
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

test "HTTP/3 response encode decode" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    const response = Response{
        .status = 201,
        .headers = &.{.{ .name = "server", .value = "netz" }},
        .body = "created",
    };
    try std.testing.expect(response.successful());
    try response.write(&encoded, allocator);

    var decoded = try decodeResponse(allocator, encoded.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 201), decoded.status);
    try std.testing.expect(decoded.successful());
    try std.testing.expectEqualStrings("created", decoded.body);
}

test {
    _ = runtime;
}
