const std = @import("std");
const wire = @import("../internal/wire.zig");
const http1 = @import("../http1/mod.zig");

pub const runtime = @import("runtime.zig");
pub const handshake_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const Error = error{
    BufferTooShort,
    InvalidOpcode,
    InvalidFrame,
    InvalidControlFrame,
    InvalidUtf8,
    MissingHeader,
    InvalidHandshake,
    PayloadTooLarge,
    UnmaskedClientFrame,
    MaskedServerFrame,
    UnexpectedRsv,
    NonMinimalLength,
    InvalidCloseCode,
} || std.mem.Allocator.Error;

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
    _,

    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }
};

pub const CloseCode = enum(u16) {
    normal_closure = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    no_status_received = 1005,
    abnormal_closure = 1006,
    invalid_payload_data = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_server_error = 1011,
    service_restart = 1012,
    try_again_later = 1013,
    bad_gateway = 1014,
    tls_handshake = 1015,
    _,
};

pub const FrameHeader = struct {
    fin: bool,
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: Opcode,
    masked: bool,
    payload_len: u64,
    mask_key: ?[4]u8,
    header_len: usize,

    pub fn parse(bytes: []const u8) Error!FrameHeader {
        if (bytes.len < 2) return error.BufferTooShort;
        const b0 = bytes[0];
        const b1 = bytes[1];
        const opcode_value: u4 = @truncate(b0 & 0x0f);
        if ((opcode_value >= 0x3 and opcode_value <= 0x7) or opcode_value >= 0xb) return error.InvalidOpcode;
        var pos: usize = 2;
        var len: u64 = b1 & 0x7f;
        if (len == 126) {
            if (bytes.len < pos + 2) return error.BufferTooShort;
            len = std.mem.readInt(u16, bytes[pos..][0..2], .big);
            pos += 2;
        } else if (len == 127) {
            if (bytes.len < pos + 8) return error.BufferTooShort;
            len = std.mem.readInt(u64, bytes[pos..][0..8], .big);
            if ((len & (1 << 63)) != 0) return error.InvalidFrame;
            pos += 8;
        }
        var mask_key: ?[4]u8 = null;
        const masked = (b1 & 0x80) != 0;
        if (masked) {
            if (bytes.len < pos + 4) return error.BufferTooShort;
            mask_key = bytes[pos..][0..4].*;
            pos += 4;
        }
        const opcode: Opcode = @enumFromInt(opcode_value);
        if (opcode.isControl() and (!(b0 & 0x80 != 0) or len > 125)) return error.InvalidControlFrame;
        return .{
            .fin = (b0 & 0x80) != 0,
            .rsv1 = (b0 & 0x40) != 0,
            .rsv2 = (b0 & 0x20) != 0,
            .rsv3 = (b0 & 0x10) != 0,
            .opcode = opcode,
            .masked = masked,
            .payload_len = len,
            .mask_key = mask_key,
            .header_len = pos,
        };
    }
};

pub const ParseFrameOptions = struct {
    /// RFC 6455 requires client-to-server frames to be masked and server-to-client
    /// frames to be unmasked.  The default keeps parseFrame's original tolerant
    /// codec behavior for fixtures and intermediaries that inspect either side.
    expect_mask: enum { any, masked, unmasked } = .any,
    /// RSV bits are only legal when an extension negotiated their meaning.
    allow_rsv1: bool = false,
    allow_rsv2: bool = false,
    allow_rsv3: bool = false,
    validate_utf8: bool = true,
};

pub const Frame = struct {
    header: FrameHeader,
    payload: []u8,
    consumed: usize,

    pub fn deinit(self: *Frame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub fn parseFrame(allocator: std.mem.Allocator, bytes: []const u8) Error!Frame {
    return parseFrameOptions(allocator, bytes, .{});
}

pub fn parseFrameOptions(allocator: std.mem.Allocator, bytes: []const u8, options: ParseFrameOptions) Error!Frame {
    const header = try FrameHeader.parse(bytes);
    try validateFrameHeader(header, options);
    const payload_len = std.math.cast(usize, header.payload_len) orelse return error.PayloadTooLarge;
    if (bytes.len < header.header_len + payload_len) return error.BufferTooShort;
    const payload = try allocator.dupe(u8, bytes[header.header_len .. header.header_len + payload_len]);
    errdefer allocator.free(payload);
    if (header.mask_key) |mask| applyMask(payload, mask, 0);
    try validatePayload(header, payload, options);
    return .{ .header = header, .payload = payload, .consumed = header.header_len + payload_len };
}

fn validateFrameHeader(header: FrameHeader, options: ParseFrameOptions) Error!void {
    if ((header.rsv1 and !options.allow_rsv1) or
        (header.rsv2 and !options.allow_rsv2) or
        (header.rsv3 and !options.allow_rsv3)) return error.UnexpectedRsv;

    switch (options.expect_mask) {
        .any => {},
        .masked => if (!header.masked) return error.UnmaskedClientFrame,
        .unmasked => if (header.masked) return error.MaskedServerFrame,
    }

    // RFC 6455 requires the shortest available length encoding.  Enforcing this
    // catches evasive encodings before callers allocate a payload buffer.
    if (header.payload_len <= 125 and header.header_len >= 4 and header.mask_key == null) return error.NonMinimalLength;
    if (header.payload_len <= 125 and header.header_len >= 8 and header.mask_key != null) return error.NonMinimalLength;
    if (header.payload_len >= 126 and header.payload_len <= std.math.maxInt(u16)) {
        const extended_len_bytes: usize = if (header.mask_key == null) header.header_len - 2 else header.header_len - 6;
        if (extended_len_bytes == 8) return error.NonMinimalLength;
    }
}

fn validatePayload(header: FrameHeader, payload: []const u8, options: ParseFrameOptions) Error!void {
    switch (header.opcode) {
        .text => if (options.validate_utf8 and header.fin and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8,
        .close => try validateClosePayload(payload),
        .continuation, .binary, .ping, .pong => {},
        _ => {},
    }
}

pub fn validateClosePayload(payload: []const u8) Error!void {
    if (payload.len == 0) return;
    if (payload.len == 1) return error.InvalidControlFrame;
    const code: CloseCode = @enumFromInt(std.mem.readInt(u16, payload[0..2], .big));
    if (!validCloseCode(code)) return error.InvalidCloseCode;
    if (!std.unicode.utf8ValidateSlice(payload[2..])) return error.InvalidUtf8;
}

pub fn validCloseCode(code: CloseCode) bool {
    return switch (code) {
        .normal_closure,
        .going_away,
        .protocol_error,
        .unsupported_data,
        .invalid_payload_data,
        .policy_violation,
        .message_too_big,
        .mandatory_extension,
        .internal_server_error,
        .service_restart,
        .try_again_later,
        .bad_gateway,
        => true,
        .no_status_received,
        .abnormal_closure,
        .tls_handshake,
        => false,
        _ => {
            const raw = @intFromEnum(code);
            return (raw >= 3000 and raw <= 4999);
        },
    };
}

pub fn writeFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    opcode: Opcode,
    payload: []const u8,
    options: struct { fin: bool = true, mask_key: ?[4]u8 = null },
) !void {
    if (opcode.isControl() and (!options.fin or payload.len > 125)) return error.InvalidControlFrame;
    const b0: u8 = (if (options.fin) @as(u8, 0x80) else 0) | @intFromEnum(opcode);
    try list.append(allocator, b0);
    const masked_bit: u8 = if (options.mask_key != null) 0x80 else 0;
    if (payload.len <= 125) {
        try list.append(allocator, masked_bit | @as(u8, @intCast(payload.len)));
    } else if (payload.len <= std.math.maxInt(u16)) {
        try list.append(allocator, masked_bit | 126);
        try wire.appendInt(list, allocator, u16, @intCast(payload.len), .big);
    } else {
        try list.append(allocator, masked_bit | 127);
        try wire.appendInt(list, allocator, u64, @intCast(payload.len), .big);
    }
    if (options.mask_key) |mask| {
        try list.appendSlice(allocator, &mask);
        const start = list.items.len;
        try list.appendSlice(allocator, payload);
        applyMask(list.items[start..], mask, 0);
    } else {
        try list.appendSlice(allocator, payload);
    }
}

pub fn applyMask(payload: []u8, mask_key: [4]u8, offset: usize) void {
    for (payload, 0..) |*byte, i| {
        byte.* ^= mask_key[(offset + i) & 3];
    }
}

pub fn acceptKey(client_key: []const u8) [28]u8 {
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(client_key);
    sha1.update(handshake_guid);
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    sha1.final(&digest);
    var out: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &digest);
    return out;
}

pub fn validateClientHandshake(req: http1.Request) Error!void {
    if (req.method != .GET) return error.InvalidHandshake;
    const upgrade = req.header("upgrade") orelse return error.MissingHeader;
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return error.InvalidHandshake;
    const connection = req.header("connection") orelse return error.MissingHeader;
    if (!wire.containsToken(connection, "upgrade")) return error.InvalidHandshake;
    const version = req.header("sec-websocket-version") orelse return error.MissingHeader;
    if (!std.mem.eql(u8, version, "13")) return error.InvalidHandshake;
    const key = req.header("sec-websocket-key") orelse return error.MissingHeader;
    try validateClientKey(key);
}

pub fn validateClientKey(key: []const u8) Error!void {
    if (key.len != 24) return error.InvalidHandshake;
    var nonce: [16]u8 = undefined;
    std.base64.standard.Decoder.decode(&nonce, key) catch return error.InvalidHandshake;
}

pub fn writeServerHandshake(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    client_key: []const u8,
    extra_headers: []const wire.Header,
) !void {
    const key = acceptKey(client_key);
    try list.appendSlice(allocator, "HTTP/1.1 101 Switching Protocols\r\n");
    try list.appendSlice(allocator, "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
    try list.appendSlice(allocator, &key);
    try list.appendSlice(allocator, "\r\n");
    for (extra_headers) |header| {
        try list.appendSlice(allocator, header.name);
        try list.appendSlice(allocator, ": ");
        try list.appendSlice(allocator, header.value);
        try list.appendSlice(allocator, "\r\n");
    }
    try list.appendSlice(allocator, "\r\n");
}

pub const MessageAssembler = struct {
    allocator: std.mem.Allocator,
    opcode: ?Opcode = null,
    buffer: std.ArrayList(u8) = .empty,

    pub const Message = struct {
        opcode: Opcode,
        payload: []u8,
    };

    pub fn init(allocator: std.mem.Allocator) MessageAssembler {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MessageAssembler) void {
        self.buffer.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn feed(self: *MessageAssembler, frame: Frame) !?Message {
        if (frame.header.opcode.isControl()) return null;
        if (frame.header.opcode != .continuation) {
            if (self.opcode != null) return error.InvalidFrame;
            self.opcode = frame.header.opcode;
            self.buffer.clearRetainingCapacity();
        } else if (self.opcode == null) {
            return error.InvalidFrame;
        }
        try self.buffer.appendSlice(self.allocator, frame.payload);
        if (!frame.header.fin) return null;
        const payload = try self.buffer.toOwnedSlice(self.allocator);
        const opcode = self.opcode.?;
        self.opcode = null;
        self.buffer = .empty;
        return .{ .opcode = opcode, .payload = payload };
    }
};

test "WebSocket accept key matches RFC example" {
    const key = acceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &key);
}

test "WebSocket frame masked roundtrip" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeFrame(&encoded, allocator, .text, "Hello", .{ .mask_key = .{ 1, 2, 3, 4 } });
    var frame = try parseFrameOptions(allocator, encoded.items, .{ .expect_mask = .masked });
    defer frame.deinit(allocator);
    try std.testing.expectEqual(Opcode.text, frame.header.opcode);
    try std.testing.expectEqualStrings("Hello", frame.payload);
}

test "WebSocket handshake validation" {
    const allocator = std.testing.allocator;
    const raw = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var req = try http1.parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);
    try validateClientHandshake(req);
}

test "WebSocket strict frame validation" {
    const allocator = std.testing.allocator;
    const unmasked_text = "\x81\x02hi";
    try std.testing.expectError(error.UnmaskedClientFrame, parseFrameOptions(allocator, unmasked_text, .{ .expect_mask = .masked }));

    const masked_server_ping = "\x89\x80\x01\x02\x03\x04";
    try std.testing.expectError(error.MaskedServerFrame, parseFrameOptions(allocator, masked_server_ping, .{ .expect_mask = .unmasked }));

    const non_minimal = "\x81\x7e\x00\x02hi";
    try std.testing.expectError(error.NonMinimalLength, parseFrameOptions(allocator, non_minimal, .{}));

    const rsv = "\xc1\x02hi";
    try std.testing.expectError(error.UnexpectedRsv, parseFrameOptions(allocator, rsv, .{}));

    const bad_utf8 = "\x81\x02\xc0\x80";
    try std.testing.expectError(error.InvalidUtf8, parseFrameOptions(allocator, bad_utf8, .{}));
}

test "WebSocket close payload validation" {
    var good_payload = [_]u8{ 0x03, 0xe8, 'b', 'y', 'e' };
    try validateClosePayload(&good_payload);

    var bad_reserved = [_]u8{ 0x03, 0xed };
    try std.testing.expectError(error.InvalidCloseCode, validateClosePayload(&bad_reserved));

    var bad_utf8 = [_]u8{ 0x03, 0xe8, 0xc0, 0x80 };
    try std.testing.expectError(error.InvalidUtf8, validateClosePayload(&bad_utf8));
}

test "WebSocket handshake rejects malformed nonce" {
    const allocator = std.testing.allocator;
    const raw = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: not-base64\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var req = try http1.parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(req));
}
