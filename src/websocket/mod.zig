const std = @import("std");
const builtin = @import("builtin");
const wire = @import("../internal/wire.zig");
const http1 = @import("../http1/mod.zig");

pub const runtime = @import("runtime.zig");

const backend_supports_vectors = switch (builtin.zig_backend) {
    .stage2_llvm, .stage2_c => true,
    else => false,
};

pub const handshake_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const Error = error{
    BufferTooShort,
    InvalidOpcode,
    InvalidFrame,
    InvalidControlFrame,
    InvalidUtf8,
    MissingHeader,
    InvalidHandshake,
    InvalidExtension,
    PayloadTooLarge,
    UnmaskedClientFrame,
    MaskedServerFrame,
    UnexpectedRsv,
    NonMinimalLength,
    InvalidCloseCode,
} || std.mem.Allocator.Error || std.Io.Writer.Error;

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

pub const CloseFrame = struct {
    code: CloseCode,
    reason: []const u8 = "",
};

pub const OwnedCloseFrame = struct {
    code: CloseCode,
    reason: []u8,

    pub fn deinit(self: *OwnedCloseFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.reason);
        self.* = undefined;
    }
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

pub const ExtensionNegotiation = struct {
    permessage_deflate: bool = false,
    client_no_context_takeover: bool = false,
    server_no_context_takeover: bool = false,
    client_max_window_bits: ?u8 = null,
    server_max_window_bits: ?u8 = null,

    pub fn parseOffer(header_value: []const u8) Error!ExtensionNegotiation {
        var offers = std.mem.splitScalar(u8, header_value, ',');
        while (offers.next()) |raw_offer| {
            if (try parseExtensionOffer(wire.trimOws(raw_offer))) |offer| return offer;
        }
        return .{};
    }

    pub fn accept(allocator: std.mem.Allocator, offer_header: ?[]const u8, enable_permessage_deflate: bool) Error!?[]u8 {
        if (!enable_permessage_deflate) return null;
        const raw = offer_header orelse return null;
        const offer = try parseOffer(raw);
        if (!offer.permessage_deflate) return null;
        if (offer.server_max_window_bits) |bits| {
            // Our compressor currently uses std.compress.flate's default 32 KiB
            // window.  Like websocket.zig, decline offers that require the
            // server-to-client direction to use a smaller LZ77 window instead
            // of negotiating an extension we cannot faithfully satisfy.
            if (bits != 15) return null;
        }

        var value: std.ArrayList(u8) = .empty;
        errdefer value.deinit(allocator);
        try value.appendSlice(allocator, "permessage-deflate");
        // `std.compress.flate` exposes a normal 32 KiB history window.  Until
        // smaller sliding windows are implemented, negotiate no-context-takeover
        // on both directions and ignore smaller *_max_window_bits offers.
        try value.appendSlice(allocator, "; server_no_context_takeover; client_no_context_takeover");
        return try value.toOwnedSlice(allocator);
    }

    pub fn acceptClientHeaders(
        allocator: std.mem.Allocator,
        headers: []const http1.Header,
        enable_permessage_deflate: bool,
    ) Error!?[]u8 {
        if (!enable_permessage_deflate) return null;
        for (headers) |header| {
            if (!header.eqlName("sec-websocket-extensions")) continue;
            if (try accept(allocator, header.value, true)) |accepted| return accepted;
        }
        return null;
    }

    pub fn validateResponse(header_value: ?[]const u8) Error!ExtensionNegotiation {
        const raw = header_value orelse return .{};
        var negotiated: ?ExtensionNegotiation = null;
        var responses = std.mem.splitScalar(u8, raw, ',');
        while (responses.next()) |response| {
            const trimmed = wire.trimOws(response);
            if (trimmed.len == 0) return error.InvalidExtension;
            const parsed = (try parseExtensionOffer(trimmed)) orelse return error.InvalidExtension;
            if (!parsed.permessage_deflate) return error.InvalidExtension;
            if (negotiated != null) return error.InvalidExtension;
            if (!parsed.client_no_context_takeover or !parsed.server_no_context_takeover) return error.InvalidExtension;
            if (parsed.client_max_window_bits) |bits| if (bits != 15) return error.InvalidExtension;
            if (parsed.server_max_window_bits) |bits| if (bits != 15) return error.InvalidExtension;
            negotiated = parsed;
        }
        return negotiated orelse error.InvalidExtension;
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

pub const BorrowedFrame = struct {
    header: FrameHeader,
    payload: []u8,
    consumed: usize,
};

pub const max_frame_header_len: usize = 14;

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

/// Decode one frame into caller-owned payload storage.
///
/// The input frame may be discarded as soon as this returns. Masking copies
/// and transforms in one pass, matching the owned parser's validation without
/// a payload allocation.
pub fn parseFrameInto(
    out: []u8,
    bytes: []const u8,
    options: ParseFrameOptions,
) Error!BorrowedFrame {
    const header = try FrameHeader.parse(bytes);
    try validateFrameHeader(header, options);
    const payload_len = std.math.cast(usize, header.payload_len) orelse
        return error.PayloadTooLarge;
    const consumed = std.math.add(
        usize,
        header.header_len,
        payload_len,
    ) catch return error.PayloadTooLarge;
    if (bytes.len < consumed) return error.BufferTooShort;
    if (out.len < payload_len) return error.BufferTooShort;
    const payload = out[0..payload_len];
    const encoded = bytes[header.header_len..consumed];
    if (header.mask_key) |mask| {
        try applyMaskCopy(payload, encoded, mask, 0);
    } else {
        @memcpy(payload, encoded);
    }
    try validatePayload(header, payload, options);
    return .{
        .header = header,
        .payload = payload,
        .consumed = consumed,
    };
}

fn validateFrameHeader(header: FrameHeader, options: ParseFrameOptions) Error!void {
    if (header.opcode.isControl() and (header.rsv1 or header.rsv2 or header.rsv3)) return error.UnexpectedRsv;
    if (header.opcode == .continuation and (header.rsv1 or header.rsv2 or header.rsv3)) return error.UnexpectedRsv;
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
        .text => if (options.validate_utf8 and header.fin and !header.rsv1 and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8,
        .close => try validateClosePayload(payload),
        .continuation, .binary, .ping, .pong => {},
        _ => {},
    }
}

pub fn validateClosePayload(payload: []const u8) Error!void {
    _ = try parseClosePayload(payload);
}

pub fn parseClosePayload(payload: []const u8) Error!?CloseFrame {
    if (payload.len == 0) return null;
    if (payload.len > 125) return error.InvalidControlFrame;
    if (payload.len == 1) return error.InvalidControlFrame;
    const code: CloseCode = @enumFromInt(std.mem.readInt(u16, payload[0..2], .big));
    if (!validCloseCode(code)) return error.InvalidCloseCode;
    if (!std.unicode.utf8ValidateSlice(payload[2..])) return error.InvalidUtf8;
    return .{ .code = code, .reason = payload[2..] };
}

pub fn parseClosePayloadOwned(allocator: std.mem.Allocator, payload: []const u8) Error!?OwnedCloseFrame {
    const parsed = try parseClosePayload(payload) orelse return null;
    return .{
        .code = parsed.code,
        .reason = try allocator.dupe(u8, parsed.reason),
    };
}

pub fn writeClosePayload(list: *std.ArrayList(u8), allocator: std.mem.Allocator, close_frame: ?CloseFrame) Error!void {
    const frame = close_frame orelse return;
    if (!validCloseCode(frame.code)) return error.InvalidCloseCode;
    if (!std.unicode.utf8ValidateSlice(frame.reason)) return error.InvalidUtf8;
    if (frame.reason.len > 123) return error.InvalidControlFrame;
    try wire.appendInt(list, allocator, u16, @intFromEnum(frame.code), .big);
    try list.appendSlice(allocator, frame.reason);
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
    try writeFrameExtended(list, allocator, opcode, payload, .{
        .fin = options.fin,
        .mask_key = options.mask_key,
    });
}

pub fn writeFrameExtended(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    opcode: Opcode,
    payload: []const u8,
    options: WriteFrameOptions,
) !void {
    var header_storage: [max_frame_header_len]u8 = undefined;
    const header = try writeFrameHeaderInto(
        &header_storage,
        opcode,
        payload,
        options,
    );
    const required = std.math.add(
        usize,
        header.len,
        payload.len,
    ) catch return error.PayloadTooLarge;
    try list.ensureUnusedCapacity(allocator, required);
    list.appendSliceAssumeCapacity(header);
    const encoded_payload =
        list.addManyAsSliceAssumeCapacity(payload.len);
    if (options.mask_key) |mask| {
        applyMaskCopyAssumeCapacity(encoded_payload, payload, mask, 0);
    } else {
        @memcpy(encoded_payload, payload);
    }
}

/// Encode a complete frame into caller-owned storage without allocation.
///
/// This is useful for fixed buffers, benchmarks, and transports that already
/// own reusable packet storage. Runtime stream writers can use
/// `writeFrameHeaderInto` directly to avoid copying an unmasked payload.
pub fn writeFrameInto(
    storage: []u8,
    opcode: Opcode,
    payload: []const u8,
    options: WriteFrameOptions,
) Error![]u8 {
    var header_storage: [max_frame_header_len]u8 = undefined;
    const header = try writeFrameHeaderInto(
        &header_storage,
        opcode,
        payload,
        options,
    );
    const required = std.math.add(
        usize,
        header.len,
        payload.len,
    ) catch return error.PayloadTooLarge;
    if (storage.len < required) return error.BufferTooShort;
    @memcpy(storage[0..header.len], header);
    const encoded_payload = storage[header.len..required];
    if (options.mask_key) |mask| {
        applyMaskCopyAssumeCapacity(encoded_payload, payload, mask, 0);
    } else {
        @memcpy(encoded_payload, payload);
    }
    return storage[0..required];
}

/// Write only the RFC 6455 frame header into the fixed 14-byte maximum.
///
/// The payload is accepted so all opcode, control-frame, RSV, UTF-8, and Close
/// validation remains identical to `writeFrameExtended`; callers may safely
/// stream the returned header and original payload as one logical frame.
pub fn writeFrameHeaderInto(
    storage: *[max_frame_header_len]u8,
    opcode: Opcode,
    payload: []const u8,
    options: WriteFrameOptions,
) Error![]const u8 {
    try validateOutgoingFrame(opcode, payload, options);
    storage[0] = (if (options.fin) @as(u8, 0x80) else 0) |
        (if (options.rsv1) @as(u8, 0x40) else 0) |
        (if (options.rsv2) @as(u8, 0x20) else 0) |
        (if (options.rsv3) @as(u8, 0x10) else 0) |
        @intFromEnum(opcode);
    const masked_bit: u8 = if (options.mask_key != null) 0x80 else 0;
    var pos: usize = 2;
    if (payload.len <= 125) {
        storage[1] = masked_bit | @as(u8, @intCast(payload.len));
    } else if (payload.len <= std.math.maxInt(u16)) {
        storage[1] = masked_bit | 126;
        std.mem.writeInt(u16, storage[2..4], @intCast(payload.len), .big);
        pos = 4;
    } else {
        const payload_len = std.math.cast(u64, payload.len) orelse
            return error.PayloadTooLarge;
        storage[1] = masked_bit | 127;
        std.mem.writeInt(u64, storage[2..10], payload_len, .big);
        pos = 10;
    }
    if (options.mask_key) |mask| {
        @memcpy(storage[pos..][0..mask.len], &mask);
        pos += mask.len;
    }
    return storage[0..pos];
}

pub const WriteFrameOptions = struct {
    fin: bool = true,
    mask_key: ?[4]u8 = null,
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
};

fn validateOutgoingFrame(
    opcode: Opcode,
    payload: []const u8,
    options: WriteFrameOptions,
) Error!void {
    _ = options.mask_key;
    switch (opcode) {
        .continuation, .text, .binary, .close, .ping, .pong => {},
        _ => return error.InvalidOpcode,
    }
    if (opcode.isControl()) {
        if (!options.fin or payload.len > 125) return error.InvalidControlFrame;
        if (options.rsv1 or options.rsv2 or options.rsv3) return error.UnexpectedRsv;
    }
    if (opcode == .continuation and (options.rsv1 or options.rsv2 or options.rsv3)) return error.UnexpectedRsv;

    // The codec writer is often used directly in tests and simple tools, so it
    // should not be able to emit frames that its peer-side parser would reject.
    // Fragmented text can split a UTF-8 sequence across frames and compressed
    // text is not UTF-8 until inflated, so validate only uncompressed final text
    // frames here; the runtime validates whole fragmented messages separately.
    if (opcode == .text and options.fin and !options.rsv1 and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
    if (opcode == .close) try validateClosePayload(payload);
}

pub fn applyMask(payload: []u8, mask_key: [4]u8, offset: usize) void {
    if (payload.len == 0) return;
    const rotated = rotatedMask(mask_key, offset);
    var data = payload;

    if (comptime backend_supports_vectors) {
        const vector_size = std.simd.suggestVectorLength(u8) orelse @sizeOf(usize);
        if (data.len >= vector_size) {
            const mask_vector = std.simd.repeat(vector_size, @as(@Vector(4, u8), rotated));
            while (data.len >= vector_size) {
                const slice = data[0..vector_size];
                const in: @Vector(vector_size, u8) = slice.*;
                slice.* = in ^ mask_vector;
                data = data[vector_size..];
            }
        }
    }

    applyMaskScalar(data, rotated);
}

/// Copy and mask payload bytes in one pass while preserving caller input.
///
/// This is the safe client-send counterpart to in-place masking: RFC 6455
/// requires a client mask, but public `[]const u8` application buffers must
/// not be modified merely to avoid an allocation.
pub fn applyMaskCopy(
    output: []u8,
    payload: []const u8,
    mask_key: [4]u8,
    offset: usize,
) Error!void {
    if (output.len < payload.len) return error.BufferTooShort;
    applyMaskCopyAssumeCapacity(
        output[0..payload.len],
        payload,
        mask_key,
        offset,
    );
}

fn applyMaskCopyAssumeCapacity(
    output: []u8,
    payload: []const u8,
    mask_key: [4]u8,
    offset: usize,
) void {
    std.debug.assert(output.len == payload.len);
    if (payload.len == 0) return;
    const rotated = rotatedMask(mask_key, offset);
    var out = output;
    var data = payload;

    if (comptime backend_supports_vectors) {
        const vector_size =
            std.simd.suggestVectorLength(u8) orelse @sizeOf(usize);
        if (comptime vector_size % mask_key.len == 0) {
            const mask_vector = std.simd.repeat(
                vector_size,
                @as(@Vector(4, u8), rotated),
            );
            while (data.len >= vector_size) {
                const in: @Vector(vector_size, u8) =
                    data[0..vector_size].*;
                out[0..vector_size].* = in ^ mask_vector;
                data = data[vector_size..];
                out = out[vector_size..];
            }
        }
    }

    @setRuntimeSafety(false);
    for (data, 0..) |byte, index| {
        out[index] = byte ^ rotated[index & 3];
    }
}

fn rotatedMask(mask_key: [4]u8, offset: usize) [4]u8 {
    const start = offset & 3;
    return .{
        mask_key[start],
        mask_key[(start + 1) & 3],
        mask_key[(start + 2) & 3],
        mask_key[(start + 3) & 3],
    };
}

fn applyMaskScalar(payload: []u8, mask_key: [4]u8) void {
    @setRuntimeSafety(false);
    for (payload, 0..) |byte, i| {
        payload[i] = byte ^ mask_key[i & 3];
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
    if (req.version != .http_1_1) return error.InvalidHandshake;
    switch (req.body_framing) {
        .none => {},
        .content_length => if (req.body.len != 0) return error.InvalidHandshake,
        .chunked, .close_delimited => return error.InvalidHandshake,
    }
    if (req.trailers.len != 0) return error.InvalidHandshake;
    const host = try requiredSingletonHeader(req.headers, "host");
    if (wire.trimOws(host).len == 0) return error.InvalidHandshake;
    http1.validateHostValue(host) catch return error.InvalidHandshake;
    const upgrade = try requiredSingletonHeader(req.headers, "upgrade");
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return error.InvalidHandshake;
    if (!hasHeader(req.headers, "connection")) return error.MissingHeader;
    if (!headersContainToken(req.headers, "connection", "upgrade")) return error.InvalidHandshake;
    const version = try requiredSingletonHeader(req.headers, "sec-websocket-version");
    if (!std.mem.eql(u8, version, "13")) return error.InvalidHandshake;
    const key = try requiredSingletonHeader(req.headers, "sec-websocket-key");
    try validateClientKey(key);
    try validateClientSubprotocolHeaders(req.headers);
}

fn requiredSingletonHeader(headers: []const http1.Header, name: []const u8) Error![]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!header.eqlName(name)) continue;
        if (found != null) return error.InvalidHandshake;
        found = header.value;
    }
    return found orelse error.MissingHeader;
}

fn hasHeader(headers: []const http1.Header, name: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name)) return true;
    }
    return false;
}

fn headersContainToken(headers: []const http1.Header, name: []const u8, token: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name) and wire.containsToken(header.value, token)) return true;
    }
    return false;
}

pub fn validateClientKey(key: []const u8) Error!void {
    if (key.len != 24) return error.InvalidHandshake;
    var nonce: [16]u8 = undefined;
    std.base64.standard.Decoder.decode(&nonce, key) catch return error.InvalidHandshake;
}

fn validateClientSubprotocolHeaders(headers: []const http1.Header) Error!void {
    var token_index: usize = 0;
    for (headers) |header| {
        if (!header.eqlName("sec-websocket-protocol")) continue;
        var protocols = std.mem.splitScalar(u8, header.value, ',');
        while (protocols.next()) |raw_protocol| {
            const protocol = wire.trimOws(raw_protocol);
            if (!validSubprotocolToken(protocol)) return error.InvalidHandshake;
            if (subprotocolTokenSeenBefore(headers, token_index, protocol)) return error.InvalidHandshake;
            token_index += 1;
        }
    }
}

fn subprotocolTokenSeenBefore(headers: []const http1.Header, before_index: usize, candidate: []const u8) bool {
    var seen: usize = 0;
    for (headers) |header| {
        if (!header.eqlName("sec-websocket-protocol")) continue;
        var protocols = std.mem.splitScalar(u8, header.value, ',');
        while (protocols.next()) |raw_protocol| {
            if (seen >= before_index) return false;
            if (std.mem.eql(u8, wire.trimOws(raw_protocol), candidate)) return true;
            seen += 1;
        }
    }
    return false;
}

pub fn validSubprotocolToken(protocol: []const u8) bool {
    if (protocol.len == 0) return false;
    for (protocol) |byte| {
        if (!isTchar(byte)) return false;
    }
    return true;
}

fn isTchar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

pub fn writeServerHandshake(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    client_key: []const u8,
    extra_headers: []const wire.Header,
) !void {
    try validateClientKey(client_key);
    try validateServerHandshakeHeaders(extra_headers);
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

fn validateServerHandshakeHeaders(headers: []const wire.Header) !void {
    var saw_protocol = false;
    var saw_extensions = false;
    for (headers) |header| {
        try http1.validateHeader(header);
        if (header.eqlName("upgrade") or
            header.eqlName("connection") or
            header.eqlName("sec-websocket-accept"))
        {
            // The writer owns these mandatory fields.  Rejecting caller-provided
            // duplicates keeps the 101 response unambiguous for RFC 6455 clients.
            return error.InvalidHandshake;
        }
        if (header.eqlName("sec-websocket-protocol")) {
            if (saw_protocol) return error.InvalidHandshake;
            saw_protocol = true;
            if (!validSubprotocolToken(wire.trimOws(header.value))) return error.InvalidHandshake;
        } else if (header.eqlName("sec-websocket-extensions")) {
            if (saw_extensions) return error.InvalidHandshake;
            saw_extensions = true;
            _ = try ExtensionNegotiation.validateResponse(header.value);
        }
    }
}

pub const MessageAssembler = struct {
    allocator: std.mem.Allocator,
    max_message_bytes: usize = std.math.maxInt(usize),
    opcode: ?Opcode = null,
    compressed: bool = false,
    buffer: std.ArrayList(u8) = .empty,

    pub const Message = struct {
        opcode: Opcode,
        payload: []u8,
        compressed: bool = false,
    };

    pub fn init(allocator: std.mem.Allocator) MessageAssembler {
        return .{ .allocator = allocator };
    }

    pub fn initLimited(allocator: std.mem.Allocator, max_message_bytes: usize) MessageAssembler {
        return .{ .allocator = allocator, .max_message_bytes = max_message_bytes };
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
            self.compressed = frame.header.rsv1;
            self.buffer.clearRetainingCapacity();
        } else if (self.opcode == null) {
            return error.InvalidFrame;
        } else if (frame.header.rsv1) {
            return error.UnexpectedRsv;
        }
        // A fragmented message can be split into many individually-valid
        // frames.  Bound the aggregate payload, not only the current frame, so
        // peers cannot bypass runtime limits with many small fragments.
        const new_len = std.math.add(usize, self.buffer.items.len, frame.payload.len) catch return error.PayloadTooLarge;
        if (new_len > self.max_message_bytes) return error.PayloadTooLarge;
        try self.buffer.appendSlice(self.allocator, frame.payload);
        if (!frame.header.fin) return null;
        const payload = try self.buffer.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(payload);
        const opcode = self.opcode.?;
        const compressed = self.compressed;
        // Keep the public assembler as strict as the runtime wrapper and
        // tungstenite's text collector: fragmented text is allowed to split
        // UTF-8 code points, but the completed uncompressed message must be
        // valid UTF-8 before it is handed to callers.
        if (opcode == .text and !compressed and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
        self.opcode = null;
        self.compressed = false;
        self.buffer = .empty;
        return .{ .opcode = opcode, .payload = payload, .compressed = compressed };
    }
};

pub fn compressMessage(
    allocator: std.mem.Allocator,
    payload: []const u8,
) Error![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    const flate_window = try allocator.alloc(
        u8,
        std.compress.flate.max_window_len,
    );
    defer allocator.free(flate_window);
    _ = try compressMessageInto(
        &output,
        allocator,
        flate_window,
        payload,
    );
    return output.toOwnedSlice(allocator);
}

/// Encode one RFC 7692 no-context-takeover message into reusable storage.
///
/// Zig 0.16's flate writer exposes a true streaming flush. Depending on the
/// current bit alignment it may finish with either zlib's canonical empty
/// stored block or one or more empty fixed blocks. RFC 7692 requires the
/// canonical `00 00 ff ff` suffix to be omitted on the wire, so the latter
/// case appends the first byte of a fresh empty stored block; the receiver's
/// normal four-byte suffix restoration then reconstructs that block exactly.
pub fn compressMessageInto(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    flate_window: []u8,
    payload: []const u8,
) Error![]const u8 {
    if (flate_window.len < std.compress.flate.max_window_len) {
        return error.BufferTooShort;
    }
    output.clearRetainingCapacity();
    var allocating = std.Io.Writer.Allocating.fromArrayList(
        allocator,
        output,
    );
    defer output.* = allocating.toArrayList();
    // Keep enough direct output capacity for the common compressible path.
    // The allocating writer remains the correctness fallback for an
    // incompressible message; the runtime will send the original bytes unless
    // the resulting wire payload is strictly smaller.
    try allocating.ensureTotalCapacity(payload.len +| 64);
    var compressor = try std.compress.flate.Compress.init(
        &allocating.writer,
        flate_window[0..std.compress.flate.max_window_len],
        .raw,
        .fastest,
    );
    try compressor.writer.writeAll(payload);
    try compressor.writer.flush();

    const sync_flush_tail = "\x00\x00\xff\xff";
    const encoded = allocating.written();
    if (std.mem.endsWith(u8, encoded, sync_flush_tail)) {
        allocating.shrinkRetainingCapacity(
            encoded.len - sync_flush_tail.len,
        );
    } else {
        // At this point the flate writer is byte-aligned. This zero is the
        // BFINAL=0/BTYPE=00 header of the empty stored block whose LEN/NLEN
        // bytes are restored by the decoder.
        try allocating.writer.writeByte(0x00);
    }
    return allocating.written();
}

pub fn decompressMessage(allocator: std.mem.Allocator, compressed_payload: []const u8, max_message_bytes: usize) Error![]u8 {
    var with_tail = try std.ArrayList(u8).initCapacity(allocator, compressed_payload.len + 4);
    defer with_tail.deinit(allocator);
    try with_tail.appendSlice(allocator, compressed_payload);
    try with_tail.appendSlice(allocator, &.{
        0x00, 0x00, 0xff, 0xff, // RFC 7692 tail restored for the message.
        0x01, 0x00, 0x00, 0xff, 0xff, // Final empty block for std's raw inflater.
    });

    var input_reader = std.Io.Reader.fixed(with_tail.items);
    const buffer = try allocator.alloc(u8, std.compress.flate.max_window_len);
    defer allocator.free(buffer);
    var decompressor = std.compress.flate.Decompress.init(&input_reader, .raw, buffer);
    var output = std.Io.Writer.Allocating.init(allocator);
    errdefer output.deinit();
    while (decompressor.reader.peekGreedy(1)) |bytes| {
        if (output.writer.end + bytes.len > max_message_bytes) return error.PayloadTooLarge;
        try output.writer.writeAll(bytes);
        decompressor.reader.toss(bytes.len);
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.ReadFailed => return error.InvalidFrame,
    }
    return output.toOwnedSlice();
}

/// Inflate one RFC 7692 no-context-takeover message into caller storage.
///
/// `compressed_scratch` must hold the wire payload plus the nine-byte
/// sync-flush/final-block suffix. `flate_window` is reusable connection state;
/// keeping it outside this function avoids a 64 KiB allocation per message.
pub fn decompressMessageInto(
    out: []u8,
    compressed_payload: []const u8,
    compressed_scratch: []u8,
    flate_window: []u8,
) Error![]u8 {
    const tail: []const u8 = &.{
        0x00, 0x00, 0xff, 0xff, // RFC 7692 sync-flush tail.
        0x01, 0x00, 0x00, 0xff, 0xff, // Final empty stored block.
    };
    const input_len = std.math.add(
        usize,
        compressed_payload.len,
        tail.len,
    ) catch return error.PayloadTooLarge;
    if (compressed_scratch.len < input_len or
        flate_window.len < std.compress.flate.max_window_len)
    {
        return error.BufferTooShort;
    }
    if (compressed_payload.ptr != compressed_scratch.ptr) {
        @memcpy(
            compressed_scratch[0..compressed_payload.len],
            compressed_payload,
        );
    }
    @memcpy(
        compressed_scratch[compressed_payload.len..input_len],
        tail,
    );

    var input_reader = std.Io.Reader.fixed(
        compressed_scratch[0..input_len],
    );
    var decompressor = std.compress.flate.Decompress.init(
        &input_reader,
        .raw,
        flate_window[0..std.compress.flate.max_window_len],
    );
    var output_writer: std.Io.Writer = .fixed(out);
    _ = decompressor.reader.streamRemaining(&output_writer) catch |err| {
        return switch (err) {
            error.WriteFailed => error.PayloadTooLarge,
            error.ReadFailed => error.InvalidFrame,
        };
    };
    return output_writer.buffered();
}

fn parseExtensionOffer(value: []const u8) Error!?ExtensionNegotiation {
    if (value.len == 0) return null;
    var parts = std.mem.splitScalar(u8, value, ';');
    const name = wire.trimOws(parts.next() orelse return null);
    if (!std.ascii.eqlIgnoreCase(name, "permessage-deflate")) return null;
    var out = ExtensionNegotiation{ .permessage_deflate = true };
    var saw_client_no_context_takeover = false;
    var saw_server_no_context_takeover = false;
    var saw_client_max_window_bits = false;
    var saw_server_max_window_bits = false;
    while (parts.next()) |raw_param| {
        const param = wire.trimOws(raw_param);
        if (param.len == 0) return error.InvalidExtension;
        if (std.ascii.eqlIgnoreCase(param, "client_no_context_takeover")) {
            if (saw_client_no_context_takeover) return error.InvalidExtension;
            saw_client_no_context_takeover = true;
            out.client_no_context_takeover = true;
        } else if (std.ascii.eqlIgnoreCase(param, "server_no_context_takeover")) {
            if (saw_server_no_context_takeover) return error.InvalidExtension;
            saw_server_no_context_takeover = true;
            out.server_no_context_takeover = true;
        } else if (parseWindowBitsParam(param, "client_max_window_bits")) |bits| {
            if (saw_client_max_window_bits) return error.InvalidExtension;
            saw_client_max_window_bits = true;
            out.client_max_window_bits = bits;
        } else if (parseWindowBitsParam(param, "server_max_window_bits")) |bits| {
            if (saw_server_max_window_bits) return error.InvalidExtension;
            saw_server_max_window_bits = true;
            out.server_max_window_bits = bits;
        } else {
            return error.InvalidExtension;
        }
    }
    if (out.client_max_window_bits) |bits| if (bits < 8 or bits > 15) return error.InvalidExtension;
    if (out.server_max_window_bits) |bits| if (bits < 8 or bits > 15) return error.InvalidExtension;
    return out;
}

fn parseWindowBitsParam(param: []const u8, name: []const u8) ?u8 {
    if (std.ascii.eqlIgnoreCase(param, name)) return 15;
    if (param.len <= name.len or param[name.len] != '=') return null;
    if (!std.ascii.eqlIgnoreCase(param[0..name.len], name)) return null;
    return parseWindowBitsValue(param[name.len + 1 ..]);
}

fn parseWindowBitsValue(raw_value: []const u8) u8 {
    // Sec-WebSocket-Extensions uses the generic extension-param grammar from
    // RFC 6455: parameter values may be either tokens or quoted-strings.  The
    // permessage-deflate window-bit value itself is still a decimal integer, so
    // accept a quoted integer like server_max_window_bits=\"15\" but reject
    // escapes/empty strings instead of silently normalizing ambiguous values.
    const value = if (raw_value.len >= 2 and raw_value[0] == '"') blk: {
        if (raw_value[raw_value.len - 1] != '"') return 0;
        const inner = raw_value[1 .. raw_value.len - 1];
        if (std.mem.indexOfScalar(u8, inner, '\\') != null or std.mem.indexOfScalar(u8, inner, '"') != null) return 0;
        break :blk inner;
    } else raw_value;

    if (value.len == 0) return 0;
    var parsed: u16 = 0;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte)) return 0;
        parsed = parsed * 10 + byte - '0';
        if (parsed > std.math.maxInt(u8)) return 0;
    }
    return @intCast(parsed);
}

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

    var payload = [_]u8{
        0,  1,  2,  3,  4,  5,  6,  7,
        8,  9,  10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31,
        32, 33, 34,
    };
    var expected = payload;
    const mask_key = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const offset = 3;
    for (&expected, 0..) |*byte, i| byte.* ^= mask_key[(offset + i) & 3];
    applyMask(&payload, mask_key, offset);
    try std.testing.expectEqualSlices(u8, &expected, &payload);
}

test "WebSocket frame decodes masked payload into caller storage" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeFrame(
        &encoded,
        allocator,
        .binary,
        "caller-owned",
        .{ .mask_key = .{ 1, 2, 3, 4 } },
    );

    var storage: [32]u8 = undefined;
    const frame = try parseFrameInto(
        &storage,
        encoded.items,
        .{ .expect_mask = .masked },
    );
    try std.testing.expectEqual(Opcode.binary, frame.header.opcode);
    try std.testing.expectEqualStrings("caller-owned", frame.payload);
    try std.testing.expectEqual(encoded.items.len, frame.consumed);
    try std.testing.expectError(
        error.BufferTooShort,
        parseFrameInto(
            storage[0..4],
            encoded.items,
            .{ .expect_mask = .masked },
        ),
    );
}

test "WebSocket caller-buffer frame encoding matches allocating writer" {
    const allocator = std.testing.allocator;
    const payload_lengths = [_]usize{
        0,
        1,
        125,
        126,
        std.math.maxInt(u16),
        @as(usize, std.math.maxInt(u16)) + 1,
    };

    for (payload_lengths) |payload_len| {
        const payload = try allocator.alloc(u8, payload_len);
        defer allocator.free(payload);
        for (payload, 0..) |*byte, index| byte.* = @truncate(index);

        for ([_]?[4]u8{ null, .{ 0x12, 0x34, 0x56, 0x78 } }) |mask_key| {
            var allocating: std.ArrayList(u8) = .empty;
            defer allocating.deinit(allocator);
            try writeFrameExtended(
                &allocating,
                allocator,
                .binary,
                payload,
                .{ .mask_key = mask_key },
            );

            const storage = try allocator.alloc(
                u8,
                payload_len + max_frame_header_len,
            );
            defer allocator.free(storage);
            const encoded = try writeFrameInto(
                storage,
                .binary,
                payload,
                .{ .mask_key = mask_key },
            );
            try std.testing.expectEqualSlices(
                u8,
                allocating.items,
                encoded,
            );

            const header = try FrameHeader.parse(encoded);
            try std.testing.expectEqual(
                @as(u64, @intCast(payload_len)),
                header.payload_len,
            );
            try std.testing.expectEqual(mask_key != null, header.masked);
        }
    }
}

test "WebSocket fixed frame encoder rejects short output transactionally" {
    var storage = [_]u8{0xa5} ** max_frame_header_len;
    try std.testing.expectError(
        error.BufferTooShort,
        writeFrameInto(
            &storage,
            .binary,
            "payload does not fit",
            .{ .mask_key = .{ 1, 2, 3, 4 } },
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xa5} ** max_frame_header_len),
        &storage,
    );
}

test "WebSocket mask copy preserves input and supports stream offsets" {
    const payload = "0123456789abcdef";
    var masked: [payload.len]u8 = undefined;
    const key = [4]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const offset = 3;
    try applyMaskCopy(&masked, payload, key, offset);
    for (masked, 0..) |byte, index| {
        try std.testing.expectEqual(
            payload[index] ^ key[(offset + index) & 3],
            byte,
        );
    }
    try std.testing.expectEqualStrings("0123456789abcdef", payload);

    var short: [payload.len - 1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        applyMaskCopy(&short, payload, key, offset),
    );
}

test "WebSocket handshake validation" {
    const allocator = std.testing.allocator;
    const raw = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var req = try http1.parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);
    try validateClientHandshake(req);

    const split_connection = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var split_req = try http1.parseRequest(allocator, split_connection, .{});
    defer split_req.deinit(allocator);
    try validateClientHandshake(split_req);

    const http10 = "GET /chat HTTP/1.0\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var http10_req = try http1.parseRequest(allocator, http10, .{});
    defer http10_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(http10_req));

    const duplicate_key = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var duplicate_key_req = try http1.parseRequest(allocator, duplicate_key, .{});
    defer duplicate_key_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(duplicate_key_req));

    const missing_host = "GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var missing_host_req = try http1.parseRequest(allocator, missing_host, .{});
    defer missing_host_req.deinit(allocator);
    try std.testing.expectError(error.MissingHeader, validateClientHandshake(missing_host_req));

    const empty_host = "GET /chat HTTP/1.1\r\nHost: \t \r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var empty_host_req = try http1.parseRequest(allocator, empty_host, .{});
    defer empty_host_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(empty_host_req));

    const invalid_host = "GET /chat HTTP/1.1\r\nHost: http://example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var invalid_host_req = try http1.parseRequest(allocator, invalid_host, .{});
    defer invalid_host_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(invalid_host_req));

    const unbracketed_ipv6_host = "GET /chat HTTP/1.1\r\nHost: 2001:db8::1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var unbracketed_ipv6_host_req = try http1.parseRequest(allocator, unbracketed_ipv6_host, .{});
    defer unbracketed_ipv6_host_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(unbracketed_ipv6_host_req));

    const duplicate_host = "GET /chat HTTP/1.1\r\nHost: example.com\r\nHost: other.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var duplicate_host_req = try http1.parseRequest(allocator, duplicate_host, .{});
    defer duplicate_host_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(duplicate_host_req));

    const valid_protocols = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1, super-chat\r\n\r\n";
    var valid_protocols_req = try http1.parseRequest(allocator, valid_protocols, .{});
    defer valid_protocols_req.deinit(allocator);
    try validateClientHandshake(valid_protocols_req);

    const invalid_protocol = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1, bad protocol\r\n\r\n";
    var invalid_protocol_req = try http1.parseRequest(allocator, invalid_protocol, .{});
    defer invalid_protocol_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(invalid_protocol_req));

    const empty_protocol = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1,\r\n\r\n";
    var empty_protocol_req = try http1.parseRequest(allocator, empty_protocol, .{});
    defer empty_protocol_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(empty_protocol_req));

    const duplicate_protocol = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1, chat.v1\r\n\r\n";
    var duplicate_protocol_req = try http1.parseRequest(allocator, duplicate_protocol, .{});
    defer duplicate_protocol_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(duplicate_protocol_req));

    const split_duplicate_protocol = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1\r\nSec-WebSocket-Protocol: chat.v2, chat.v1\r\n\r\n";
    var split_duplicate_protocol_req = try http1.parseRequest(allocator, split_duplicate_protocol, .{});
    defer split_duplicate_protocol_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(split_duplicate_protocol_req));

    const request_body = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nContent-Length: 4\r\n\r\nbody";
    var request_body_req = try http1.parseRequest(allocator, request_body, .{});
    defer request_body_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(request_body_req));

    const chunked_request = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    var chunked_request_req = try http1.parseRequest(allocator, chunked_request, .{});
    defer chunked_request_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(chunked_request_req));
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

    const rsv_ping = "\xc9\x00";
    try std.testing.expectError(error.UnexpectedRsv, parseFrameOptions(allocator, rsv_ping, .{ .allow_rsv1 = true }));

    const rsv_continuation = "\xc0\x00";
    try std.testing.expectError(error.UnexpectedRsv, parseFrameOptions(allocator, rsv_continuation, .{ .allow_rsv1 = true }));

    const bad_utf8 = "\x81\x02\xc0\x80";
    try std.testing.expectError(error.InvalidUtf8, parseFrameOptions(allocator, bad_utf8, .{}));

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try std.testing.expectError(error.InvalidOpcode, writeFrame(&encoded, allocator, @enumFromInt(0x3), "", .{}));
    try std.testing.expectError(error.InvalidControlFrame, writeFrameExtended(&encoded, allocator, .ping, "", .{ .fin = false }));
    try std.testing.expectError(error.UnexpectedRsv, writeFrameExtended(&encoded, allocator, .ping, "", .{ .rsv1 = true }));
    try std.testing.expectError(error.UnexpectedRsv, writeFrameExtended(&encoded, allocator, .continuation, "", .{ .rsv1 = true }));
    var bad_close = [_]u8{ 0x03, 0xed };
    try std.testing.expectError(error.InvalidCloseCode, writeFrame(&encoded, allocator, .close, &bad_close, .{}));
    var invalid_text = [_]u8{ 0xc0, 0x80 };
    try std.testing.expectError(error.InvalidUtf8, writeFrame(&encoded, allocator, .text, &invalid_text, .{}));
}

test "WebSocket close payload validation" {
    const allocator = std.testing.allocator;
    var good_payload = [_]u8{ 0x03, 0xe8, 'b', 'y', 'e' };
    try validateClosePayload(&good_payload);
    const parsed = (try parseClosePayload(&good_payload)).?;
    try std.testing.expectEqual(CloseCode.normal_closure, parsed.code);
    try std.testing.expectEqualStrings("bye", parsed.reason);

    var owned = (try parseClosePayloadOwned(allocator, &good_payload)).?;
    defer owned.deinit(allocator);
    try std.testing.expectEqual(CloseCode.normal_closure, owned.code);
    try std.testing.expectEqualStrings("bye", owned.reason);

    try std.testing.expect((try parseClosePayload(&.{})) == null);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeClosePayload(&encoded, allocator, .{ .code = .going_away, .reason = "restart" });
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0xe9, 'r', 'e', 's', 't', 'a', 'r', 't' }, encoded.items);
    const encoded_parsed = (try parseClosePayload(encoded.items)).?;
    try std.testing.expectEqual(CloseCode.going_away, encoded_parsed.code);
    try std.testing.expectEqualStrings("restart", encoded_parsed.reason);

    encoded.clearRetainingCapacity();
    try writeClosePayload(&encoded, allocator, null);
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    var bad_reserved = [_]u8{ 0x03, 0xed };
    try std.testing.expectError(error.InvalidCloseCode, validateClosePayload(&bad_reserved));
    try std.testing.expectError(error.InvalidCloseCode, writeClosePayload(&encoded, allocator, .{ .code = .no_status_received }));

    var bad_utf8 = [_]u8{ 0x03, 0xe8, 0xc0, 0x80 };
    try std.testing.expectError(error.InvalidUtf8, validateClosePayload(&bad_utf8));
    try std.testing.expectError(error.InvalidUtf8, writeClosePayload(&encoded, allocator, .{ .code = .normal_closure, .reason = "\xc0\x80" }));

    try std.testing.expectError(error.InvalidControlFrame, writeClosePayload(&encoded, allocator, .{ .code = .normal_closure, .reason = "x" ** 124 }));
}

test "WebSocket permessage-deflate helpers negotiate and roundtrip" {
    const allocator = std.testing.allocator;

    const accepted = try ExtensionNegotiation.accept(
        allocator,
        "permessage-deflate; client_no_context_takeover; server_max_window_bits=\"15\"",
        true,
    );
    defer if (accepted) |value| allocator.free(value);
    try std.testing.expect(accepted != null);
    try std.testing.expect(std.mem.indexOf(u8, accepted.?, "permessage-deflate") != null);
    const response = try ExtensionNegotiation.validateResponse(accepted.?);
    try std.testing.expect(response.permessage_deflate);
    try std.testing.expect(response.client_no_context_takeover);
    try std.testing.expect(response.server_no_context_takeover);

    const split_headers = [_]http1.Header{
        .{ .name = "Sec-WebSocket-Extensions", .value = "x-unknown" },
        .{ .name = "Sec-WebSocket-Extensions", .value = "permessage-deflate; client_no_context_takeover; server_max_window_bits=15" },
    };
    const accepted_split = try ExtensionNegotiation.acceptClientHeaders(allocator, &split_headers, true);
    defer if (accepted_split) |value| allocator.free(value);
    try std.testing.expect(accepted_split != null);
    try std.testing.expect(std.mem.startsWith(u8, accepted_split.?, "permessage-deflate"));

    const unsupported_window = try ExtensionNegotiation.accept(
        allocator,
        "permessage-deflate; server_max_window_bits=12",
        true,
    );
    try std.testing.expect(unsupported_window == null);
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse("permessage-deflate"));
    const quoted_window_response = try ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=\"15\"",
    );
    try std.testing.expectEqual(@as(?u8, 15), quoted_window_response.client_max_window_bits);
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=\"12\"",
    ));
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=\"1\\5\"",
    ));
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover, x-unknown",
    ));
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover, permessage-deflate; server_no_context_takeover; client_no_context_takeover",
    ));
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.parseOffer(
        "permessage-deflate; server_no_context_takeover; x-unknown=1",
    ));
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.parseOffer(
        "permessage-deflate; client_no_context_takeover; client_no_context_takeover",
    ));
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.parseOffer(
        "permessage-deflate; server_max_window_bits=15; server_max_window_bits=15",
    ));

    const payload = "compress me compress me compress me compress me";
    const compressed = try compressMessage(allocator, payload);
    defer allocator.free(compressed);
    try std.testing.expect(compressed.len < payload.len);
    try std.testing.expect(!std.mem.endsWith(u8, compressed, "\x00\x00\xff\xff"));
    const decoded = try decompressMessage(allocator, compressed, 1024);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(payload, decoded);

    const repeated_payload = "fragmented compressed message fragmented compressed message";
    const repeated_compressed = try compressMessage(allocator, repeated_payload);
    defer allocator.free(repeated_compressed);
    const repeated_decoded = try decompressMessage(allocator, repeated_compressed, 1024);
    defer allocator.free(repeated_decoded);
    try std.testing.expectEqualStrings(repeated_payload, repeated_decoded);

    var assembler = MessageAssembler.initLimited(allocator, 1024);
    defer assembler.deinit();
    const split = repeated_compressed.len / 2;
    const compressed_first = Frame{
        .header = .{
            .fin = false,
            .rsv1 = true,
            .opcode = .text,
            .masked = false,
            .payload_len = split,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = repeated_compressed[0..split],
        .consumed = 2 + split,
    };
    try std.testing.expectEqual(@as(?MessageAssembler.Message, null), try assembler.feed(compressed_first));
    const compressed_tail = Frame{
        .header = .{
            .fin = true,
            .opcode = .continuation,
            .masked = false,
            .payload_len = repeated_compressed.len - split,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = repeated_compressed[split..],
        .consumed = 2 + repeated_compressed.len - split,
    };
    const compressed_message = (try assembler.feed(compressed_tail)).?;
    defer allocator.free(compressed_message.payload);
    try std.testing.expect(compressed_message.compressed);
    const fragmented_decoded = try decompressMessage(allocator, compressed_message.payload, 1024);
    defer allocator.free(fragmented_decoded);
    try std.testing.expectEqualStrings(repeated_payload, fragmented_decoded);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeFrameExtended(&encoded, allocator, .text, compressed, .{ .rsv1 = true });
    var frame = try parseFrameOptions(allocator, encoded.items, .{ .allow_rsv1 = true, .validate_utf8 = false });
    defer frame.deinit(allocator);
    try std.testing.expect(frame.header.rsv1);
    try std.testing.expectError(error.PayloadTooLarge, decompressMessage(allocator, frame.payload, 4));
}

test "WebSocket message assembler enforces aggregate payload limit" {
    const allocator = std.testing.allocator;
    var assembler = MessageAssembler.initLimited(allocator, 8);
    defer assembler.deinit();

    var first_payload = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    const first = Frame{
        .header = .{
            .fin = false,
            .opcode = .text,
            .masked = false,
            .payload_len = first_payload.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = &first_payload,
        .consumed = 2 + first_payload.len,
    };
    try std.testing.expectEqual(@as(?MessageAssembler.Message, null), try assembler.feed(first));

    var second_payload = [_]u8{ 'w', 'o', 'r', 'l', 'd' };
    const second = Frame{
        .header = .{
            .fin = true,
            .opcode = .continuation,
            .masked = false,
            .payload_len = second_payload.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = &second_payload,
        .consumed = 2 + second_payload.len,
    };
    try std.testing.expectError(error.PayloadTooLarge, assembler.feed(second));
}

test "WebSocket message assembler validates completed text fragments" {
    const allocator = std.testing.allocator;
    var assembler = MessageAssembler.init(allocator);
    defer assembler.deinit();

    var first_payload = [_]u8{0xf0};
    const first = Frame{
        .header = .{
            .fin = false,
            .opcode = .text,
            .masked = false,
            .payload_len = first_payload.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = &first_payload,
        .consumed = 2 + first_payload.len,
    };
    try std.testing.expectEqual(@as(?MessageAssembler.Message, null), try assembler.feed(first));

    var invalid_tail = [_]u8{ 0x28, 0x8c, 0x28 };
    const second = Frame{
        .header = .{
            .fin = true,
            .opcode = .continuation,
            .masked = false,
            .payload_len = invalid_tail.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = &invalid_tail,
        .consumed = 2 + invalid_tail.len,
    };
    try std.testing.expectError(error.InvalidUtf8, assembler.feed(second));

    assembler.deinit();
    assembler = MessageAssembler.init(allocator);
    var compressed_first_payload = [_]u8{0xf0};
    const compressed_first = Frame{
        .header = .{
            .fin = false,
            .rsv1 = true,
            .opcode = .text,
            .masked = false,
            .payload_len = compressed_first_payload.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = &compressed_first_payload,
        .consumed = 2 + compressed_first_payload.len,
    };
    try std.testing.expectEqual(@as(?MessageAssembler.Message, null), try assembler.feed(compressed_first));

    const compressed_message = (try assembler.feed(second)).?;
    defer allocator.free(compressed_message.payload);
    try std.testing.expect(compressed_message.compressed);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xf0, 0x28, 0x8c, 0x28 }, compressed_message.payload);
}

test "WebSocket handshake rejects malformed nonce" {
    const allocator = std.testing.allocator;
    const raw = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: not-base64\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var req = try http1.parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(req));
}

test "WebSocket server handshake writer validates generated response" {
    const allocator = std.testing.allocator;
    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);

    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "not-base64",
        &.{},
    ));
    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{.{ .name = "Sec-WebSocket-Accept", .value = "duplicate" }},
    ));
    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1" },
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v2" },
        },
    ));
    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{.{ .name = "Sec-WebSocket-Protocol", .value = "bad protocol" }},
    ));
    try std.testing.expectError(error.MalformedHeader, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{.{ .name = "X-Test", .value = "ok\r\nInjected: yes" }},
    ));
}

test {
    _ = runtime;
}
