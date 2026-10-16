const std = @import("std");
const builtin = @import("builtin");
const wire = @import("../internal/wire.zig");
const http1 = @import("../http1/mod.zig");
const deflate = @import("../internal/deflate.zig");
const compression_context = @import("compression_context.zig");

pub const runtime = @import("runtime.zig");
pub const CompressionContext = compression_context.CompressionContext;
pub const DecompressionContext = compression_context.DecompressionContext;

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

    /// Return the complete encoded frame length without permitting a
    /// peer-provided payload length to wrap the platform `usize` boundary.
    pub fn wireLen(self: FrameHeader) Error!usize {
        const payload_len = std.math.cast(usize, self.payload_len) orelse
            return error.PayloadTooLarge;
        return std.math.add(usize, self.header_len, payload_len) catch
            error.PayloadTooLarge;
    }

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

    pub const Policy = struct {
        enable_permessage_deflate: bool = false,
        allow_context_takeover: bool = false,
        /// Server-side selection for the peer's compressor. Emitted only when
        /// the client offered `client_max_window_bits`, and capped by an
        /// explicit client value. Client offer construction ignores this.
        accept_client_max_window_bits: ?u8 = null,
        /// Server-side limit for its own compressor. RFC 7692 permits this
        /// selection even when the client omitted the parameter; an offered
        /// maximum remains authoritative. Client offer construction ignores
        /// this field.
        accept_server_max_window_bits: ?u8 = null,
    };

    pub fn offerValue(policy: Policy) ?[]const u8 {
        if (!policy.enable_permessage_deflate) return null;
        return if (policy.allow_context_takeover)
            "permessage-deflate"
        else
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover";
    }

    pub fn parseOffer(header_value: []const u8) Error!ExtensionNegotiation {
        const parsed = try parseOfferPart(header_value);
        if (!parsed.saw_member) return error.InvalidExtension;
        return parsed.negotiation;
    }

    const ParsedOffer = struct {
        negotiation: ExtensionNegotiation,
        saw_member: bool,
    };

    fn parseOfferPart(header_value: []const u8) Error!ParsedOffer {
        var parser = ExtensionListParser.init(header_value);
        var selected = ExtensionNegotiation{};
        while (try parser.next(.offer)) |extension| {
            switch (extension) {
                .unknown, .declined => {},
                .permessage_deflate => |offer| {
                    if (!selected.permessage_deflate) selected = offer;
                },
            }
        }
        return .{
            .negotiation = selected,
            .saw_member = parser.saw_member,
        };
    }

    fn parseClientHeaders(headers: anytype) Error!ExtensionNegotiation {
        var saw_field = false;
        var saw_member = false;
        var selected = ExtensionNegotiation{};
        for (headers) |header| {
            if (!std.ascii.eqlIgnoreCase(
                header.name,
                "sec-websocket-extensions",
            )) continue;
            saw_field = true;
            const parsed = try parseOfferPart(header.value);
            saw_member = saw_member or parsed.saw_member;
            if (!selected.permessage_deflate and
                parsed.negotiation.permessage_deflate)
            {
                selected = parsed.negotiation;
            }
        }
        if (saw_field and !saw_member) return error.InvalidExtension;
        return selected;
    }

    pub fn accept(allocator: std.mem.Allocator, offer_header: ?[]const u8, enable_permessage_deflate: bool) Error!?[]u8 {
        return acceptWithPolicy(allocator, offer_header, .{
            .enable_permessage_deflate = enable_permessage_deflate,
        });
    }

    pub fn acceptWithPolicy(
        allocator: std.mem.Allocator,
        offer_header: ?[]const u8,
        policy: Policy,
    ) Error!?[]u8 {
        const raw = offer_header orelse return null;
        const offer = try parseOffer(raw);
        return acceptParsedWithPolicy(allocator, offer, policy);
    }

    fn acceptParsedWithPolicy(
        allocator: std.mem.Allocator,
        offer: ExtensionNegotiation,
        policy: Policy,
    ) Error!?[]u8 {
        try validatePolicy(policy);
        if (!policy.enable_permessage_deflate) return null;
        if (!offer.permessage_deflate) return null;

        var value: std.ArrayList(u8) = .empty;
        errdefer value.deinit(allocator);
        try value.appendSlice(allocator, "permessage-deflate");
        if (!policy.allow_context_takeover or
            offer.server_no_context_takeover)
        {
            try value.appendSlice(allocator, "; server_no_context_takeover");
        }
        if (!policy.allow_context_takeover or
            offer.client_no_context_takeover)
        {
            try value.appendSlice(allocator, "; client_no_context_takeover");
        }
        if (policy.accept_client_max_window_bits) |configured| {
            if (offer.client_max_window_bits) |offered| {
                var writer = std.Io.Writer.Allocating.fromArrayList(
                    allocator,
                    &value,
                );
                defer value = writer.toArrayList();
                try writer.writer.print(
                    "; client_max_window_bits={d}",
                    .{@min(configured, offered)},
                );
            }
        }
        const server_max_window_bits = if (policy.accept_server_max_window_bits) |configured|
            if (offer.server_max_window_bits) |offered|
                @min(configured, offered)
            else
                configured
        else
            offer.server_max_window_bits;
        if (server_max_window_bits) |bits| {
            var writer = std.Io.Writer.Allocating.fromArrayList(
                allocator,
                &value,
            );
            defer value = writer.toArrayList();
            try writer.writer.print(
                "; server_max_window_bits={d}",
                .{bits},
            );
        }
        return try value.toOwnedSlice(allocator);
    }

    pub fn acceptClientHeaders(
        allocator: std.mem.Allocator,
        headers: anytype,
        enable_permessage_deflate: bool,
    ) Error!?[]u8 {
        return acceptClientHeadersWithPolicy(allocator, headers, .{
            .enable_permessage_deflate = enable_permessage_deflate,
        });
    }

    pub fn acceptClientHeadersWithPolicy(
        allocator: std.mem.Allocator,
        headers: anytype,
        policy: Policy,
    ) Error!?[]u8 {
        const selected = try parseClientHeaders(headers);
        return acceptParsedWithPolicy(allocator, selected, policy);
    }

    pub fn validateResponse(header_value: ?[]const u8) Error!ExtensionNegotiation {
        return validateResponseWithPolicy(header_value, .{
            .enable_permessage_deflate = true,
        });
    }

    pub fn validateResponseWithPolicy(
        header_value: ?[]const u8,
        policy: Policy,
    ) Error!ExtensionNegotiation {
        try validatePolicy(policy);
        const raw = header_value orelse return .{};
        if (!policy.enable_permessage_deflate) return error.InvalidExtension;
        var negotiated: ?ExtensionNegotiation = null;
        try mergeResponseValue(raw, policy, &negotiated);
        return negotiated orelse error.InvalidExtension;
    }

    /// Validate all repeated Sec-WebSocket-Extensions response fields as one
    /// HTTP list.
    pub fn validateResponseHeadersWithPolicy(
        headers: anytype,
        policy: Policy,
    ) Error!ExtensionNegotiation {
        try validatePolicy(policy);
        var saw_header = false;
        var negotiated: ?ExtensionNegotiation = null;
        for (headers) |header| {
            if (!std.ascii.eqlIgnoreCase(
                header.name,
                "sec-websocket-extensions",
            )) continue;
            saw_header = true;
            if (!policy.enable_permessage_deflate) {
                return error.InvalidExtension;
            }
            try mergeResponseValue(header.value, policy, &negotiated);
        }
        if (!saw_header) return .{};
        return negotiated orelse error.InvalidExtension;
    }

    /// Validate repeated response fields and bind the selected extension to
    /// the client's exact offer.
    pub fn validateResponseHeadersForOfferWithPolicy(
        headers: anytype,
        offer_header: ?[]const u8,
        policy: Policy,
    ) Error!ExtensionNegotiation {
        const response = try validateResponseHeadersWithPolicy(
            headers,
            policy,
        );
        return validateResponseAgainstOffer(response, offer_header);
    }

    fn mergeResponseValue(
        raw: []const u8,
        policy: Policy,
        negotiated: *?ExtensionNegotiation,
    ) Error!void {
        var parser = ExtensionListParser.init(raw);
        while (try parser.next(.response)) |extension| {
            switch (extension) {
                .unknown, .declined => return error.InvalidExtension,
                .permessage_deflate => |parsed| {
                    if (negotiated.* != null) return error.InvalidExtension;
                    if (!policy.allow_context_takeover and
                        (!parsed.client_no_context_takeover or
                            !parsed.server_no_context_takeover))
                    {
                        return error.InvalidExtension;
                    }
                    negotiated.* = parsed;
                },
            }
        }
    }

    fn validatePolicy(policy: Policy) Error!void {
        for ([_]?u8{
            policy.accept_client_max_window_bits,
            policy.accept_server_max_window_bits,
        }) |maybe_bits| {
            if (maybe_bits) |bits| {
                if (bits < 8 or bits > 15) return error.InvalidExtension;
                if (!policy.enable_permessage_deflate) {
                    return error.InvalidExtension;
                }
            }
        }
    }

    /// Validate a server selection against the exact extension offer sent by
    /// the client. RFC 7692 permits a server to add either no-context flag and
    /// to choose server_max_window_bits without an offer parameter, but it
    /// forbids an unsolicited client_max_window_bits. An offered
    /// client_max_window_bits value is only a hint, while an offered
    /// server_max_window_bits value is a hard upper bound.
    pub fn validateResponseForOfferWithPolicy(
        header_value: ?[]const u8,
        offer_header: ?[]const u8,
        policy: Policy,
    ) Error!ExtensionNegotiation {
        const response = try validateResponseWithPolicy(header_value, policy);
        return validateResponseAgainstOffer(response, offer_header);
    }

    fn validateResponseAgainstOffer(
        response: ExtensionNegotiation,
        offer_header: ?[]const u8,
    ) Error!ExtensionNegotiation {
        if (!response.permessage_deflate) return response;

        const raw_offer = offer_header orelse return error.InvalidExtension;
        var matched = false;
        var parser = ExtensionListParser.init(raw_offer);
        while (try parser.next(.offer)) |extension| {
            switch (extension) {
                .unknown, .declined => {},
                .permessage_deflate => |offer| {
                    if (response.client_max_window_bits != null and
                        offer.client_max_window_bits == null)
                    {
                        continue;
                    }
                    if (response.server_max_window_bits) |selected| {
                        if (offer.server_max_window_bits) |maximum| {
                            if (selected > maximum) continue;
                        }
                    } else if (offer.server_max_window_bits != null) {
                        continue;
                    }
                    matched = true;
                },
            }
        }
        return if (matched) response else error.InvalidExtension;
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
pub const max_frame_payload_len: u64 = std.math.maxInt(u63);

pub fn parseFrame(allocator: std.mem.Allocator, bytes: []const u8) Error!Frame {
    return parseFrameOptions(allocator, bytes, .{});
}

pub fn parseFrameOptions(allocator: std.mem.Allocator, bytes: []const u8, options: ParseFrameOptions) Error!Frame {
    const header = try FrameHeader.parse(bytes);
    return parseFrameWithHeader(allocator, bytes, header, options);
}

/// Decode a complete frame after the caller has already parsed its header.
/// Streaming runtimes use this after buffering exactly `header_len +
/// payload_len`, avoiding a second variable-length header parse.
pub fn parseFrameWithHeader(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    header: FrameHeader,
    options: ParseFrameOptions,
) Error!Frame {
    try validateFrameHeader(header, options);
    const consumed = try header.wireLen();
    if (bytes.len < consumed) return error.BufferTooShort;
    const payload = try allocator.dupe(u8, bytes[header.header_len..consumed]);
    errdefer allocator.free(payload);
    if (header.mask_key) |mask| applyMask(payload, mask, 0);
    try validatePayload(header, payload, options);
    return .{ .header = header, .payload = payload, .consumed = consumed };
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
    return parseFrameIntoWithHeader(out, bytes, header, options);
}

/// Caller-buffer counterpart to `parseFrameWithHeader`.
pub fn parseFrameIntoWithHeader(
    out: []u8,
    bytes: []const u8,
    header: FrameHeader,
    options: ParseFrameOptions,
) Error!BorrowedFrame {
    try validateFrameHeader(header, options);
    const consumed = try header.wireLen();
    const payload_len = consumed - header.header_len;
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

/// Decode one complete frame in caller-owned mutable wire storage. The
/// returned payload aliases `bytes`, so it remains valid only while that
/// storage is unchanged. Stream runtimes use this to feed message assembly
/// without allocating an intermediate payload for every fragment.
pub fn parseFrameInPlaceWithHeader(
    bytes: []u8,
    header: FrameHeader,
    options: ParseFrameOptions,
) Error!BorrowedFrame {
    try validateFrameHeader(header, options);
    const consumed = try header.wireLen();
    if (bytes.len < consumed) return error.BufferTooShort;
    const payload = bytes[header.header_len..consumed];
    if (header.mask_key) |mask| applyMask(payload, mask, 0);
    try validatePayload(header, payload, options);
    return .{
        .header = header,
        .payload = payload,
        .consumed = consumed,
    };
}

pub fn validateFrameHeader(header: FrameHeader, options: ParseFrameOptions) Error!void {
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

/// Incremental RFC 3629 validator for fragmented or partially received text.
/// In addition to rejecting bad lead/continuation bytes, the first continuation
/// range rejects overlong encodings, surrogate halves, and values above
/// U+10FFFF as soon as the decisive byte arrives.
pub const Utf8Validator = struct {
    remaining: u3 = 0,
    next_min: u8 = 0x80,
    next_max: u8 = 0xbf,

    pub fn reset(self: *Utf8Validator) void {
        self.* = .{};
    }

    pub fn feed(self: *Utf8Validator, bytes: []const u8) Error!void {
        var offset: usize = if (self.remaining == 0)
            asciiPrefixLen(bytes)
        else
            0;
        while (offset < bytes.len) {
            try self.feedByte(bytes[offset]);
            offset += 1;
            if (self.remaining == 0) {
                offset += asciiPrefixLen(bytes[offset..]);
            }
        }
    }

    pub fn feedByte(self: *Utf8Validator, byte: u8) Error!void {
        if (self.remaining != 0) {
            if (byte < self.next_min or byte > self.next_max) {
                return error.InvalidUtf8;
            }
            self.remaining -= 1;
            self.next_min = 0x80;
            self.next_max = 0xbf;
            return;
        }

        switch (byte) {
            0x00...0x7f => {},
            0xc2...0xdf => self.remaining = 1,
            0xe0 => {
                self.remaining = 2;
                self.next_min = 0xa0;
            },
            0xe1...0xec, 0xee...0xef => self.remaining = 2,
            0xed => {
                self.remaining = 2;
                self.next_max = 0x9f;
            },
            0xf0 => {
                self.remaining = 3;
                self.next_min = 0x90;
            },
            0xf1...0xf3 => self.remaining = 3,
            0xf4 => {
                self.remaining = 3;
                self.next_max = 0x8f;
            },
            else => return error.InvalidUtf8,
        }
    }

    /// Validate a masked wire slice without materializing an unmasked copy.
    /// ASCII blocks are XORed and tested as vectors; a non-ASCII block falls
    /// back to the incremental byte state machine and resumes the fast path
    /// after the code point completes.
    pub fn feedMasked(
        self: *Utf8Validator,
        bytes: []const u8,
        mask_key: [4]u8,
        mask_offset: usize,
    ) Error!void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            if (self.remaining == 0) {
                offset += maskedAsciiPrefixLen(
                    bytes[offset..],
                    mask_key,
                    mask_offset + offset,
                );
                if (offset == bytes.len) return;
            }
            try self.feedByte(
                bytes[offset] ^ mask_key[(mask_offset + offset) & 3],
            );
            offset += 1;
        }
    }

    /// Copy, unmask, and validate one wire slice in a single pass. `output`
    /// may alias `bytes` exactly, allowing transport reads to land in their
    /// final destination before in-place decoding.
    pub fn feedMaskedCopy(
        self: *Utf8Validator,
        output: []u8,
        bytes: []const u8,
        mask_key: [4]u8,
        mask_offset: usize,
    ) Error!void {
        if (output.len < bytes.len) return error.BufferTooShort;
        const destination = output[0..bytes.len];
        const rotated = rotatedMask(mask_key, mask_offset);
        var offset: usize = 0;
        var saw_non_ascii = self.remaining != 0;
        if (comptime backend_supports_vectors) {
            const vector_size =
                std.simd.suggestVectorLength(u8) orelse @sizeOf(usize);
            if (comptime vector_size % mask_key.len == 0) {
                const high_bits: @Vector(vector_size, u8) = @splat(0x80);
                const mask_vector = std.simd.repeat(
                    vector_size,
                    @as(@Vector(4, u8), rotated),
                );
                var seen_high_bits: @Vector(vector_size, u8) = @splat(0);
                while (bytes.len - offset >= vector_size) {
                    const decoded: @Vector(vector_size, u8) =
                        bytes[offset..][0..vector_size].* ^ mask_vector;
                    destination[offset..][0..vector_size].* = decoded;
                    seen_high_bits |= decoded & high_bits;
                    offset += vector_size;
                }
                saw_non_ascii = saw_non_ascii or
                    @reduce(.Or, seen_high_bits) != 0;
            }
        }
        while (offset < bytes.len) : (offset += 1) {
            const decoded = bytes[offset] ^ rotated[offset & 3];
            destination[offset] = decoded;
            saw_non_ascii = saw_non_ascii or decoded >= 0x80;
        }
        if (saw_non_ascii) try self.feed(destination);
    }

    pub fn finish(self: Utf8Validator) Error!void {
        if (self.remaining != 0) return error.InvalidUtf8;
    }
};

inline fn asciiPrefixLen(bytes: []const u8) usize {
    var offset: usize = 0;
    if (comptime backend_supports_vectors) {
        const vector_size = std.simd.suggestVectorLength(u8) orelse
            @sizeOf(usize);
        const high_bits: @Vector(vector_size, u8) = @splat(0x80);
        while (bytes.len - offset >= vector_size) {
            const block: @Vector(vector_size, u8) =
                bytes[offset..][0..vector_size].*;
            if (@reduce(.Or, block & high_bits) != 0) break;
            offset += vector_size;
        }
    }
    while (offset < bytes.len and bytes[offset] < 0x80) : (offset += 1) {}
    return offset;
}

inline fn maskedAsciiPrefixLen(
    bytes: []const u8,
    mask_key: [4]u8,
    mask_offset: usize,
) usize {
    const rotated = rotatedMask(mask_key, mask_offset);
    var offset: usize = 0;
    if (comptime backend_supports_vectors) {
        const vector_size = std.simd.suggestVectorLength(u8) orelse
            @sizeOf(usize);
        const high_bits: @Vector(vector_size, u8) = @splat(0x80);
        const mask_vector = std.simd.repeat(
            vector_size,
            @as(@Vector(4, u8), rotated),
        );
        while (bytes.len - offset >= vector_size) {
            const block: @Vector(vector_size, u8) =
                bytes[offset..][0..vector_size].* ^ mask_vector;
            if (@reduce(.Or, block & high_bits) != 0) break;
            offset += vector_size;
        }
    }
    while (offset < bytes.len and
        (bytes[offset] ^ rotated[offset & 3]) < 0x80) : (offset += 1)
    {}
    return offset;
}

test "WebSocket incremental UTF-8 validator rejects decisive bytes" {
    var validator: Utf8Validator = .{};
    try validator.feed("valid \xe2");
    try validator.feed("\x82");
    try validator.feed("\xac text");
    try validator.finish();

    validator.reset();
    try validator.feedByte(0xf4);
    try std.testing.expectError(error.InvalidUtf8, validator.feedByte(0x90));

    validator.reset();
    try validator.feedByte(0xed);
    try std.testing.expectError(error.InvalidUtf8, validator.feedByte(0xa0));

    validator.reset();
    try validator.feedByte(0xe0);
    try std.testing.expectError(error.InvalidUtf8, validator.feedByte(0x9f));

    validator.reset();
    try validator.feedByte(0xf0);
    try std.testing.expectError(error.InvalidUtf8, validator.finish());
}

test "WebSocket incremental UTF-8 validator skips ASCII blocks safely" {
    var validator: Utf8Validator = .{};
    const ascii = "abcdefghijklmnopqrstuvwxyz0123456789" ** 8;
    try validator.feed(ascii);
    try validator.finish();

    validator.reset();
    try validator.feed(ascii ++ "\xe2");
    try validator.feed("\x82");
    try validator.feed("\xac" ++ ascii);
    try validator.finish();

    validator.reset();
    const invalid = ascii ++ "\xff" ++ ascii;
    try std.testing.expectError(error.InvalidUtf8, validator.feed(invalid));

    var storage = [_]u8{'x'} ** 96;
    for (0..64) |offset| {
        @memset(&storage, 'x');
        @memcpy(storage[offset..][0..3], "\xe2\x98\x83");
        validator.reset();
        try validator.feed(&storage);
        try validator.finish();

        storage[offset] = 0xff;
        validator.reset();
        try std.testing.expectError(
            error.InvalidUtf8,
            validator.feed(&storage),
        );
    }
}

test "WebSocket incremental UTF-8 validator handles masked offsets" {
    const key = [4]u8{ 0x12, 0x34, 0x56, 0x78 };
    var storage = [_]u8{'a'} ** 96;
    @memcpy(storage[31..34], "\xe2\x98\x83");
    const plain = storage;
    for (0..4) |mask_offset| {
        storage = plain;
        applyMask(&storage, key, mask_offset);
        var validator: Utf8Validator = .{};
        try validator.feedMasked(&storage, key, mask_offset);
        try validator.finish();

        storage = plain;
        storage[63] = 0xff;
        applyMask(&storage, key, mask_offset);
        validator.reset();
        try std.testing.expectError(
            error.InvalidUtf8,
            validator.feedMasked(&storage, key, mask_offset),
        );
    }

    var split = [_]u8{ 0xe2, 0x98, 0x83 };
    applyMask(&split, key, 3);
    var validator: Utf8Validator = .{};
    try validator.feedMasked(split[0..1], key, 3);
    try validator.feedMasked(split[1..2], key, 4);
    try validator.feedMasked(split[2..3], key, 5);
    try validator.finish();
}

test "WebSocket masked UTF-8 copy validates in one pass" {
    const key = [4]u8{ 0x12, 0x34, 0x56, 0x78 };
    const plain = ("vector-ascii-" ** 8) ++ "snowman: \xe2\x98\x83";
    for (0..4) |mask_offset| {
        var encoded = plain.*;
        applyMask(&encoded, key, mask_offset);
        var output: [plain.len]u8 = undefined;
        var validator: Utf8Validator = .{};
        try validator.feedMaskedCopy(
            &output,
            &encoded,
            key,
            mask_offset,
        );
        try validator.finish();
        try std.testing.expectEqualStrings(plain, &output);

        validator.reset();
        try validator.feedMaskedCopy(
            &encoded,
            &encoded,
            key,
            mask_offset,
        );
        try validator.finish();
        try std.testing.expectEqualStrings(plain, &encoded);
    }

    var invalid = [_]u8{ 0xf4, 0x90 };
    applyMask(&invalid, key, 3);
    var output: [invalid.len]u8 = undefined;
    var validator: Utf8Validator = .{};
    try std.testing.expectError(
        error.InvalidUtf8,
        validator.feedMaskedCopy(&output, &invalid, key, 3),
    );

    var split = [_]u8{ 0xe2, 0x98, 0x83 };
    applyMask(&split, key, 3);
    var decoded: [split.len]u8 = undefined;
    validator.reset();
    try validator.feedMaskedCopy(decoded[0..1], split[0..1], key, 3);
    try validator.feedMaskedCopy(decoded[1..2], split[1..2], key, 4);
    try validator.feedMaskedCopy(decoded[2..3], split[2..3], key, 5);
    try validator.finish();
    try std.testing.expectEqualStrings("\xe2\x98\x83", &decoded);
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
    var storage: [125]u8 = undefined;
    const payload = try writeClosePayloadInto(&storage, close_frame);
    try list.appendSlice(allocator, payload);
}

/// Encode a Close payload into caller-owned RFC 6455 control-frame storage.
/// The returned slice aliases `storage` and is valid until that storage is
/// reused. This lets runtimes send Close without a transient heap allocation.
pub fn writeClosePayloadInto(
    storage: *[125]u8,
    close_frame: ?CloseFrame,
) Error![]const u8 {
    const frame = close_frame orelse return storage[0..0];
    if (!validCloseCode(frame.code)) return error.InvalidCloseCode;
    if (!std.unicode.utf8ValidateSlice(frame.reason)) return error.InvalidUtf8;
    if (frame.reason.len > 123) return error.InvalidControlFrame;
    std.mem.writeInt(u16, storage[0..2], @intFromEnum(frame.code), .big);
    @memcpy(storage[2..][0..frame.reason.len], frame.reason);
    return storage[0 .. 2 + frame.reason.len];
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
    return writeFrameHeaderForLengthAssumeValid(
        storage,
        opcode,
        payload.len,
        options,
    );
}

/// Encode a frame header for a payload supplied as multiple transport slices.
/// Validation that depends on payload contents (text UTF-8 and Close syntax)
/// remains the caller's responsibility; this API is intended for binary data.
pub fn writeFrameHeaderForLengthInto(
    storage: *[max_frame_header_len]u8,
    opcode: Opcode,
    payload_len: usize,
    options: WriteFrameOptions,
) Error![]const u8 {
    switch (opcode) {
        .continuation, .text, .binary, .close, .ping, .pong => {},
        else => return error.InvalidOpcode,
    }
    if (opcode.isControl()) {
        if (!options.fin or payload_len > 125) {
            return error.InvalidControlFrame;
        }
        if (options.rsv1 or options.rsv2 or options.rsv3) {
            return error.UnexpectedRsv;
        }
    }
    if (opcode == .continuation and
        (options.rsv1 or options.rsv2 or options.rsv3))
    {
        return error.UnexpectedRsv;
    }
    return writeFrameHeaderForLengthAssumeValid(
        storage,
        opcode,
        payload_len,
        options,
    );
}

fn writeFrameHeaderForLengthAssumeValid(
    storage: *[max_frame_header_len]u8,
    opcode: Opcode,
    payload_len: usize,
    options: WriteFrameOptions,
) Error![]const u8 {
    const payload_len_u64 = std.math.cast(u64, payload_len) orelse
        return error.PayloadTooLarge;
    if (payload_len_u64 > max_frame_payload_len) {
        return error.PayloadTooLarge;
    }
    storage[0] = (if (options.fin) @as(u8, 0x80) else 0) |
        (if (options.rsv1) @as(u8, 0x40) else 0) |
        (if (options.rsv2) @as(u8, 0x20) else 0) |
        (if (options.rsv3) @as(u8, 0x10) else 0) |
        @intFromEnum(opcode);
    const masked_bit: u8 = if (options.mask_key != null) 0x80 else 0;
    var pos: usize = 2;
    if (payload_len <= 125) {
        storage[1] = masked_bit | @as(u8, @intCast(payload_len));
    } else if (payload_len <= std.math.maxInt(u16)) {
        storage[1] = masked_bit | 126;
        std.mem.writeInt(u16, storage[2..4], @intCast(payload_len), .big);
        pos = 4;
    } else {
        storage[1] = masked_bit | 127;
        std.mem.writeInt(u64, storage[2..10], payload_len_u64, .big);
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
    try validateHttp1UpgradeHeaders(req.headers);
    const version = try requiredSingletonHeader(req.headers, "sec-websocket-version");
    if (!std.mem.eql(u8, version, "13")) return error.InvalidHandshake;
    const key = try requiredSingletonHeader(req.headers, "sec-websocket-key");
    try validateClientKey(key);
    try validateClientSubprotocolHeaders(req.headers);
    try validateClientExtensionHeaders(req.headers);
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

const HeaderListMatch = struct {
    present: bool = false,
    matched: bool = false,
};

fn validUpgradeProtocol(protocol: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, protocol, '/') orelse
        return validSubprotocolToken(protocol);
    if (slash == 0 or slash + 1 == protocol.len or
        std.mem.indexOfScalar(u8, protocol[slash + 1 ..], '/') != null)
    {
        return false;
    }
    return validSubprotocolToken(protocol[0..slash]) and
        validSubprotocolToken(protocol[slash + 1 ..]);
}

fn headerListMatch(
    headers: []const http1.Header,
    name: []const u8,
    expected: []const u8,
    comptime upgrade_protocol: bool,
) Error!HeaderListMatch {
    var result: HeaderListMatch = .{};
    for (headers) |header| {
        if (!header.eqlName(name)) continue;
        result.present = true;
        var values = std.mem.splitScalar(u8, header.value, ',');
        while (values.next()) |raw_value| {
            const value = wire.trimOws(raw_value);
            if (value.len == 0) continue;
            const valid = if (upgrade_protocol)
                validUpgradeProtocol(value)
            else
                validSubprotocolToken(value);
            if (!valid) return error.InvalidHandshake;
            if (std.ascii.eqlIgnoreCase(value, expected)) {
                result.matched = true;
            }
        }
    }
    return result;
}

/// Validate repeated HTTP/1 Upgrade and Connection fields as list-valued
/// fields. RFC 6455 requires `websocket` and `upgrade` tokens respectively;
/// unrelated valid protocols and connection options remain interoperable.
pub fn validateHttp1UpgradeHeaders(headers: []const http1.Header) Error!void {
    const upgrade = try headerListMatch(
        headers,
        "upgrade",
        "websocket",
        true,
    );
    if (!upgrade.present) return error.MissingHeader;
    if (!upgrade.matched) return error.InvalidHandshake;

    const connection = try headerListMatch(
        headers,
        "connection",
        "upgrade",
        false,
    );
    if (!connection.present) return error.MissingHeader;
    if (!connection.matched) return error.InvalidHandshake;
}

pub fn validateClientKey(key: []const u8) Error!void {
    if (key.len != 24) return error.InvalidHandshake;
    var nonce: [16]u8 = undefined;
    std.base64.standard.Decoder.decode(&nonce, key) catch return error.InvalidHandshake;
}

fn validateClientSubprotocolHeaders(headers: []const http1.Header) Error!void {
    var saw_header = false;
    var token_index: usize = 0;
    for (headers) |header| {
        if (!header.eqlName("sec-websocket-protocol")) continue;
        saw_header = true;
        var protocols = std.mem.splitScalar(u8, header.value, ',');
        while (protocols.next()) |raw_protocol| {
            const protocol = wire.trimOws(raw_protocol);
            if (protocol.len == 0) continue;
            if (!validSubprotocolToken(protocol)) return error.InvalidHandshake;
            if (subprotocolTokenSeenBefore(headers, token_index, protocol)) return error.InvalidHandshake;
            token_index += 1;
        }
    }
    if (saw_header and token_index == 0) return error.InvalidHandshake;
}

fn validateClientExtensionHeaders(headers: []const http1.Header) Error!void {
    _ = try ExtensionNegotiation.parseClientHeaders(headers);
}

fn subprotocolTokenSeenBefore(headers: []const http1.Header, before_index: usize, candidate: []const u8) bool {
    var seen: usize = 0;
    for (headers) |header| {
        if (!header.eqlName("sec-websocket-protocol")) continue;
        var protocols = std.mem.splitScalar(u8, header.value, ',');
        while (protocols.next()) |raw_protocol| {
            const protocol = wire.trimOws(raw_protocol);
            if (protocol.len == 0) continue;
            if (seen >= before_index) return false;
            if (std.mem.eql(u8, protocol, candidate)) return true;
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
    const response_prefix =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
    const key = acceptKey(client_key);
    var response_len = response_prefix.len + key.len;
    response_len = std.math.add(usize, response_len, 2) catch
        return error.PayloadTooLarge;
    for (extra_headers) |header| {
        response_len = std.math.add(usize, response_len, header.name.len) catch
            return error.PayloadTooLarge;
        response_len = std.math.add(usize, response_len, 2) catch
            return error.PayloadTooLarge;
        response_len = std.math.add(usize, response_len, header.value.len) catch
            return error.PayloadTooLarge;
        response_len = std.math.add(usize, response_len, 2) catch
            return error.PayloadTooLarge;
    }
    response_len = std.math.add(usize, response_len, 2) catch
        return error.PayloadTooLarge;

    try list.ensureUnusedCapacity(allocator, response_len);
    list.appendSliceAssumeCapacity(response_prefix);
    list.appendSliceAssumeCapacity(&key);
    list.appendSliceAssumeCapacity("\r\n");
    for (extra_headers) |header| {
        list.appendSliceAssumeCapacity(header.name);
        list.appendSliceAssumeCapacity(": ");
        list.appendSliceAssumeCapacity(header.value);
        list.appendSliceAssumeCapacity("\r\n");
    }
    list.appendSliceAssumeCapacity("\r\n");
}

fn validateServerHandshakeHeaders(headers: []const wire.Header) !void {
    var saw_protocol = false;
    var saw_extensions = false;
    for (headers) |header| {
        try http1.validateHeader(header);
        if (header.eqlName("upgrade") or
            header.eqlName("connection") or
            header.eqlName("sec-websocket-accept") or
            header.eqlName("content-length") or
            header.eqlName("transfer-encoding") or
            header.eqlName("trailer"))
        {
            // The writer owns the mandatory fields, while a 101 response cannot
            // carry HTTP/1 message framing. Reject both groups before output.
            return error.InvalidHandshake;
        }
        if (header.eqlName("sec-websocket-protocol")) {
            if (saw_protocol) return error.InvalidHandshake;
            saw_protocol = true;
            if (!validSubprotocolToken(wire.trimOws(header.value))) return error.InvalidHandshake;
        } else if (header.eqlName("sec-websocket-extensions")) {
            if (saw_extensions) return error.InvalidHandshake;
            saw_extensions = true;
            _ = try ExtensionNegotiation.validateResponseWithPolicy(
                header.value,
                .{
                    .enable_permessage_deflate = true,
                    .allow_context_takeover = true,
                },
            );
        }
    }
}

pub const MessageAssembler = struct {
    allocator: std.mem.Allocator,
    max_message_bytes: usize = std.math.maxInt(usize),
    opcode: ?Opcode = null,
    compressed: bool = false,
    text_utf8: Utf8Validator = .{},
    buffer: std.ArrayList(u8) = .empty,

    pub const Message = struct {
        opcode: Opcode,
        payload: []u8,
        compressed: bool = false,
        /// The assembler incrementally validated this uncompressed text.
        /// This is internal protocol evidence, not a caller assertion; runtime
        /// finalization skips its otherwise redundant full-message scan only
        /// for values produced by `feed`.
        utf8_validated: bool = false,
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
        return self.feedInternal(frame, null);
    }

    /// Assemble a frame whose uncompressed text bytes were already checked by
    /// a transport-level incremental validator. The supplied state is copied
    /// into the assembler so continuation boundaries and final completeness
    /// retain the same proof without rescanning the frame payload.
    pub fn feedUtf8Validated(
        self: *MessageAssembler,
        frame: anytype,
        text_utf8: Utf8Validator,
    ) !?Message {
        return self.feedInternal(frame, text_utf8);
    }

    fn feedInternal(
        self: *MessageAssembler,
        frame: anytype,
        validated_text_utf8: ?Utf8Validator,
    ) !?Message {
        if (frame.header.opcode.isControl()) return null;
        if (frame.header.opcode != .continuation) {
            if (self.opcode != null) return error.InvalidFrame;
            self.opcode = frame.header.opcode;
            self.compressed = frame.header.rsv1;
            self.text_utf8.reset();
            self.buffer.clearRetainingCapacity();
        } else if (self.opcode == null) {
            return error.InvalidFrame;
        } else if (frame.header.rsv1) {
            return error.UnexpectedRsv;
        }
        if (frame.header.fin and self.buffer.items.len == 0 and
            self.buffer.capacity < frame.payload.len)
        {
            if (frame.payload.len > self.max_message_bytes) {
                return error.PayloadTooLarge;
            }
            if (self.opcode == .text and !self.compressed) {
                if (validated_text_utf8) |validator| {
                    self.text_utf8 = validator;
                } else {
                    try self.text_utf8.feed(frame.payload);
                }
                try self.text_utf8.finish();
            }
            const payload = try self.allocator.dupe(u8, frame.payload);
            const opcode = self.opcode.?;
            const compressed = self.compressed;
            self.opcode = null;
            self.compressed = false;
            self.text_utf8.reset();
            return .{
                .opcode = opcode,
                .payload = payload,
                .compressed = compressed,
                .utf8_validated = opcode == .text and !compressed,
            };
        }
        // A fragmented message can be split into many individually-valid
        // frames.  Bound the aggregate payload, not only the current frame, so
        // peers cannot bypass runtime limits with many small fragments.
        const new_len = std.math.add(usize, self.buffer.items.len, frame.payload.len) catch return error.PayloadTooLarge;
        if (new_len > self.max_message_bytes) return error.PayloadTooLarge;
        try self.buffer.appendSlice(self.allocator, frame.payload);
        if (self.opcode == .text and !self.compressed) {
            if (validated_text_utf8) |validator| {
                self.text_utf8 = validator;
            } else {
                try self.text_utf8.feed(frame.payload);
            }
            if (frame.header.fin) try self.text_utf8.finish();
        }
        if (!frame.header.fin) return null;
        const payload = try self.buffer.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(payload);
        const opcode = self.opcode.?;
        const compressed = self.compressed;
        self.opcode = null;
        self.compressed = false;
        self.text_utf8.reset();
        self.buffer = .empty;
        return .{
            .opcode = opcode,
            .payload = payload,
            .compressed = compressed,
            .utf8_validated = opcode == .text and !compressed,
        };
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

    try removeCompressionTail(&allocating);
    return allocating.written();
}

pub fn compressMessageVortInto(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    payload: []const u8,
) Error![]const u8 {
    return compressMessageVortIntoWindow(
        output,
        allocator,
        payload,
        15,
    );
}

/// Encode one no-context-takeover message while bounding every LZ77 distance
/// to the window negotiated by RFC 7692. Using a smaller search window is
/// sufficient for raw DEFLATE because the format carries distances, not an
/// independent window declaration.
pub fn compressMessageVortIntoWindow(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    payload: []const u8,
    max_window_bits: u8,
) Error![]const u8 {
    output.clearRetainingCapacity();
    _ = deflate.encodeRawFixedSyncFlushAppend(
        allocator,
        output,
        payload,
        try vortWebSocketCompressionOptions(max_window_bits),
    ) catch |err| return mapVortCompressionError(err);
    return removeVortCompressionTail(output);
}

pub fn compressMessageVortIntoWindowWithEncoder(
    encoder: *deflate.RawFixedSyncFlushEncoder,
    output: *std.ArrayList(u8),
    payload: []const u8,
    max_window_bits: u8,
) Error![]const u8 {
    output.clearRetainingCapacity();
    _ = encoder.encodeAppend(
        output,
        payload,
        try vortWebSocketCompressionOptions(max_window_bits),
    ) catch |err| return mapVortCompressionError(err);
    return removeVortCompressionTail(output);
}

/// Encode discontiguous RFC 7692 input without joining caller plaintext.
///
/// The encoder feeds all non-empty slices into one non-final fixed-Huffman
/// block followed by one sync-flush block. The bounded hash chain preserves
/// matches across caller-slice boundaries without joining plaintext.
pub fn compressMessageFragmentsVortInto(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fragments: []const []const u8,
) Error![]const u8 {
    return compressMessageFragmentsVortIntoWindow(
        output,
        allocator,
        fragments,
        15,
    );
}

pub fn compressMessageFragmentsVortIntoWindow(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fragments: []const []const u8,
    max_window_bits: u8,
) Error![]const u8 {
    output.clearRetainingCapacity();
    _ = deflate.encodeRawFixedSyncFlushChunksAppend(
        allocator,
        output,
        fragments,
        try vortWebSocketCompressionOptions(max_window_bits),
    ) catch |err| return mapVortCompressionError(err);
    return removeVortCompressionTail(output);
}

pub fn compressMessageFragmentsVortIntoWindowWithEncoder(
    encoder: *deflate.RawFixedSyncFlushEncoder,
    output: *std.ArrayList(u8),
    fragments: []const []const u8,
    max_window_bits: u8,
) Error![]const u8 {
    output.clearRetainingCapacity();
    _ = encoder.encodeChunksAppend(
        output,
        fragments,
        try vortWebSocketCompressionOptions(max_window_bits),
    ) catch |err| return mapVortCompressionError(err);
    return removeVortCompressionTail(output);
}

const vort_websocket_compression_options: deflate.CompressionOptions = .{
    .parser = .hash,
    .lz77_options = .{
        .window_len = 16 * 1024,
        .max_chain = 4,
        .nice_len = 32,
    },
};

fn vortWebSocketCompressionOptions(
    max_window_bits: u8,
) Error!deflate.CompressionOptions {
    if (max_window_bits < 8 or max_window_bits > 15) {
        return error.InvalidExtension;
    }
    var options = vort_websocket_compression_options;
    const negotiated_window = @as(usize, 1) << @intCast(max_window_bits);
    options.lz77_options.window_len = @min(
        options.lz77_options.window_len,
        negotiated_window,
    );
    return options;
}

fn mapVortCompressionError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.WriteFailed,
    };
}

fn removeVortCompressionTail(
    output: *std.ArrayList(u8),
) Error![]const u8 {
    const tail = "\x00\x00\xff\xff";
    if (!std.mem.endsWith(u8, output.items, tail)) {
        return error.WriteFailed;
    }
    output.items.len -= tail.len;
    return output.items;
}

/// Encode fragmented RFC 7692 input without first joining plaintext.
///
/// Fragment boundaries do not reset DEFLATE state: all slices are streamed
/// through one compressor and the caller decides how to split the resulting
/// wire payload into WebSocket continuation frames.
pub fn compressMessageFragmentsInto(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    flate_window: []u8,
    fragments: []const []const u8,
) Error![]const u8 {
    if (flate_window.len < std.compress.flate.max_window_len) {
        return error.BufferTooShort;
    }
    var total: usize = 0;
    for (fragments) |fragment| {
        total = std.math.add(usize, total, fragment.len) catch
            return error.PayloadTooLarge;
    }
    output.clearRetainingCapacity();
    var allocating = std.Io.Writer.Allocating.fromArrayList(
        allocator,
        output,
    );
    defer output.* = allocating.toArrayList();
    try allocating.ensureTotalCapacity(total +| 64);
    var compressor = try std.compress.flate.Compress.init(
        &allocating.writer,
        flate_window[0..std.compress.flate.max_window_len],
        .raw,
        .fastest,
    );
    for (fragments) |fragment| {
        try compressor.writer.writeAll(fragment);
    }
    try compressor.writer.flush();
    try removeCompressionTail(&allocating);
    return allocating.written();
}

fn removeCompressionTail(
    allocating: *std.Io.Writer.Allocating,
) Error!void {
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
}

pub fn decompressMessage(allocator: std.mem.Allocator, compressed_payload: []const u8, max_message_bytes: usize) Error![]u8 {
    const tail = [_]u8{
        0x00, 0x00, 0xff, 0xff, // RFC 7692 tail restored for the message.
        0x01, 0x00, 0x00, 0xff, 0xff, // Final empty block for the raw inflater.
    };
    const logical_input_len = std.math.add(
        usize,
        compressed_payload.len,
        tail.len,
    ) catch return error.PayloadTooLarge;
    var with_tail = try std.ArrayList(u8).initCapacity(allocator, logical_input_len);
    defer with_tail.deinit(allocator);
    try with_tail.appendSlice(allocator, compressed_payload);
    try with_tail.appendSlice(allocator, &tail);
    return deflate.decodeRawDeflateAllocLimited(
        allocator,
        with_tail.items,
        max_message_bytes,
    ) catch |err| return mapVortDecompressionError(err);
}

/// Inflate one RFC 7692 no-context-takeover message into caller storage.
///
/// Compatibility wrapper for callers that already provide the former Zig
/// inflater window. New code should call `decompressMessageVortInto`, which
/// needs only the compressed scratch slice.
pub fn decompressMessageInto(
    out: []u8,
    compressed_payload: []const u8,
    compressed_scratch: []u8,
    flate_window: []u8,
) Error![]u8 {
    if (flate_window.len < std.compress.flate.max_window_len) {
        return error.BufferTooShort;
    }
    return decompressMessageVortInto(
        out,
        compressed_payload,
        compressed_scratch,
    );
}

/// Inflate one RFC 7692 no-context-takeover message with Vort directly into
/// caller-owned storage. The scratch slice holds only compressed input plus
/// the restored nine-byte suffix; no separate 64-KiB inflater window is used.
pub fn decompressMessageVortInto(
    out: []u8,
    compressed_payload: []const u8,
    compressed_scratch: []u8,
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
    if (compressed_scratch.len < input_len) {
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
    const decoded = deflate.decodeRawDeflate(
        compressed_scratch[0..input_len],
        out,
    ) catch |err| return mapVortDecompressionError(err);
    if (decoded.input_read != input_len) {
        return error.InvalidFrame;
    }
    return out[0..decoded.output_written];
}

fn mapVortDecompressionError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.OutputTooSmall, error.OutputLimitExceeded => error.PayloadTooLarge,
        else => error.InvalidFrame,
    };
}

const ExtensionHeaderRole = enum { offer, response };

const ParsedExtension = union(enum) {
    unknown,
    declined,
    permessage_deflate: ExtensionNegotiation,
};

const ExtensionListParser = struct {
    value: []const u8,
    offset: usize = 0,
    saw_member: bool = false,

    fn init(value: []const u8) ExtensionListParser {
        return .{ .value = value };
    }

    fn next(
        self: *ExtensionListParser,
        role: ExtensionHeaderRole,
    ) Error!?ParsedExtension {
        while (true) {
            skipExtensionOws(self.value, &self.offset);
            if (self.offset == self.value.len) return null;
            if (self.value[self.offset] != ',') break;
            self.offset += 1;
        }

        const extension = try parseExtensionMember(
            self.value,
            &self.offset,
            role,
        );
        self.saw_member = true;
        skipExtensionOws(self.value, &self.offset);
        if (self.offset == self.value.len) return extension;
        if (self.value[self.offset] != ',') return error.InvalidExtension;
        self.offset += 1;
        return extension;
    }
};

fn parseExtensionMember(
    value: []const u8,
    offset: *usize,
    role: ExtensionHeaderRole,
) Error!ParsedExtension {
    const name = try parseExtensionToken(value, offset);
    const is_permessage_deflate =
        std.ascii.eqlIgnoreCase(name, "permessage-deflate");
    var out = ExtensionNegotiation{
        .permessage_deflate = is_permessage_deflate,
    };
    var saw_client_no_context_takeover = false;
    var saw_server_no_context_takeover = false;
    var saw_client_max_window_bits = false;
    var saw_server_max_window_bits = false;
    var acceptable = true;

    while (true) {
        skipExtensionOws(value, offset);
        if (offset.* == value.len or value[offset.*] == ',') break;
        if (value[offset.*] != ';') return error.InvalidExtension;
        offset.* += 1;
        skipExtensionOws(value, offset);
        const param_name = try parseExtensionToken(value, offset);
        skipExtensionOws(value, offset);

        var param_value: ?[]const u8 = null;
        if (offset.* < value.len and value[offset.*] == '=') {
            offset.* += 1;
            skipExtensionOws(value, offset);
            if (offset.* == value.len) return error.InvalidExtension;
            const start = offset.*;
            if (value[offset.*] == '"') {
                try parseExtensionQuotedToken(value, offset);
            } else {
                _ = try parseExtensionToken(value, offset);
            }
            param_value = value[start..offset.*];
            skipExtensionOws(value, offset);
        }
        if (offset.* < value.len and
            value[offset.*] != ';' and
            value[offset.*] != ',')
        {
            return error.InvalidExtension;
        }

        if (!is_permessage_deflate) continue;
        if (std.ascii.eqlIgnoreCase(
            param_name,
            "client_no_context_takeover",
        )) {
            if (param_value != null or saw_client_no_context_takeover) {
                acceptable = false;
            }
            saw_client_no_context_takeover = true;
            out.client_no_context_takeover = true;
        } else if (std.ascii.eqlIgnoreCase(
            param_name,
            "server_no_context_takeover",
        )) {
            if (param_value != null or saw_server_no_context_takeover) {
                acceptable = false;
            }
            saw_server_no_context_takeover = true;
            out.server_no_context_takeover = true;
        } else if (std.ascii.eqlIgnoreCase(
            param_name,
            "client_max_window_bits",
        )) {
            if (saw_client_max_window_bits) acceptable = false;
            saw_client_max_window_bits = true;
            const bits: u8 = if (param_value) |raw|
                parseWindowBitsValue(raw)
            else if (role == .offer)
                15
            else
                0;
            if (bits < 8 or bits > 15) acceptable = false;
            out.client_max_window_bits = bits;
        } else if (std.ascii.eqlIgnoreCase(
            param_name,
            "server_max_window_bits",
        )) {
            if (saw_server_max_window_bits) acceptable = false;
            saw_server_max_window_bits = true;
            const bits: u8 = if (param_value) |raw|
                parseWindowBitsValue(raw)
            else
                0;
            if (bits < 8 or bits > 15) acceptable = false;
            out.server_max_window_bits = bits;
        } else {
            acceptable = false;
        }
    }

    if (is_permessage_deflate and !acceptable) {
        if (role == .response) return error.InvalidExtension;
        return .declined;
    }
    return if (is_permessage_deflate)
        .{ .permessage_deflate = out }
    else
        .unknown;
}

fn skipExtensionOws(value: []const u8, offset: *usize) void {
    while (offset.* < value.len and
        (value[offset.*] == ' ' or value[offset.*] == '\t'))
    {
        offset.* += 1;
    }
}

fn parseExtensionToken(value: []const u8, offset: *usize) Error![]const u8 {
    const start = offset.*;
    while (offset.* < value.len and isTchar(value[offset.*])) {
        offset.* += 1;
    }
    if (offset.* == start) return error.InvalidExtension;
    return value[start..offset.*];
}

fn parseExtensionQuotedToken(value: []const u8, offset: *usize) Error!void {
    std.debug.assert(offset.* < value.len and value[offset.*] == '"');
    offset.* += 1;
    var decoded_len: usize = 0;
    while (offset.* < value.len) {
        var byte = value[offset.*];
        if (byte == '"') {
            if (decoded_len == 0) return error.InvalidExtension;
            offset.* += 1;
            return;
        }
        if (byte == '\\') {
            offset.* += 1;
            if (offset.* == value.len) return error.InvalidExtension;
            byte = value[offset.*];
        }
        // RFC 6455 uses quoted-string only as transport syntax here: after
        // unescaping, every extension parameter value must still be a token.
        if (!isTchar(byte)) return error.InvalidExtension;
        decoded_len += 1;
        offset.* += 1;
    }
    return error.InvalidExtension;
}

fn parseWindowBitsValue(raw_value: []const u8) u8 {
    // Sec-WebSocket-Extensions uses the generic extension-param grammar from
    // RFC 6455: parameter values may be either tokens or quoted-strings.  The
    // permessage-deflate window-bit value itself is still a decimal integer.
    // Decode quoted-pairs while scanning instead of allocating a temporary
    // string, then apply the same leading-zero and range rules as token form.
    const quoted = raw_value.len >= 2 and raw_value[0] == '"';
    const value = if (quoted) blk: {
        if (raw_value[raw_value.len - 1] != '"') return 0;
        break :blk raw_value[1 .. raw_value.len - 1];
    } else raw_value;

    if (value.len == 0) return 0;
    var parsed: u8 = 0;
    var index: usize = 0;
    var digits: usize = 0;
    var first_digit: u8 = 0;
    while (index < value.len) : (index += 1) {
        var byte = value[index];
        if (quoted and byte == '\\') {
            index += 1;
            if (index == value.len) return 0;
            byte = value[index];
        }
        if (!std.ascii.isDigit(byte)) return 0;
        if (digits == 2) return 0;
        if (digits == 0) first_digit = byte;
        digits += 1;
        parsed = parsed * 10 + byte - '0';
    }
    if (digits > 1 and first_digit == '0') return 0;
    return parsed;
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

    var predecoded_storage: [32]u8 = undefined;
    const header = try FrameHeader.parse(encoded.items);
    const predecoded = try parseFrameIntoWithHeader(
        &predecoded_storage,
        encoded.items,
        header,
        .{ .expect_mask = .masked },
    );
    try std.testing.expectEqual(
        frame.header.header_len,
        predecoded.header.header_len,
    );
    try std.testing.expectEqual(
        frame.header.payload_len,
        predecoded.header.payload_len,
    );
    try std.testing.expectEqual(frame.header.opcode, predecoded.header.opcode);
    try std.testing.expectEqual(frame.header.masked, predecoded.header.masked);
    try std.testing.expectEqualStrings(frame.payload, predecoded.payload);
    try std.testing.expectEqual(frame.consumed, predecoded.consumed);

    const in_place = try allocator.dupe(u8, encoded.items);
    defer allocator.free(in_place);
    const decoded_in_place = try parseFrameInPlaceWithHeader(
        in_place,
        header,
        .{ .expect_mask = .masked },
    );
    try std.testing.expectEqualStrings(
        frame.payload,
        decoded_in_place.payload,
    );
    try std.testing.expectEqual(
        frame.consumed,
        decoded_in_place.consumed,
    );

    try std.testing.expectError(
        error.MaskedServerFrame,
        parseFrameIntoWithHeader(
            &predecoded_storage,
            encoded.items,
            header,
            .{ .expect_mask = .unmasked },
        ),
    );
}

test "WebSocket predecoded frame rejects total length overflow" {
    const header = FrameHeader{
        .fin = true,
        .opcode = .binary,
        .masked = false,
        .payload_len = @intCast(std.math.maxInt(usize)),
        .mask_key = null,
        .header_len = max_frame_header_len,
    };
    try std.testing.expectError(error.PayloadTooLarge, header.wireLen());
    try std.testing.expectError(
        error.PayloadTooLarge,
        parseFrameWithHeader(std.testing.allocator, &.{}, header, .{}),
    );

    var output: [0]u8 = .{};
    try std.testing.expectError(
        error.PayloadTooLarge,
        parseFrameIntoWithHeader(&output, &.{}, header, .{}),
    );
    try std.testing.expectError(
        error.PayloadTooLarge,
        parseFrameInPlaceWithHeader(&output, header, .{}),
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

test "WebSocket predecoded header parsers match ordinary parsers" {
    const allocator = std.testing.allocator;
    const payload_lengths = [_]usize{ 0, 1, 125, 126, 257 };
    for (payload_lengths) |payload_len| {
        const payload = try allocator.alloc(u8, payload_len);
        defer allocator.free(payload);
        for (payload, 0..) |*byte, index| byte.* = @truncate(index * 29);
        for ([_]?[4]u8{ null, .{ 9, 8, 7, 6 } }) |mask_key| {
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(allocator);
            try writeFrame(
                &encoded,
                allocator,
                .binary,
                payload,
                .{ .mask_key = mask_key },
            );
            const header = try FrameHeader.parse(encoded.items);

            var ordinary = try parseFrameOptions(
                allocator,
                encoded.items,
                .{},
            );
            defer ordinary.deinit(allocator);
            var predecoded = try parseFrameWithHeader(
                allocator,
                encoded.items,
                header,
                .{},
            );
            defer predecoded.deinit(allocator);
            try std.testing.expectEqual(ordinary.consumed, predecoded.consumed);
            try std.testing.expectEqualSlices(
                u8,
                ordinary.payload,
                predecoded.payload,
            );

            const output = try allocator.alloc(u8, payload_len);
            defer allocator.free(output);
            const borrowed = try parseFrameIntoWithHeader(
                output,
                encoded.items,
                header,
                .{},
            );
            try std.testing.expectEqualSlices(u8, payload, borrowed.payload);

            const mutable_encoded = try allocator.dupe(u8, encoded.items);
            defer allocator.free(mutable_encoded);
            const in_place = try parseFrameInPlaceWithHeader(
                mutable_encoded,
                header,
                .{},
            );
            try std.testing.expectEqual(ordinary.consumed, in_place.consumed);
            try std.testing.expectEqualSlices(u8, payload, in_place.payload);
        }
    }
}

test "WebSocket length-only frame header matches payload-based encoder" {
    const payload_lengths = [_]usize{
        0,
        1,
        125,
        126,
        std.math.maxInt(u16),
        @as(usize, std.math.maxInt(u16)) + 1,
    };
    for (payload_lengths) |payload_len| {
        const payload = try std.testing.allocator.alloc(u8, payload_len);
        defer std.testing.allocator.free(payload);
        for ([_]?[4]u8{ null, .{ 1, 2, 3, 4 } }) |mask_key| {
            var expected_storage: [max_frame_header_len]u8 = undefined;
            const expected = try writeFrameHeaderInto(
                &expected_storage,
                .binary,
                payload,
                .{ .mask_key = mask_key },
            );
            var actual_storage: [max_frame_header_len]u8 = undefined;
            const actual = try writeFrameHeaderForLengthInto(
                &actual_storage,
                .binary,
                payload_len,
                .{ .mask_key = mask_key },
            );
            try std.testing.expectEqualSlices(u8, expected, actual);
        }
    }
    var storage: [max_frame_header_len]u8 = undefined;
    if (comptime @bitSizeOf(usize) >= 64) {
        const largest = try writeFrameHeaderForLengthInto(
            &storage,
            .binary,
            @intCast(max_frame_payload_len),
            .{},
        );
        const parsed = try FrameHeader.parse(largest);
        try std.testing.expectEqual(max_frame_payload_len, parsed.payload_len);
        @memset(&storage, 0xa5);
        try std.testing.expectError(
            error.PayloadTooLarge,
            writeFrameHeaderForLengthInto(
                &storage,
                .binary,
                @as(usize, @intCast(max_frame_payload_len)) + 1,
                .{},
            ),
        );
        try std.testing.expectEqualSlices(
            u8,
            &([_]u8{0xa5} ** max_frame_header_len),
            &storage,
        );
    }
    try std.testing.expectError(
        error.InvalidControlFrame,
        writeFrameHeaderForLengthInto(
            &storage,
            .ping,
            126,
            .{},
        ),
    );
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
    var constructed_missing_host = req;
    constructed_missing_host.headers = req.headers[1..];
    try std.testing.expectError(
        error.MissingHeader,
        validateClientHandshake(constructed_missing_host),
    );

    const split_connection = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var split_req = try http1.parseRequest(allocator, split_connection, .{});
    defer split_req.deinit(allocator);
    try validateClientHandshake(split_req);

    const listed_upgrade = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c/1, WebSocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var listed_upgrade_req = try http1.parseRequest(
        allocator,
        listed_upgrade,
        .{},
    );
    defer listed_upgrade_req.deinit(allocator);
    try validateClientHandshake(listed_upgrade_req);

    const split_upgrade = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c/1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var split_upgrade_req = try http1.parseRequest(
        allocator,
        split_upgrade,
        .{},
    );
    defer split_upgrade_req.deinit(allocator);
    try validateClientHandshake(split_upgrade_req);

    const invalid_upgrade = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c/bad/version, websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var invalid_upgrade_req = try http1.parseRequest(
        allocator,
        invalid_upgrade,
        .{},
    );
    defer invalid_upgrade_req.deinit(allocator);
    try std.testing.expectError(
        error.InvalidHandshake,
        validateClientHandshake(invalid_upgrade_req),
    );

    const http10 = "GET /chat HTTP/1.0\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var http10_req = try http1.parseRequest(allocator, http10, .{});
    defer http10_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(http10_req));

    const duplicate_key = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var duplicate_key_req = try http1.parseRequest(allocator, duplicate_key, .{});
    defer duplicate_key_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(duplicate_key_req));

    const missing_host = "GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        http1.parseRequest(allocator, missing_host, .{}),
    );

    const empty_host = "GET /chat HTTP/1.1\r\nHost: \t \r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        http1.parseRequest(allocator, empty_host, .{}),
    );

    const invalid_host = "GET /chat HTTP/1.1\r\nHost: http://example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        http1.parseRequest(allocator, invalid_host, .{}),
    );

    const unbracketed_ipv6_host = "GET /chat HTTP/1.1\r\nHost: 2001:db8::1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        http1.parseRequest(allocator, unbracketed_ipv6_host, .{}),
    );

    const duplicate_host = "GET /chat HTTP/1.1\r\nHost: example.com\r\nHost: other.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        http1.parseRequest(allocator, duplicate_host, .{}),
    );

    const valid_protocols = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1, super-chat\r\n\r\n";
    var valid_protocols_req = try http1.parseRequest(allocator, valid_protocols, .{});
    defer valid_protocols_req.deinit(allocator);
    try validateClientHandshake(valid_protocols_req);

    const invalid_protocol = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1, bad protocol\r\n\r\n";
    var invalid_protocol_req = try http1.parseRequest(allocator, invalid_protocol, .{});
    defer invalid_protocol_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(invalid_protocol_req));

    const empty_protocol_members = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: , chat.v1,,\r\n\r\n";
    var empty_protocol_members_req = try http1.parseRequest(
        allocator,
        empty_protocol_members,
        .{},
    );
    defer empty_protocol_members_req.deinit(allocator);
    try validateClientHandshake(empty_protocol_members_req);

    const only_empty_protocols = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: , ,\r\n\r\n";
    var only_empty_protocols_req = try http1.parseRequest(
        allocator,
        only_empty_protocols,
        .{},
    );
    defer only_empty_protocols_req.deinit(allocator);
    try std.testing.expectError(
        error.InvalidHandshake,
        validateClientHandshake(only_empty_protocols_req),
    );

    const duplicate_protocol = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1, chat.v1\r\n\r\n";
    var duplicate_protocol_req = try http1.parseRequest(allocator, duplicate_protocol, .{});
    defer duplicate_protocol_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(duplicate_protocol_req));

    const split_duplicate_protocol = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1\r\nSec-WebSocket-Protocol: chat.v2, chat.v1\r\n\r\n";
    var split_duplicate_protocol_req = try http1.parseRequest(allocator, split_duplicate_protocol, .{});
    defer split_duplicate_protocol_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(split_duplicate_protocol_req));

    const valid_extensions = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: x-example; mode=\"safe\", permessage-deflate\r\n\r\n";
    var valid_extensions_req = try http1.parseRequest(
        allocator,
        valid_extensions,
        .{},
    );
    defer valid_extensions_req.deinit(allocator);
    try validateClientHandshake(valid_extensions_req);

    const declined_extension = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; unknown=1\r\n\r\n";
    var declined_extension_req = try http1.parseRequest(
        allocator,
        declined_extension,
        .{},
    );
    defer declined_extension_req.deinit(allocator);
    try validateClientHandshake(declined_extension_req);

    const malformed_trailing_extension = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Extensions: broken extension\r\n\r\n";
    var malformed_trailing_extension_req = try http1.parseRequest(
        allocator,
        malformed_trailing_extension,
        .{},
    );
    defer malformed_trailing_extension_req.deinit(allocator);
    try std.testing.expectError(
        error.InvalidExtension,
        validateClientHandshake(malformed_trailing_extension_req),
    );

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
    var fixed_storage: [125]u8 = undefined;
    const fixed_payload = try writeClosePayloadInto(
        &fixed_storage,
        .{ .code = .going_away, .reason = "restart" },
    );
    try std.testing.expectEqualSlices(u8, encoded.items, fixed_payload);
    const encoded_parsed = (try parseClosePayload(encoded.items)).?;
    try std.testing.expectEqual(CloseCode.going_away, encoded_parsed.code);
    try std.testing.expectEqualStrings("restart", encoded_parsed.reason);

    encoded.clearRetainingCapacity();
    try writeClosePayload(&encoded, allocator, null);
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);
    try std.testing.expectEqual(
        @as(usize, 0),
        (try writeClosePayloadInto(&fixed_storage, null)).len,
    );

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

    const bounded = try ExtensionNegotiation.acceptWithPolicy(
        allocator,
        "permessage-deflate; client_max_window_bits=12; server_max_window_bits=11",
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .accept_client_max_window_bits = 9,
            .accept_server_max_window_bits = 10,
        },
    );
    defer if (bounded) |value| allocator.free(value);
    try std.testing.expectEqualStrings(
        "permessage-deflate; client_max_window_bits=9; server_max_window_bits=10",
        bounded.?,
    );
    const selected_window_response = try ExtensionNegotiation
        .validateResponseWithPolicy(bounded.?, .{
        .enable_permessage_deflate = true,
        .allow_context_takeover = true,
    });
    try std.testing.expectEqual(
        @as(?u8, 9),
        selected_window_response.client_max_window_bits,
    );
    try std.testing.expectEqual(
        @as(?u8, 10),
        selected_window_response.server_max_window_bits,
    );

    const peer_bounded = try ExtensionNegotiation.acceptWithPolicy(
        allocator,
        "permessage-deflate; client_max_window_bits=8; server_max_window_bits=9",
        .{
            .enable_permessage_deflate = true,
            .accept_client_max_window_bits = 12,
            .accept_server_max_window_bits = 12,
        },
    );
    defer if (peer_bounded) |value| allocator.free(value);
    try std.testing.expect(std.mem.indexOf(
        u8,
        peer_bounded.?,
        "client_max_window_bits=8; server_max_window_bits=9",
    ) != null);
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.acceptWithPolicy(
            allocator,
            "permessage-deflate",
            .{
                .enable_permessage_deflate = true,
                .accept_client_max_window_bits = 7,
            },
        ),
    );

    const split_headers = [_]http1.Header{
        .{ .name = "Sec-WebSocket-Extensions", .value = "x-unknown" },
        .{ .name = "Sec-WebSocket-Extensions", .value = "permessage-deflate; client_no_context_takeover; server_max_window_bits=15" },
    };
    const accepted_split = try ExtensionNegotiation.acceptClientHeaders(allocator, &split_headers, true);
    defer if (accepted_split) |value| allocator.free(value);
    try std.testing.expect(accepted_split != null);
    try std.testing.expect(std.mem.startsWith(u8, accepted_split.?, "permessage-deflate"));

    const small_window = try ExtensionNegotiation.accept(
        allocator,
        "permessage-deflate; server_max_window_bits=12",
        true,
    );
    defer if (small_window) |value| allocator.free(value);
    try std.testing.expectEqualStrings(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=12",
        small_window.?,
    );
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse("permessage-deflate"));
    const quoted_window_response = try ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=\"15\"",
    );
    try std.testing.expectEqual(@as(?u8, 15), quoted_window_response.client_max_window_bits);
    const small_window_response = try ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=\"12\"",
    );
    try std.testing.expectEqual(@as(?u8, 12), small_window_response.client_max_window_bits);
    const split_response_headers = [_]http1.Header{
        .{ .name = "Sec-WebSocket-Extensions", .value = "" },
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "permessage-deflate",
        },
    };
    const split_response = try ExtensionNegotiation
        .validateResponseHeadersForOfferWithPolicy(
        &split_response_headers,
        "permessage-deflate",
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
        },
    );
    try std.testing.expect(split_response.permessage_deflate);

    const duplicate_response_headers = [_]http1.Header{
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "permessage-deflate",
        },
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = ", permessage-deflate",
        },
    };
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseHeadersForOfferWithPolicy(
            &duplicate_response_headers,
            "permessage-deflate",
            .{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
            },
        ),
    );

    const unknown_response_headers = [_]http1.Header{
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "permessage-deflate",
        },
        .{ .name = "Sec-WebSocket-Extensions", .value = "x-unknown" },
    };
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseHeadersForOfferWithPolicy(
            &unknown_response_headers,
            "permessage-deflate",
            .{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
            },
        ),
    );
    var invalid_window_output: std.ArrayList(u8) = .empty;
    defer invalid_window_output.deinit(allocator);
    try std.testing.expectError(
        error.InvalidExtension,
        compressMessageVortIntoWindow(
            &invalid_window_output,
            allocator,
            "invalid compression window",
            7,
        ),
    );
    const escaped_window_response = try ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=\"1\\5\"",
    );
    try std.testing.expectEqual(
        @as(?u8, 15),
        escaped_window_response.client_max_window_bits,
    );
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=\"1\\ 5\"",
    ));
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover, x-unknown",
    ));
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover, permessage-deflate; server_no_context_takeover; client_no_context_takeover",
    ));
    const unknown_parameter = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; server_no_context_takeover; x-unknown=1",
    );
    try std.testing.expect(!unknown_parameter.permessage_deflate);
    const declined_accept = try ExtensionNegotiation.accept(
        allocator,
        "permessage-deflate; x-unknown=1",
        true,
    );
    try std.testing.expect(declined_accept == null);
    const duplicate_parameter = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; client_no_context_takeover; client_no_context_takeover",
    );
    try std.testing.expect(!duplicate_parameter.permessage_deflate);
    const duplicate_window = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; server_max_window_bits=15; server_max_window_bits=15",
    );
    try std.testing.expect(!duplicate_window.permessage_deflate);
    const later_valid_offer = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; x-unknown=1, " ++
            "permessage-deflate; server_max_window_bits=12",
    );
    try std.testing.expect(later_valid_offer.permessage_deflate);
    try std.testing.expectEqual(
        @as(?u8, 12),
        later_valid_offer.server_max_window_bits,
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.parseOffer(
            "permessage-deflate, broken extension",
        ),
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.parseOffer(
            "x-example; mode=\"not a token\"",
        ),
    );
    const empty_members = try ExtensionNegotiation.parseOffer(
        ", permessage-deflate,,",
    );
    try std.testing.expect(empty_members.permessage_deflate);
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.parseOffer(", ,"),
    );

    const valid_unknown_then_known = try ExtensionNegotiation.parseOffer(
        "x-example; mode=\"safe\", permessage-deflate; server_max_window_bits=12",
    );
    try std.testing.expect(valid_unknown_then_known.permessage_deflate);
    try std.testing.expectEqual(
        @as(?u8, 12),
        valid_unknown_then_known.server_max_window_bits,
    );
    const escaped_window_offer = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; server_max_window_bits=\"\\1\\2\"",
    );
    try std.testing.expectEqual(
        @as(?u8, 12),
        escaped_window_offer.server_max_window_bits,
    );

    const complete_headers = [_]http1.Header{
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "",
        },
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "permessage-deflate",
        },
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "x-example; mode=\"safe\"",
        },
    };
    const complete_accept = try ExtensionNegotiation
        .acceptClientHeadersWithPolicy(
        allocator,
        &complete_headers,
        .{ .enable_permessage_deflate = true },
    );
    defer if (complete_accept) |value| allocator.free(value);
    try std.testing.expect(complete_accept != null);

    const empty_headers = [_]http1.Header{
        .{ .name = "Sec-WebSocket-Extensions", .value = "" },
        .{ .name = "Sec-WebSocket-Extensions", .value = ", ," },
    };
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.acceptClientHeadersWithPolicy(
            allocator,
            &empty_headers,
            .{ .enable_permessage_deflate = false },
        ),
    );

    const malformed_later_headers = [_]http1.Header{
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "permessage-deflate",
        },
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "x-example; mode=\"not a token\"",
        },
    };
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.acceptClientHeadersWithPolicy(
            allocator,
            &malformed_later_headers,
            .{ .enable_permessage_deflate = true },
        ),
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.acceptWithPolicy(
            allocator,
            "permessage-deflate, broken extension",
            .{ .enable_permessage_deflate = false },
        ),
    );

    try std.testing.expect(ExtensionNegotiation.offerValue(.{}) == null);
    try std.testing.expectEqualStrings(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
        ExtensionNegotiation.offerValue(.{
            .enable_permessage_deflate = true,
        }).?,
    );
    try std.testing.expectEqualStrings(
        "permessage-deflate",
        ExtensionNegotiation.offerValue(.{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
        }).?,
    );
    const takeover_accept = try ExtensionNegotiation.acceptWithPolicy(
        allocator,
        "permessage-deflate",
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
        },
    );
    defer if (takeover_accept) |value| allocator.free(value);
    try std.testing.expectEqualStrings(
        "permessage-deflate",
        takeover_accept.?,
    );
    const takeover_response = try ExtensionNegotiation
        .validateResponseWithPolicy(
        takeover_accept,
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
        },
    );
    try std.testing.expect(takeover_response.permessage_deflate);
    try std.testing.expect(!takeover_response.client_no_context_takeover);
    try std.testing.expect(!takeover_response.server_no_context_takeover);
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseWithPolicy(
            "permessage-deflate",
            .{ .enable_permessage_deflate = false },
        ),
    );

    const permissive_policy: ExtensionNegotiation.Policy = .{
        .enable_permessage_deflate = true,
        .allow_context_takeover = true,
    };
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseWithPolicy(
            "permessage-deflate; x-unknown=1",
            permissive_policy,
        ),
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; client_max_window_bits=15",
            "permessage-deflate",
            permissive_policy,
        ),
    );
    const implicit_client_window = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; client_max_window_bits=8",
        "permessage-deflate; client_max_window_bits",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 8),
        implicit_client_window.client_max_window_bits,
    );
    const maximum_implicit_client_window = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; client_max_window_bits=15",
        "permessage-deflate; client_max_window_bits",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 15),
        maximum_implicit_client_window.client_max_window_bits,
    );
    const client_window_hint_is_not_a_limit = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; client_max_window_bits=13",
        "permessage-deflate; client_max_window_bits=12",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 13),
        client_window_hint_is_not_a_limit.client_max_window_bits,
    );
    for ([_]u8{ 11, 12 }) |bits| {
        var response_buffer: [64]u8 = undefined;
        const bounded_response = try std.fmt.bufPrint(
            &response_buffer,
            "permessage-deflate; client_max_window_bits={d}",
            .{bits},
        );
        const bounded_client_window = try ExtensionNegotiation
            .validateResponseForOfferWithPolicy(
            bounded_response,
            "permessage-deflate; client_max_window_bits=12",
            permissive_policy,
        );
        try std.testing.expectEqual(
            @as(?u8, bits),
            bounded_client_window.client_max_window_bits,
        );
    }
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; client_max_window_bits",
            "permessage-deflate; client_max_window_bits",
            permissive_policy,
        ),
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; server_max_window_bits",
            "permessage-deflate",
            permissive_policy,
        ),
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; client_max_window_bits=08",
            "permessage-deflate; client_max_window_bits",
            permissive_policy,
        ),
    );
    const invalid_window_offer = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; server_max_window_bits=012",
    );
    try std.testing.expect(!invalid_window_offer.permessage_deflate);
    const unsolicited_server_window = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; server_max_window_bits=12",
        "permessage-deflate",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 12),
        unsolicited_server_window.server_max_window_bits,
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; server_max_window_bits=13",
            "permessage-deflate; server_max_window_bits=12",
            permissive_policy,
        ),
    );
    const bounded_server_window = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; server_max_window_bits=12",
        "permessage-deflate; server_max_window_bits=12",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 12),
        bounded_server_window.server_max_window_bits,
    );
    const matching_offer = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; client_max_window_bits=12; server_max_window_bits=11",
        "permessage-deflate, " ++
            "permessage-deflate; client_max_window_bits=12; server_max_window_bits=11",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 12),
        matching_offer.client_max_window_bits,
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; client_max_window_bits=13; server_max_window_bits=12",
            "permessage-deflate, " ++
                "permessage-deflate; client_max_window_bits=13; server_max_window_bits=11",
            permissive_policy,
        ),
    );

    const payload = "compress me compress me compress me compress me";
    const compressed = try compressMessage(allocator, payload);
    defer allocator.free(compressed);
    try std.testing.expect(compressed.len < payload.len);
    try std.testing.expect(!std.mem.endsWith(u8, compressed, "\x00\x00\xff\xff"));
    const decoded = try decompressMessage(allocator, compressed, 1024);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(payload, decoded);

    // Two identical pseudo-random halves have no useful local repetition, so
    // a 512-byte window cannot refer back to the first half while a 32-KiB
    // window can. This guards the negotiated bound in the actual encoder, not
    // merely the extension response text.
    var distant_repeat: [2048]u8 = undefined;
    var state: u32 = 0x9e37_79b9;
    for (distant_repeat[0..1024]) |*byte| {
        state = state *% 1_664_525 +% 1_013_904_223;
        byte.* = @truncate(state >> 24);
    }
    @memcpy(distant_repeat[1024..], distant_repeat[0..1024]);
    var small_window_encoded: std.ArrayList(u8) = .empty;
    defer small_window_encoded.deinit(allocator);
    _ = try compressMessageVortIntoWindow(
        &small_window_encoded,
        allocator,
        &distant_repeat,
        9,
    );
    var full_window_encoded: std.ArrayList(u8) = .empty;
    defer full_window_encoded.deinit(allocator);
    _ = try compressMessageVortIntoWindow(
        &full_window_encoded,
        allocator,
        &distant_repeat,
        15,
    );
    try std.testing.expect(
        small_window_encoded.items.len > full_window_encoded.items.len + 512,
    );
    const small_window_decoded = try decompressMessage(
        allocator,
        small_window_encoded.items,
        distant_repeat.len,
    );
    defer allocator.free(small_window_decoded);
    try std.testing.expectEqualSlices(
        u8,
        &distant_repeat,
        small_window_decoded,
    );

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

test "WebSocket message assembler owns a complete frame with one exact allocation" {
    const payload = "single-frame-owned-payload";
    var tracking = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = tracking.allocator();
    var assembler = MessageAssembler.initLimited(allocator, payload.len);
    defer assembler.deinit();
    const frame = Frame{
        .header = .{
            .fin = true,
            .opcode = .binary,
            .masked = false,
            .payload_len = payload.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = @constCast(payload),
        .consumed = 2 + payload.len,
    };

    const message = (try assembler.feed(frame)).?;
    defer allocator.free(message.payload);
    try std.testing.expectEqualStrings(payload, message.payload);
    try std.testing.expectEqual(@as(usize, 1), tracking.allocations);
    try std.testing.expectEqual(@as(usize, 0), tracking.resize_index);
    try std.testing.expectEqual(payload.len, tracking.allocated_bytes);
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
    const original = "existing output";
    try response.appendSlice(allocator, original);

    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "not-base64",
        &.{},
    ));
    try std.testing.expectEqualStrings(original, response.items);
    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{.{ .name = "Sec-WebSocket-Accept", .value = "duplicate" }},
    ));
    try std.testing.expectEqualStrings(original, response.items);
    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1" },
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v2" },
        },
    ));
    try std.testing.expectEqualStrings(original, response.items);
    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{.{ .name = "Sec-WebSocket-Protocol", .value = "bad protocol" }},
    ));
    try std.testing.expectEqualStrings(original, response.items);
    try std.testing.expectError(error.MalformedHeader, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{.{ .name = "X-Test", .value = "ok\r\nInjected: yes" }},
    ));
    try std.testing.expectEqualStrings(original, response.items);

    for ([_]wire.Header{
        .{ .name = "cOnTeNt-LeNgTh", .value = "0" },
        .{ .name = "TrAnSfEr-EnCoDiNg", .value = "chunked" },
        .{ .name = "TrAiLeR", .value = "X-Checksum" },
    }) |header| {
        try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
            &response,
            allocator,
            "dGhlIHNhbXBsZSBub25jZQ==",
            &.{header},
        ));
        try std.testing.expectEqualStrings(original, response.items);
    }
}

test "WebSocket server handshake write is transactional and exactly reserved" {
    const allocator = std.testing.allocator;
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const extra_headers = &[_]wire.Header{
        .{ .name = "X-Test", .value = "ok" },
    };
    const expected =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "X-Test: ok\r\n" ++
        "\r\n";

    var failure: std.ArrayList(u8) = .empty;
    defer failure.deinit(allocator);
    try failure.ensureTotalCapacityPrecise(allocator, "seed".len);
    failure.appendSliceAssumeCapacity("seed");
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        writeServerHandshake(
            &failure,
            fail_first.allocator(),
            client_key,
            extra_headers,
        ),
    );
    try std.testing.expectEqualStrings("seed", failure.items);

    var exact_storage: [expected.len]u8 = undefined;
    var exact = std.ArrayList(u8).initBuffer(&exact_storage);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try writeServerHandshake(
        &exact,
        no_alloc.allocator(),
        client_key,
        extra_headers,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings(expected, exact.items);
}

test {
    _ = runtime;
}
