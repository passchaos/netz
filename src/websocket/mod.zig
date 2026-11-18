const std = @import("std");
const builtin = @import("builtin");
const wire = @import("../internal/wire.zig");
const http1 = @import("../http1/mod.zig");
const deflate = @import("../internal/deflate.zig");
const compression_context = @import("compression_context.zig");
const compression_policy = @import("compression/policy.zig");
const server_handshake = @import("handshake/server.zig");

pub const runtime = @import("runtime.zig");
pub const CompressionContext = compression_context.CompressionContext;
pub const DecompressionContext = compression_context.DecompressionContext;
pub const ContextTakeover = compression_policy.ContextTakeover;

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
    UnsupportedVersion,
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

pub const OwnedCloseFrame = @import("close/owned.zig").OwnedCloseFrame;

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
    pub const max_offer_value_len: usize = 160;
    permessage_deflate: bool = false,
    client_no_context_takeover: bool = false,
    server_no_context_takeover: bool = false,
    client_max_window_bits: ?u8 = null,
    server_max_window_bits: ?u8 = null,

    pub const Policy = compression_policy.Policy;

    pub fn offerValue(policy: Policy) ?[]const u8 {
        if (!policy.enable_permessage_deflate) return null;
        if (!policy.serverTakeover() and !policy.clientTakeover()) return "permessage-deflate; server_no_context_takeover; client_no_context_takeover";
        if (!policy.serverTakeover()) return "permessage-deflate; server_no_context_takeover";
        if (!policy.clientTakeover()) return "permessage-deflate; client_no_context_takeover";
        return "permessage-deflate";
    }

    /// Render a client offer with optional RFC 7692 window bounds into caller
    /// storage. The ordinary null-window path remains allocation free and
    /// byte-identical to `offerValue`.
    pub fn offerValueInto(
        out: []u8,
        policy: Policy,
        client_max_window_bits: ?u8,
        server_max_window_bits: ?u8,
    ) Error!?[]const u8 {
        try validateOfferWindowBits(
            policy.enable_permessage_deflate,
            client_max_window_bits,
            server_max_window_bits,
        );
        if (!policy.enable_permessage_deflate) return null;
        if (client_max_window_bits == null and
            server_max_window_bits == null)
        {
            return offerValue(policy);
        }
        var writer = std.Io.Writer.fixed(out);
        try writer.writeAll("permessage-deflate");
        if (!policy.serverTakeover()) try writer.writeAll("; server_no_context_takeover");
        if (!policy.clientTakeover()) try writer.writeAll("; client_no_context_takeover");
        if (client_max_window_bits) |bits| {
            try writer.print("; client_max_window_bits={d}", .{bits});
        }
        if (server_max_window_bits) |bits| {
            try writer.print("; server_max_window_bits={d}", .{bits});
        }
        return writer.buffered();
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
        if (!policy.serverTakeover() or
            offer.server_no_context_takeover)
        {
            try value.appendSlice(allocator, "; server_no_context_takeover");
        }
        if (!policy.clientTakeover() or
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
            policy.clientResponsePolicy(),
        );
        return validateClientSelection(try validateResponseAgainstOffer(response, offer_header), policy);
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
                    if ((!policy.clientTakeover() and !parsed.client_no_context_takeover) or
                        (!policy.serverTakeover() and !parsed.server_no_context_takeover))
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

    fn validateOfferWindowBits(
        enabled: bool,
        client_max_window_bits: ?u8,
        server_max_window_bits: ?u8,
    ) Error!void {
        for ([_]?u8{
            client_max_window_bits,
            server_max_window_bits,
        }) |maybe_bits| {
            if (maybe_bits) |bits| {
                if (!enabled or bits < 8 or bits > 15) {
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
    /// server_max_window_bits value is a hard upper bound. An offered
    /// server_no_context_takeover must be acknowledged in the selection;
    /// client_no_context_takeover remains a client-side hint.
    pub fn validateResponseForOfferWithPolicy(
        header_value: ?[]const u8,
        offer_header: ?[]const u8,
        policy: Policy,
    ) Error!ExtensionNegotiation {
        const response = try validateResponseWithPolicy(header_value, policy.clientResponsePolicy());
        return validateClientSelection(try validateResponseAgainstOffer(response, offer_header), policy);
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
                    if (offer.server_no_context_takeover and !response.server_no_context_takeover) continue;
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
        if (!matched) return error.InvalidExtension;
        return response;
    }

    fn validateClientSelection(response: ExtensionNegotiation, policy: Policy) Error!ExtensionNegotiation {
        if (response.permessage_deflate and !policy.serverTakeover() and !response.server_no_context_takeover) {
            return error.InvalidExtension;
        }
        var effective = response;
        // RFC 7692 permits a client to use no takeover even when the server
        // omitted the flag. Preserve local policy without inventing a peer
        // acknowledgement requirement or treating the offer hint as mandatory.
        if (effective.permessage_deflate and !policy.clientTakeover()) effective.client_no_context_takeover = true;
        return effective;
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

    /// Consume this Close frame and transfer its existing payload allocation
    /// to the owned diagnostic without another allocation. On validation
    /// failure, the frame remains owned by the caller.
    pub fn takeClose(self: *Frame, allocator: std.mem.Allocator) Error!?OwnedCloseFrame {
        return @import("close/owned.zig").take(self, allocator);
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
    try validateClientHandshakePrefix(req);
    const version = try requiredSingletonHeader(
        req.headers,
        "sec-websocket-version",
    );
    try validateClientVersion(version);
    try validateClientHandshakeSuffix(req);
}

/// Validate every HTTP/1 WebSocket handshake requirement except the concrete
/// version value. Servers use this only after `validateClientHandshake`
/// reports `UnsupportedVersion`, before advertising the supported version.
pub fn validateClientHandshakeForVersionNegotiation(
    req: http1.Request,
) Error!void {
    try validateClientHandshakePrefix(req);
    try validateClientVersionSyntax(try requiredSingletonHeader(
        req.headers,
        "sec-websocket-version",
    ));
    try validateClientHandshakeSuffix(req);
}

pub fn validateClientVersion(value: []const u8) Error!void {
    try validateClientVersionSyntax(value);
    if (!std.mem.eql(u8, value, "13")) return error.UnsupportedVersion;
}

pub fn validateClientVersionSyntax(value: []const u8) Error!void {
    const valid = switch (value.len) {
        1 => std.ascii.isDigit(value[0]),
        2 => value[0] >= '1' and value[0] <= '9' and
            std.ascii.isDigit(value[1]),
        3 => (value[0] == '1' or value[0] == '2') and
            std.ascii.isDigit(value[1]) and std.ascii.isDigit(value[2]),
        else => false,
    };
    if (!valid) return error.InvalidHandshake;
}

fn validateClientHandshakePrefix(req: http1.Request) Error!void {
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
}

fn validateClientHandshakeSuffix(req: http1.Request) Error!void {
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

pub const writeServerHandshake = server_handshake.write;

pub const MessageAssembler = @import("message/assembler.zig").Assembler;

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

test {
    _ = @import("compression/negotiation_tests.zig");
    _ = runtime;
}

pub const stream_connection = @import("stream_connection.zig");

test {
    _ = @import("tests.zig");
}
