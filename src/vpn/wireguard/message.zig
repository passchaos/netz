//! Bounded WireGuard wire-format parsing and construction.
//!
//! Every parser checks the exact message length and the type/reserved word
//! before exposing fields. Handshake messages have fixed sizes; transport
//! messages are bounded by an explicit caller-provided maximum.

const std = @import("std");

pub const initiation_size = 148;
pub const response_size = 92;
pub const cookie_reply_size = 64;
pub const transport_header_size = 16;
pub const keepalive_size = transport_header_size + 16;
pub const max_transport_size = 65_535;
pub const padding_multiple = 16;

pub const mac1_size = 16;
pub const mac2_size = 16;
pub const cookie_size = 16;
pub const timestamp_size = 12;

pub const MessageType = enum(u8) {
    handshake_initiation = 1,
    handshake_response = 2,
    cookie_reply = 3,
    transport_data = 4,
};

pub const ParseError = error{
    InvalidLength,
    InvalidType,
    ReservedNotZero,
    TooLarge,
};

/// WireGuard writes the type as a little-endian u32 whose upper three bytes
/// must be zero.
pub fn messageType(bytes: []const u8) ParseError!MessageType {
    if (bytes.len < 4) return error.InvalidLength;
    const raw = std.mem.readInt(u32, bytes[0..4], .little);
    if (raw & 0x00ff_ff00 != 0) return error.ReservedNotZero;
    return switch (raw & 0xff) {
        1 => .handshake_initiation,
        2 => .handshake_response,
        3 => .cookie_reply,
        4 => .transport_data,
        else => error.InvalidType,
    };
}

pub const Initiation = struct {
    raw: [initiation_size]u8,

    pub const sender_offset = 4;
    pub const ephemeral_offset = 8;
    pub const static_offset = 40;
    pub const timestamp_offset = 88;
    pub const mac1_offset = 116;
    pub const mac2_offset = 132;

    pub fn parse(input: []const u8) ParseError!Initiation {
        if (input.len != initiation_size) return error.InvalidLength;
        const kind = try messageType(input);
        if (kind != .handshake_initiation) return error.InvalidType;
        return .{ .raw = input[0..initiation_size].* };
    }

    pub fn init() Initiation {
        var message = Initiation{ .raw = [_]u8{0} ** initiation_size };
        std.mem.writeInt(u32, message.raw[0..4], 1, .little);
        return message;
    }

    pub fn bytes(self: *const Initiation) []const u8 {
        return &self.raw;
    }

    pub fn bytesMut(self: *Initiation) []u8 {
        return &self.raw;
    }

    pub fn sender(self: *const Initiation) u32 {
        return std.mem.readInt(u32, self.raw[sender_offset..][0..4], .little);
    }

    pub fn setSender(self: *Initiation, index: u32) void {
        std.mem.writeInt(u32, self.raw[sender_offset..][0..4], index, .little);
    }

    pub fn ephemeral(self: *const Initiation) []const u8 {
        return self.raw[ephemeral_offset..][0..32];
    }

    pub fn setEphemeral(self: *Initiation, key: [32]u8) void {
        self.raw[ephemeral_offset..][0..32].* = key;
    }

    pub fn encryptedStatic(self: *const Initiation) []const u8 {
        return self.raw[static_offset..][0..48];
    }

    pub fn encryptedTimestamp(self: *const Initiation) []const u8 {
        return self.raw[timestamp_offset..][0..28];
    }

    pub fn mac1(self: *const Initiation) []const u8 {
        return self.raw[mac1_offset..][0..mac1_size];
    }

    pub fn mac2(self: *const Initiation) []const u8 {
        return self.raw[mac2_offset..][0..mac2_size];
    }

    pub fn setMac1(self: *Initiation, mac: [mac1_size]u8) void {
        self.raw[mac1_offset..][0..mac1_size].* = mac;
    }

    pub fn setMac2(self: *Initiation, mac: [mac2_size]u8) void {
        self.raw[mac2_offset..][0..mac2_size].* = mac;
    }

    /// Bytes covered by MAC1, including the MAC1 field when MAC2 is computed.
    pub fn authenticatedPrefix(self: *const Initiation) []const u8 {
        return self.raw[0..mac2_offset];
    }

    pub fn mac1Input(self: *const Initiation) []const u8 {
        return self.raw[0..mac1_offset];
    }

    pub fn mac2Input(self: *const Initiation) []const u8 {
        return self.raw[0..mac2_offset];
    }
};

pub const Response = struct {
    raw: [response_size]u8,

    pub const sender_offset = 4;
    pub const receiver_offset = 8;
    pub const ephemeral_offset = 12;
    pub const empty_offset = 44;
    pub const mac1_offset = 60;
    pub const mac2_offset = 76;

    pub fn parse(input: []const u8) ParseError!Response {
        if (input.len != response_size) return error.InvalidLength;
        const kind = try messageType(input);
        if (kind != .handshake_response) return error.InvalidType;
        return .{ .raw = input[0..response_size].* };
    }

    pub fn init() Response {
        var message = Response{ .raw = [_]u8{0} ** response_size };
        std.mem.writeInt(u32, message.raw[0..4], 2, .little);
        return message;
    }

    pub fn bytes(self: *const Response) []const u8 {
        return &self.raw;
    }

    pub fn bytesMut(self: *Response) []u8 {
        return &self.raw;
    }

    pub fn sender(self: *const Response) u32 {
        return std.mem.readInt(u32, self.raw[sender_offset..][0..4], .little);
    }

    pub fn setSender(self: *Response, index: u32) void {
        std.mem.writeInt(u32, self.raw[sender_offset..][0..4], index, .little);
    }

    pub fn receiver(self: *const Response) u32 {
        return std.mem.readInt(u32, self.raw[receiver_offset..][0..4], .little);
    }

    pub fn setReceiver(self: *Response, index: u32) void {
        std.mem.writeInt(u32, self.raw[receiver_offset..][0..4], index, .little);
    }

    pub fn ephemeral(self: *const Response) []const u8 {
        return self.raw[ephemeral_offset..][0..32];
    }

    pub fn setEphemeral(self: *Response, key: [32]u8) void {
        self.raw[ephemeral_offset..][0..32].* = key;
    }

    pub fn empty(self: *const Response) []const u8 {
        return self.raw[empty_offset..][0..16];
    }

    pub fn mac1(self: *const Response) []const u8 {
        return self.raw[mac1_offset..][0..mac1_size];
    }

    pub fn mac2(self: *const Response) []const u8 {
        return self.raw[mac2_offset..][0..mac2_size];
    }

    pub fn setMac1(self: *Response, mac: [mac1_size]u8) void {
        self.raw[mac1_offset..][0..mac1_size].* = mac;
    }

    pub fn setMac2(self: *Response, mac: [mac2_size]u8) void {
        self.raw[mac2_offset..][0..mac2_size].* = mac;
    }

    pub fn authenticatedPrefix(self: *const Response) []const u8 {
        return self.raw[0..mac2_offset];
    }

    pub fn mac1Input(self: *const Response) []const u8 {
        return self.raw[0..mac1_offset];
    }

    pub fn mac2Input(self: *const Response) []const u8 {
        return self.raw[0..mac2_offset];
    }
};

pub const CookieReply = struct {
    raw: [cookie_reply_size]u8,

    pub const receiver_offset = 4;
    pub const nonce_offset = 8;
    pub const cookie_offset = 32;

    pub fn parse(input: []const u8) ParseError!CookieReply {
        if (input.len != cookie_reply_size) return error.InvalidLength;
        const kind = try messageType(input);
        if (kind != .cookie_reply) return error.InvalidType;
        return .{ .raw = input[0..cookie_reply_size].* };
    }

    pub fn init() CookieReply {
        var message = CookieReply{ .raw = [_]u8{0} ** cookie_reply_size };
        std.mem.writeInt(u32, message.raw[0..4], 3, .little);
        return message;
    }

    pub fn bytes(self: *const CookieReply) []const u8 {
        return &self.raw;
    }

    pub fn bytesMut(self: *CookieReply) []u8 {
        return &self.raw;
    }

    pub fn receiver(self: *const CookieReply) u32 {
        return std.mem.readInt(u32, self.raw[receiver_offset..][0..4], .little);
    }

    pub fn setReceiver(self: *CookieReply, index: u32) void {
        std.mem.writeInt(u32, self.raw[receiver_offset..][0..4], index, .little);
    }

    pub fn nonce(self: *const CookieReply) [24]u8 {
        return self.raw[nonce_offset..][0..24].*;
    }

    pub fn setNonce(self: *CookieReply, value: [24]u8) void {
        self.raw[nonce_offset..][0..24].* = value;
    }

    pub fn encryptedCookie(self: *const CookieReply) []const u8 {
        return self.raw[cookie_offset..][0..32];
    }
};

pub const Transport = struct {
    raw: []const u8,

    pub const receiver_offset = 4;
    pub const counter_offset = 8;
    pub const content_offset = 16;

    pub fn parse(bytes: []const u8) ParseError!Transport {
        if (bytes.len < keepalive_size) return error.InvalidLength;
        if (bytes.len > max_transport_size) return error.TooLarge;
        const kind = try messageType(bytes);
        if (kind != .transport_data) return error.InvalidType;
        return .{ .raw = bytes };
    }

    pub fn receiver(self: Transport) u32 {
        return std.mem.readInt(u32, self.raw[receiver_offset..][0..4], .little);
    }

    pub fn counter(self: Transport) u64 {
        return std.mem.readInt(u64, self.raw[counter_offset..][0..8], .little);
    }

    pub fn header(self: Transport) []const u8 {
        return self.raw[0..transport_header_size];
    }

    pub fn content(self: Transport) []const u8 {
        return self.raw[content_offset..];
    }
};

/// Pads a plaintext length to the WireGuard 16-byte multiple, excluding the
/// AEAD tag. Returns null when the padded message cannot fit `max_total`.
pub fn paddedLength(plaintext_len: usize) usize {
    return (plaintext_len + padding_multiple - 1) &
        ~(@as(usize, padding_multiple) - 1);
}

test "rejects wrong lengths and reserved bits" {
    var bytes = [_]u8{0} ** initiation_size;
    std.mem.writeInt(u32, bytes[0..4], 1, .little);
    const message = try Initiation.parse(&bytes);
    try std.testing.expectEqual(@as(u32, 0), message.sender());

    try std.testing.expectError(
        error.InvalidLength,
        Initiation.parse(bytes[0 .. initiation_size - 1]),
    );

    std.mem.writeInt(u32, bytes[0..4], 0x0001_0101, .little);
    try std.testing.expectError(error.ReservedNotZero, Initiation.parse(&bytes));

    std.mem.writeInt(u32, bytes[0..4], 2, .little);
    try std.testing.expectError(error.InvalidType, Initiation.parse(&bytes));
}

test "transport bounds" {
    var bytes = [_]u8{0} ** keepalive_size;
    std.mem.writeInt(u32, bytes[0..4], 4, .little);
    const message = try Transport.parse(&bytes);
    // `content` includes the 16-byte Poly1305 tag; a keepalive carries no
    // plaintext bytes.
    try std.testing.expectEqual(@as(usize, 16), message.content().len);
    try std.testing.expectError(
        error.InvalidLength,
        Transport.parse(bytes[0 .. keepalive_size - 1]),
    );
}

test "padding multiple" {
    try std.testing.expectEqual(@as(usize, 0), paddedLength(0));
    try std.testing.expectEqual(@as(usize, 16), paddedLength(1));
    try std.testing.expectEqual(@as(usize, 16), paddedLength(16));
    try std.testing.expectEqual(@as(usize, 32), paddedLength(17));
}
