//! TLS 1.3 NewSessionTicket codec and resumption-PSK derivation.
//!
//! Slices in `Parsed` borrow from the encoded handshake message.  The owning
//! session cache copies all fields that must outlive packet processing.

const std = @import("std");

const vail = @import("vail");

pub const handshake_type_new_session_ticket: u8 = 0x04;
pub const ext_early_data: u16 = 0x002a;
pub const quic_early_data_size: u32 = std.math.maxInt(u32);
pub const max_lifetime_seconds: u32 = 7 * 24 * 60 * 60;

pub const Error = std.mem.Allocator.Error || error{
    InvalidNewSessionTicket,
    InvalidTicketLifetime,
    InvalidEarlyDataSize,
};

pub const Options = struct {
    lifetime_seconds: u32,
    age_add: u32,
    nonce: []const u8,
    ticket: []const u8,
    allow_early_data: bool = false,
};

pub const Parsed = struct {
    lifetime_seconds: u32,
    age_add: u32,
    nonce: []const u8,
    ticket: []const u8,
    max_early_data_size: ?u32,
};

pub fn write(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: Options,
) Error!void {
    try validateOptions(options);
    const original_len = list.items.len;
    errdefer list.items.len = original_len;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendInt(&body, allocator, u32, options.lifetime_seconds);
    try appendInt(&body, allocator, u32, options.age_add);
    try body.append(allocator, @intCast(options.nonce.len));
    try body.appendSlice(allocator, options.nonce);
    try appendInt(&body, allocator, u16, @intCast(options.ticket.len));
    try body.appendSlice(allocator, options.ticket);
    if (options.allow_early_data) {
        try appendInt(&body, allocator, u16, 8);
        try appendInt(&body, allocator, u16, ext_early_data);
        try appendInt(&body, allocator, u16, @sizeOf(u32));
        try appendInt(&body, allocator, u32, quic_early_data_size);
    } else {
        try appendInt(&body, allocator, u16, 0);
    }
    if (body.items.len > std.math.maxInt(u24)) {
        return error.InvalidNewSessionTicket;
    }

    try list.append(allocator, handshake_type_new_session_ticket);
    var len: [3]u8 = undefined;
    writeU24(&len, @intCast(body.items.len));
    try list.appendSlice(allocator, &len);
    try list.appendSlice(allocator, body.items);
}

pub fn parse(bytes: []const u8) Error!Parsed {
    if (bytes.len < 4 or bytes[0] != handshake_type_new_session_ticket) {
        return error.InvalidNewSessionTicket;
    }
    const body_len = readU24(bytes[1..4]);
    if (body_len + 4 != bytes.len) return error.InvalidNewSessionTicket;
    var pos: usize = 4;

    const lifetime_seconds = try readInt(u32, bytes, &pos);
    if (lifetime_seconds == 0 or
        lifetime_seconds > max_lifetime_seconds)
    {
        return error.InvalidTicketLifetime;
    }
    const age_add = try readInt(u32, bytes, &pos);
    const nonce_len = try readInt(u8, bytes, &pos);
    const nonce = try readSlice(bytes, &pos, nonce_len);
    const ticket_len = try readInt(u16, bytes, &pos);
    if (ticket_len == 0) return error.InvalidNewSessionTicket;
    const ticket = try readSlice(bytes, &pos, ticket_len);
    const extensions_len = try readInt(u16, bytes, &pos);
    const extensions = try readSlice(bytes, &pos, extensions_len);
    if (pos != bytes.len) return error.InvalidNewSessionTicket;

    var early_data_size: ?u32 = null;
    var ext_pos: usize = 0;
    var seen: [64]u16 = undefined;
    var seen_len: usize = 0;
    while (ext_pos < extensions.len) {
        const typ = try readInt(u16, extensions, &ext_pos);
        const len = try readInt(u16, extensions, &ext_pos);
        const payload = try readSlice(extensions, &ext_pos, len);
        for (seen[0..seen_len]) |existing| {
            if (existing == typ) return error.InvalidNewSessionTicket;
        }
        if (seen_len == seen.len) return error.InvalidNewSessionTicket;
        seen[seen_len] = typ;
        seen_len += 1;

        if (typ == ext_early_data) {
            if (payload.len != @sizeOf(u32)) {
                return error.InvalidEarlyDataSize;
            }
            const size = std.mem.readInt(u32, payload[0..4], .big);
            if (size != quic_early_data_size) {
                return error.InvalidEarlyDataSize;
            }
            early_data_size = size;
        }
    }
    return .{
        .lifetime_seconds = lifetime_seconds,
        .age_add = age_add,
        .nonce = nonce,
        .ticket = ticket,
        .max_early_data_size = early_data_size,
    };
}

pub fn deriveResumptionMasterSecret(
    master_secret: [32]u8,
    transcript_hash: [32]u8,
) [32]u8 {
    return vail.tls.key_schedule.deriveResumptionMasterSecret(
        master_secret,
        transcript_hash,
    );
}

pub fn derivePsk(
    resumption_master_secret: [32]u8,
    ticket_nonce: []const u8,
) [32]u8 {
    return vail.tls.key_schedule.deriveResumptionPsk(
        resumption_master_secret,
        ticket_nonce,
    );
}

fn validateOptions(options: Options) Error!void {
    if (options.lifetime_seconds == 0 or
        options.lifetime_seconds > max_lifetime_seconds)
    {
        return error.InvalidTicketLifetime;
    }
    if (options.nonce.len > std.math.maxInt(u8) or
        options.ticket.len == 0 or
        options.ticket.len > std.math.maxInt(u16))
    {
        return error.InvalidNewSessionTicket;
    }
}

fn appendInt(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) std.mem.Allocator.Error!void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try list.appendSlice(allocator, &bytes);
}

fn readInt(
    comptime T: type,
    bytes: []const u8,
    pos: *usize,
) Error!T {
    const slice = try readSlice(bytes, pos, @sizeOf(T));
    return std.mem.readInt(T, slice[0..@sizeOf(T)], .big);
}

fn readSlice(
    bytes: []const u8,
    pos: *usize,
    len: usize,
) Error![]const u8 {
    const end = std.math.add(usize, pos.*, len) catch
        return error.InvalidNewSessionTicket;
    if (end > bytes.len) return error.InvalidNewSessionTicket;
    const result = bytes[pos.*..end];
    pos.* = end;
    return result;
}

fn readU24(bytes: *const [3]u8) usize {
    return (@as(usize, bytes[0]) << 16) |
        (@as(usize, bytes[1]) << 8) |
        bytes[2];
}

fn writeU24(bytes: *[3]u8, value: u24) void {
    bytes[0] = @truncate(value >> 16);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value);
}
