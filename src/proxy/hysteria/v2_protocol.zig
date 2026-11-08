//! Hysteria 2 wire codec: QUIC varints, TCP request/response messages,
//! UDP datagram framing, and Salamander packet obfuscation.

const std = @import("std");

pub const tcp_request_id: u64 = 0x401;
pub const max_address_bytes: usize = 255;
pub const max_padding_bytes: usize = 255;
pub const max_message_bytes: usize = 255;
pub const salamander_salt_len: usize = 8;

pub const Error = error{
    Incomplete,
    InvalidVarInt,
    InvalidMessage,
    InvalidLength,
    BufferTooSmall,
};

pub const DecodedVarInt = struct {
    value: u64,
    len: usize,
};

pub fn encodeVarInt(output: []u8, value: u64) Error!usize {
    if (value < (1 << 6)) {
        if (output.len < 1) return error.BufferTooSmall;
        output[0] = @intCast(value);
        return 1;
    }
    if (value < (1 << 14)) {
        if (output.len < 2) return error.BufferTooSmall;
        output[0] = @intCast(0x40 | (value >> 8));
        output[1] = @intCast(value & 0xff);
        return 2;
    }
    if (value < (1 << 30)) {
        if (output.len < 4) return error.BufferTooSmall;
        output[0] = @intCast(0x80 | (value >> 24));
        output[1] = @intCast((value >> 16) & 0xff);
        output[2] = @intCast((value >> 8) & 0xff);
        output[3] = @intCast(value & 0xff);
        return 4;
    }
    if (value < (1 << 62)) {
        if (output.len < 8) return error.BufferTooSmall;
        output[0] = @intCast(0xc0 | (value >> 56));
        output[1] = @intCast((value >> 48) & 0xff);
        output[2] = @intCast((value >> 40) & 0xff);
        output[3] = @intCast((value >> 32) & 0xff);
        output[4] = @intCast((value >> 24) & 0xff);
        output[5] = @intCast((value >> 16) & 0xff);
        output[6] = @intCast((value >> 8) & 0xff);
        output[7] = @intCast(value & 0xff);
        return 8;
    }
    return error.InvalidVarInt;
}

pub fn decodeVarInt(bytes: []const u8) Error!DecodedVarInt {
    if (bytes.len == 0) return error.Incomplete;
    const prefix = bytes[0] >> 6;
    const len: usize = switch (prefix) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (bytes.len < len) return error.Incomplete;
    var value: u64 = bytes[0] & 0x3f;
    for (bytes[1..len]) |byte| {
        value = (value << 8) | byte;
    }
    return .{ .value = value, .len = len };
}

pub const TcpRequest = struct {
    address: []const u8,
    padding: []const u8,
    end: usize,
};

pub fn parseTcpRequest(bytes: []const u8) Error!TcpRequest {
    const id = try decodeVarInt(bytes);
    if (id.value != tcp_request_id) return error.InvalidMessage;
    var offset = id.len;
    const address_len = try decodeVarInt(bytes[offset..]);
    offset += address_len.len;
    if (address_len.value > max_address_bytes) return error.InvalidLength;
    const address_end = offset + @as(usize, @intCast(address_len.value));
    if (bytes.len < address_end) return error.Incomplete;
    const address = bytes[offset..address_end];
    offset = address_end;
    const padding_len = try decodeVarInt(bytes[offset..]);
    offset += padding_len.len;
    if (padding_len.value > max_padding_bytes) return error.InvalidLength;
    const end = offset + @as(usize, @intCast(padding_len.value));
    if (bytes.len < end) return error.Incomplete;
    return .{
        .address = address,
        .padding = bytes[offset..end],
        .end = end,
    };
}

pub fn buildTcpRequest(
    allocator: std.mem.Allocator,
    address: []const u8,
    padding: []const u8,
) ![]u8 {
    if (address.len > max_address_bytes or padding.len > max_padding_bytes) {
        return error.InvalidLength;
    }
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    var varint: [8]u8 = undefined;
    const id_len = try encodeVarInt(&varint, tcp_request_id);
    try output.appendSlice(allocator, varint[0..id_len]);
    const addr_len = try encodeVarInt(&varint, address.len);
    try output.appendSlice(allocator, varint[0..addr_len]);
    try output.appendSlice(allocator, address);
    const pad_len = try encodeVarInt(&varint, padding.len);
    try output.appendSlice(allocator, varint[0..pad_len]);
    try output.appendSlice(allocator, padding);
    return output.toOwnedSlice(allocator);
}

pub const TcpResponse = struct {
    ok: bool,
    message: []const u8,
    padding: []const u8,
    end: usize,
};

pub fn parseTcpResponse(bytes: []const u8) Error!TcpResponse {
    if (bytes.len < 1) return error.Incomplete;
    const ok = bytes[0] == 0;
    if (bytes[0] > 1) return error.InvalidMessage;
    var offset: usize = 1;
    const message_len = try decodeVarInt(bytes[offset..]);
    offset += message_len.len;
    if (message_len.value > max_message_bytes) return error.InvalidLength;
    const message_end = offset + @as(usize, @intCast(message_len.value));
    if (bytes.len < message_end) return error.Incomplete;
    const message = bytes[offset..message_end];
    offset = message_end;
    const padding_len = try decodeVarInt(bytes[offset..]);
    offset += padding_len.len;
    if (padding_len.value > max_padding_bytes) return error.InvalidLength;
    const end = offset + @as(usize, @intCast(padding_len.value));
    if (bytes.len < end) return error.Incomplete;
    return .{
        .ok = ok,
        .message = message,
        .padding = bytes[offset..end],
        .end = end,
    };
}

pub fn buildTcpResponse(
    allocator: std.mem.Allocator,
    ok: bool,
    message: []const u8,
    padding: []const u8,
) ![]u8 {
    if (message.len > max_message_bytes or padding.len > max_padding_bytes) {
        return error.InvalidLength;
    }
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.append(allocator, if (ok) 0 else 1);
    var varint: [8]u8 = undefined;
    const message_len = try encodeVarInt(&varint, message.len);
    try output.appendSlice(allocator, varint[0..message_len]);
    try output.appendSlice(allocator, message);
    const pad_len = try encodeVarInt(&varint, padding.len);
    try output.appendSlice(allocator, varint[0..pad_len]);
    try output.appendSlice(allocator, padding);
    return output.toOwnedSlice(allocator);
}

pub const UdpMessage = struct {
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    address: []const u8,
    payload: []const u8,
    end: usize,
};

pub fn parseUdpMessage(bytes: []const u8) Error!UdpMessage {
    if (bytes.len < 4 + 2 + 1 + 1) return error.Incomplete;
    const session_id = std.mem.readInt(u32, bytes[0..4], .big);
    const packet_id = std.mem.readInt(u16, bytes[4..6], .big);
    const frag_id = bytes[6];
    const frag_count = bytes[7];
    if (frag_count == 0 or frag_id >= frag_count) return error.InvalidMessage;
    var offset: usize = 8;
    const address_len = try decodeVarInt(bytes[offset..]);
    offset += address_len.len;
    if (address_len.value > max_address_bytes) return error.InvalidLength;
    const address_end = offset + @as(usize, @intCast(address_len.value));
    if (bytes.len < address_end) return error.Incomplete;
    const address = bytes[offset..address_end];
    return .{
        .session_id = session_id,
        .packet_id = packet_id,
        .frag_id = frag_id,
        .frag_count = frag_count,
        .address = address,
        .payload = bytes[address_end..],
        .end = bytes.len,
    };
}

pub fn buildUdpMessage(
    allocator: std.mem.Allocator,
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    address: []const u8,
    payload: []const u8,
) ![]u8 {
    if (address.len > max_address_bytes or frag_count == 0 or
        frag_id >= frag_count)
    {
        return error.InvalidLength;
    }
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    var number: [4]u8 = undefined;
    std.mem.writeInt(u32, &number, session_id, .big);
    try output.appendSlice(allocator, &number);
    var packet: [2]u8 = undefined;
    std.mem.writeInt(u16, &packet, packet_id, .big);
    try output.appendSlice(allocator, &packet);
    try output.append(allocator, frag_id);
    try output.append(allocator, frag_count);
    var varint: [8]u8 = undefined;
    const addr_len = try encodeVarInt(&varint, address.len);
    try output.appendSlice(allocator, varint[0..addr_len]);
    try output.appendSlice(allocator, address);
    try output.appendSlice(allocator, payload);
    return output.toOwnedSlice(allocator);
}

pub const max_head_bytes: usize = 16 * 1024;
pub const max_header_line_bytes: usize = 8 * 1024;
pub const max_headers: usize = 64;
pub const max_auth_bytes: usize = 1024;

fn headerColon(line: []const u8) ?usize {
    if (line.len == 0) return null;
    if (line[0] == ':') {
        const index = std.mem.findScalar(u8, line[1..], ':') orelse return null;
        return index + 1;
    }
    return std.mem.findScalar(u8, line, ':');
}

pub const AuthRequest = struct {
    auth: []const u8,
    cc_rx: u64,
    padding: []const u8,
};

/// Parse the HTTP/3 HEADERS payload used for Hysteria 2 authentication.
pub fn parseAuthRequest(head: []const u8) Error!AuthRequest {
    if (head.len > max_head_bytes) return error.InvalidLength;
    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var host: ?[]const u8 = null;
    var auth: ?[]const u8 = null;
    var cc_rx: u64 = 0;
    var padding: []const u8 = "";
    var header_count: usize = 0;

    var lines = std.mem.splitScalar(u8, head, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        if (line.len > max_header_line_bytes) return error.InvalidLength;
        header_count += 1;
        if (header_count > max_headers) return error.InvalidMessage;
        const colon = headerColon(line) orelse return error.InvalidMessage;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, ":method")) {
            method = value;
        } else if (std.ascii.eqlIgnoreCase(name, ":path")) {
            path = value;
        } else if (std.ascii.eqlIgnoreCase(name, ":host")) {
            host = value;
        } else if (std.ascii.eqlIgnoreCase(name, "hysteria-auth")) {
            if (auth != null or value.len == 0 or value.len > max_auth_bytes) {
                return error.InvalidMessage;
            }
            auth = value;
        } else if (std.ascii.eqlIgnoreCase(name, "hysteria-cc-rx")) {
            cc_rx = std.fmt.parseInt(u64, value, 10) catch
                return error.InvalidMessage;
        } else if (std.ascii.eqlIgnoreCase(name, "hysteria-padding")) {
            if (value.len > max_padding_bytes) return error.InvalidLength;
            padding = value;
        }
    }

    if (method == null or !std.mem.eql(u8, method.?, "POST")) {
        return error.InvalidMessage;
    }
    if (path == null or !std.mem.eql(u8, path.?, "/auth")) {
        return error.InvalidMessage;
    }
    if (host == null or !std.mem.eql(u8, host.?, "hysteria")) {
        return error.InvalidMessage;
    }
    return .{
        .auth = auth orelse return error.InvalidMessage,
        .cc_rx = cc_rx,
        .padding = padding,
    };
}

pub fn buildAuthRequest(
    allocator: std.mem.Allocator,
    auth: []const u8,
    cc_rx: u64,
    padding: []const u8,
) ![]u8 {
    if (auth.len == 0 or auth.len > max_auth_bytes or
        padding.len > max_padding_bytes)
    {
        return error.InvalidLength;
    }
    return std.fmt.allocPrint(
        allocator,
        ":method: POST\r\n:path: /auth\r\n:host: hysteria\r\n" ++
            "Hysteria-Auth: {s}\r\nHysteria-CC-RX: {d}\r\n" ++
            "Hysteria-Padding: {s}\r\n\r\n",
        .{ auth, cc_rx, padding },
    );
}

pub const AuthResponse = struct {
    udp: bool,
    cc_rx: ?u64,
    padding: []const u8,
};

pub fn parseAuthResponse(head: []const u8) Error!AuthResponse {
    if (head.len > max_head_bytes) return error.InvalidLength;
    var status: ?[]const u8 = null;
    var udp: bool = false;
    var cc_rx: ?u64 = null;
    var padding: []const u8 = "";
    var header_count: usize = 0;
    var lines = std.mem.splitScalar(u8, head, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        if (line.len > max_header_line_bytes) return error.InvalidLength;
        header_count += 1;
        if (header_count > max_headers) return error.InvalidMessage;
        const colon = headerColon(line) orelse return error.InvalidMessage;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, ":status")) {
            status = value;
        } else if (std.ascii.eqlIgnoreCase(name, "hysteria-udp")) {
            udp = std.ascii.eqlIgnoreCase(value, "true");
        } else if (std.ascii.eqlIgnoreCase(name, "hysteria-cc-rx")) {
            if (std.ascii.eqlIgnoreCase(value, "auto")) {
                cc_rx = null;
            } else {
                cc_rx = std.fmt.parseInt(u64, value, 10) catch
                    return error.InvalidMessage;
            }
        } else if (std.ascii.eqlIgnoreCase(name, "hysteria-padding")) {
            if (value.len > max_padding_bytes) return error.InvalidLength;
            padding = value;
        }
    }
    if (status == null or !std.mem.eql(u8, status.?, "233")) {
        return error.InvalidMessage;
    }
    return .{ .udp = udp, .cc_rx = cc_rx, .padding = padding };
}

pub fn buildAuthResponse(
    allocator: std.mem.Allocator,
    udp: bool,
    cc_rx: ?u64,
    padding: []const u8,
) ![]u8 {
    if (padding.len > max_padding_bytes) return error.InvalidLength;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.appendSlice(allocator, ":status: 233\r\n");
    try output.appendSlice(
        allocator,
        if (udp) "Hysteria-UDP: true\r\n" else "Hysteria-UDP: false\r\n",
    );
    if (cc_rx) |value| {
        const line = try std.fmt.allocPrint(
            allocator,
            "Hysteria-CC-RX: {d}\r\n",
            .{value},
        );
        defer allocator.free(line);
        try output.appendSlice(allocator, line);
    } else {
        try output.appendSlice(allocator, "Hysteria-CC-RX: auto\r\n");
    }
    try output.appendSlice(allocator, "Hysteria-Padding: ");
    try output.appendSlice(allocator, padding);
    try output.appendSlice(allocator, "\r\n\r\n");
    return output.toOwnedSlice(allocator);
}

pub const gecko = struct {
    pub const flags: u8 = 0x80;
    pub const min_chunks: u8 = 2;
    pub const max_chunks: u8 = 8;

    pub const Frame = struct {
        msg_id: u8,
        chunk_idx: u8,
        total_chunks: u8,
        padding: []const u8,
        chunk: []const u8,
        end: usize,
    };

    pub fn shouldFragment(packet: []const u8) bool {
        return packet.len > 0 and (packet[0] & 0x80) != 0;
    }

    pub fn parseFrame(bytes: []const u8) Error!Frame {
        if (bytes.len < 4) return error.Incomplete;
        if (bytes[0] != flags) return error.InvalidMessage;
        const msg_id = bytes[1];
        const chunk_idx = bytes[2] >> 4;
        const total_chunks = bytes[2] & 0x0f;
        if (total_chunks < min_chunks or total_chunks > max_chunks or
            chunk_idx >= total_chunks)
        {
            return error.InvalidMessage;
        }
        const pad_len = std.mem.readInt(u16, bytes[3..5], .big);
        const padding_end = 5 + @as(usize, pad_len);
        if (bytes.len < padding_end) return error.Incomplete;
        return .{
            .msg_id = msg_id,
            .chunk_idx = chunk_idx,
            .total_chunks = total_chunks,
            .padding = bytes[5..padding_end],
            .chunk = bytes[padding_end..],
            .end = bytes.len,
        };
    }

    pub fn buildFrame(
        allocator: std.mem.Allocator,
        msg_id: u8,
        chunk_idx: u8,
        total_chunks: u8,
        padding: []const u8,
        chunk: []const u8,
    ) ![]u8 {
        if (total_chunks < min_chunks or total_chunks > max_chunks or
            chunk_idx >= total_chunks or padding.len > std.math.maxInt(u16))
        {
            return error.InvalidLength;
        }
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);
        try output.append(allocator, flags);
        try output.append(allocator, msg_id);
        try output.append(allocator, (chunk_idx << 4) | total_chunks);
        var pad_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &pad_len, @intCast(padding.len), .big);
        try output.appendSlice(allocator, &pad_len);
        try output.appendSlice(allocator, padding);
        try output.appendSlice(allocator, chunk);
        return output.toOwnedSlice(allocator);
    }
};

pub const salamander = struct {
    pub const salt_len: usize = salamander_salt_len;

    pub fn obfuscate(
        allocator: std.mem.Allocator,
        key: []const u8,
        salt: [salt_len]u8,
        payload: []const u8,
    ) ![]u8 {
        const output = try allocator.alloc(u8, salt_len + payload.len);
        @memcpy(output[0..salt_len], &salt);
        const hash = saltedHash(key, salt);
        for (payload, 0..) |byte, index| {
            output[salt_len + index] = byte ^ hash[index % 32];
        }
        return output;
    }

    pub fn deobfuscate(
        allocator: std.mem.Allocator,
        key: []const u8,
        packet: []const u8,
    ) ![]u8 {
        if (packet.len < salt_len) return error.InvalidLength;
        const salt: [salt_len]u8 = packet[0..salt_len].*;
        const hash = saltedHash(key, salt);
        const output = try allocator.alloc(u8, packet.len - salt_len);
        for (packet[salt_len..], 0..) |byte, index| {
            output[index] = byte ^ hash[index % 32];
        }
        return output;
    }

    fn saltedHash(key: []const u8, salt: [salt_len]u8) [32]u8 {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(key);
        hasher.update(&salt);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }
};

test "Hysteria 2 auth request and response round trip" {
    const allocator = std.testing.allocator;
    const request = try buildAuthRequest(allocator, "secret", 1000, "pad");
    defer allocator.free(request);
    const parsed = try parseAuthRequest(request);
    try std.testing.expectEqualStrings("secret", parsed.auth);
    try std.testing.expectEqual(@as(u64, 1000), parsed.cc_rx);
    try std.testing.expectEqualStrings("pad", parsed.padding);

    const response = try buildAuthResponse(allocator, true, 2000, "pad");
    defer allocator.free(response);
    const parsed_response = try parseAuthResponse(response);
    try std.testing.expect(parsed_response.udp);
    try std.testing.expectEqual(@as(?u64, 2000), parsed_response.cc_rx);
    try std.testing.expectEqualStrings("pad", parsed_response.padding);

    const auto = try buildAuthResponse(allocator, false, null, "");
    defer allocator.free(auto);
    const parsed_auto = try parseAuthResponse(auto);
    try std.testing.expect(!parsed_auto.udp);
    try std.testing.expectEqual(@as(?u64, null), parsed_auto.cc_rx);
}

test "Hysteria 2 Gecko frames round trip" {
    const allocator = std.testing.allocator;
    const frame = try gecko.buildFrame(allocator, 7, 0, 2, "pad", "chunk");
    defer allocator.free(frame);
    const parsed = try gecko.parseFrame(frame);
    try std.testing.expectEqual(@as(u8, 7), parsed.msg_id);
    try std.testing.expectEqual(@as(u8, 0), parsed.chunk_idx);
    try std.testing.expectEqual(@as(u8, 2), parsed.total_chunks);
    try std.testing.expectEqualStrings("pad", parsed.padding);
    try std.testing.expectEqualStrings("chunk", parsed.chunk);
    try std.testing.expect(gecko.shouldFragment(&[_]u8{0x80}));
    try std.testing.expect(!gecko.shouldFragment(&[_]u8{0x00}));
}

test "Hysteria 2 varints round trip" {
    const values = [_]u64{ 0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30 };
    var storage: [8]u8 = undefined;
    for (values) |value| {
        const len = try encodeVarInt(&storage, value);
        const decoded = try decodeVarInt(storage[0..len]);
        try std.testing.expectEqual(value, decoded.value);
        try std.testing.expectEqual(len, decoded.len);
    }
}

test "Hysteria 2 TCP request and response round trip" {
    const allocator = std.testing.allocator;
    const request = try buildTcpRequest(allocator, "example.com:443", "pad");
    defer allocator.free(request);
    const parsed = try parseTcpRequest(request);
    try std.testing.expectEqualStrings("example.com:443", parsed.address);
    try std.testing.expectEqualStrings("pad", parsed.padding);

    const response = try buildTcpResponse(allocator, true, "ok", "x");
    defer allocator.free(response);
    const parsed_response = try parseTcpResponse(response);
    try std.testing.expect(parsed_response.ok);
    try std.testing.expectEqualStrings("ok", parsed_response.message);
}

test "Hysteria 2 UDP message and Salamander round trip" {
    const allocator = std.testing.allocator;
    const message = try buildUdpMessage(
        allocator,
        7,
        9,
        0,
        1,
        "127.0.0.1:53",
        "dns",
    );
    defer allocator.free(message);
    const parsed = try parseUdpMessage(message);
    try std.testing.expectEqual(@as(u32, 7), parsed.session_id);
    try std.testing.expectEqualStrings("127.0.0.1:53", parsed.address);
    try std.testing.expectEqualStrings("dns", parsed.payload);

    const salt = [_]u8{0x11} ** salamander.salt_len;
    const wrapped = try salamander.obfuscate(allocator, "secret", salt, "packet");
    defer allocator.free(wrapped);
    const unwrapped = try salamander.deobfuscate(allocator, "secret", wrapped);
    defer allocator.free(unwrapped);
    try std.testing.expectEqualStrings("packet", unwrapped);
}
