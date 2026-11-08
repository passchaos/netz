//! Hysteria v3 wire codec (QUIC control, relay requests, and UDP messages).
//!
//! See the Hysteria protocol specification: all multibyte numbers are big
//! endian. Parsers are bounded and return borrowed slices.

const std = @import("std");

pub const version: u8 = 0x03;
pub const max_auth_bytes: usize = 255;
pub const max_message_bytes: usize = 255;
pub const max_host_bytes: usize = 255;

pub const Error = error{
    Incomplete,
    InvalidVersion,
    InvalidLength,
    InvalidType,
    UnsupportedFragment,
    BufferTooSmall,
};

pub const ClientHello = struct {
    send_bps: u64,
    recv_bps: u64,
    auth: []const u8,
};

pub fn parseClientHello(bytes: []const u8) Error!ClientHello {
    if (bytes.len < 1 + 8 + 8 + 2) return error.Incomplete;
    if (bytes[0] != version) return error.InvalidVersion;
    const send_bps = std.mem.readInt(u64, bytes[1..9], .big);
    const recv_bps = std.mem.readInt(u64, bytes[9..17], .big);
    const auth_len = std.mem.readInt(u16, bytes[17..19], .big);
    if (auth_len > max_auth_bytes) return error.InvalidLength;
    const end = 19 + @as(usize, auth_len);
    if (bytes.len < end) return error.Incomplete;
    return .{
        .send_bps = send_bps,
        .recv_bps = recv_bps,
        .auth = bytes[19..end],
    };
}

pub fn buildClientHello(
    allocator: std.mem.Allocator,
    send_bps: u64,
    recv_bps: u64,
    auth: []const u8,
) ![]u8 {
    if (auth.len > max_auth_bytes) return error.InvalidLength;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.append(allocator, version);
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, send_bps, .big);
    try output.appendSlice(allocator, &number);
    std.mem.writeInt(u64, &number, recv_bps, .big);
    try output.appendSlice(allocator, &number);
    try output.append(allocator, @intCast(auth.len >> 8));
    try output.append(allocator, @intCast(auth.len & 0xff));
    try output.appendSlice(allocator, auth);
    return output.toOwnedSlice(allocator);
}

pub const ServerHello = struct {
    ok: bool,
    send_bps: u64,
    recv_bps: u64,
    message: []const u8,
};

pub fn parseServerHello(bytes: []const u8) Error!ServerHello {
    if (bytes.len < 1 + 8 + 8 + 2) return error.Incomplete;
    const send_bps = std.mem.readInt(u64, bytes[1..9], .big);
    const recv_bps = std.mem.readInt(u64, bytes[9..17], .big);
    const msg_len = std.mem.readInt(u16, bytes[17..19], .big);
    if (msg_len > max_message_bytes) return error.InvalidLength;
    const end = 19 + @as(usize, msg_len);
    if (bytes.len < end) return error.Incomplete;
    return .{
        .ok = bytes[0] != 0,
        .send_bps = send_bps,
        .recv_bps = recv_bps,
        .message = bytes[19..end],
    };
}

pub fn buildServerHello(
    allocator: std.mem.Allocator,
    ok: bool,
    send_bps: u64,
    recv_bps: u64,
    message: []const u8,
) ![]u8 {
    if (message.len > max_message_bytes) return error.InvalidLength;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.append(allocator, if (ok) 1 else 0);
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, send_bps, .big);
    try output.appendSlice(allocator, &number);
    std.mem.writeInt(u64, &number, recv_bps, .big);
    try output.appendSlice(allocator, &number);
    try output.append(allocator, @intCast(message.len >> 8));
    try output.append(allocator, @intCast(message.len & 0xff));
    try output.appendSlice(allocator, message);
    return output.toOwnedSlice(allocator);
}

pub const RequestType = enum(u8) { tcp = 0x00, udp = 0x01 };

pub const Request = struct {
    request_type: RequestType,
    host: []const u8,
    port: u16,
};

pub fn parseRequest(bytes: []const u8) Error!Request {
    if (bytes.len < 1 + 2) return error.Incomplete;
    const request_type: RequestType = switch (bytes[0]) {
        0x00 => .tcp,
        0x01 => .udp,
        else => return error.InvalidType,
    };
    const host_len = std.mem.readInt(u16, bytes[1..3], .big);
    if (host_len > max_host_bytes) return error.InvalidLength;
    const end = 3 + @as(usize, host_len) + 2;
    if (bytes.len < end) return error.Incomplete;
    return .{
        .request_type = request_type,
        .host = bytes[3 .. 3 + @as(usize, host_len)],
        .port = std.mem.readInt(u16, bytes[3 + @as(usize, host_len) ..][0..2], .big),
    };
}

pub fn buildRequest(
    allocator: std.mem.Allocator,
    request_type: RequestType,
    host: []const u8,
    port: u16,
) ![]u8 {
    if (host.len > max_host_bytes) return error.InvalidLength;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.append(allocator, @intFromEnum(request_type));
    try output.append(allocator, @intCast(host.len >> 8));
    try output.append(allocator, @intCast(host.len & 0xff));
    try output.appendSlice(allocator, host);
    try output.append(allocator, @intCast(port >> 8));
    try output.append(allocator, @intCast(port & 0xff));
    return output.toOwnedSlice(allocator);
}

pub const Response = struct {
    ok: bool,
    udp_session_id: u32,
    message: []const u8,
};

pub fn parseResponse(bytes: []const u8) Error!Response {
    if (bytes.len < 1 + 4 + 2) return error.Incomplete;
    const udp_session_id = std.mem.readInt(u32, bytes[1..5], .big);
    const msg_len = std.mem.readInt(u16, bytes[5..7], .big);
    if (msg_len > max_message_bytes) return error.InvalidLength;
    const end = 7 + @as(usize, msg_len);
    if (bytes.len < end) return error.Incomplete;
    return .{
        .ok = bytes[0] != 0,
        .udp_session_id = udp_session_id,
        .message = bytes[7..end],
    };
}

pub fn buildResponse(
    allocator: std.mem.Allocator,
    ok: bool,
    udp_session_id: u32,
    message: []const u8,
) ![]u8 {
    if (message.len > max_message_bytes) return error.InvalidLength;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.append(allocator, if (ok) 1 else 0);
    try output.append(allocator, @intCast(udp_session_id >> 24));
    try output.append(allocator, @intCast((udp_session_id >> 16) & 0xff));
    try output.append(allocator, @intCast((udp_session_id >> 8) & 0xff));
    try output.append(allocator, @intCast(udp_session_id & 0xff));
    try output.append(allocator, @intCast(message.len >> 8));
    try output.append(allocator, @intCast(message.len & 0xff));
    try output.appendSlice(allocator, message);
    return output.toOwnedSlice(allocator);
}

pub const UdpMessage = struct {
    session_id: u32,
    host: []const u8,
    port: u16,
    msg_id: u16,
    frag_id: u8,
    frag_count: u8,
    data: []const u8,
};

pub fn parseUdpMessage(bytes: []const u8) Error!UdpMessage {
    if (bytes.len < 4 + 2) return error.Incomplete;
    const session_id = std.mem.readInt(u32, bytes[0..4], .big);
    const host_len = std.mem.readInt(u16, bytes[4..6], .big);
    if (host_len > max_host_bytes) return error.InvalidLength;
    const host_end = 6 + @as(usize, host_len);
    if (bytes.len < host_end + 2 + 2 + 1 + 1 + 2) return error.Incomplete;
    const port = std.mem.readInt(u16, bytes[host_end..][0..2], .big);
    const msg_id = std.mem.readInt(u16, bytes[host_end + 2 ..][0..2], .big);
    const frag_id = bytes[host_end + 4];
    const frag_count = bytes[host_end + 5];
    if (frag_count == 0 or frag_id >= frag_count) return error.InvalidLength;
    const data_len = std.mem.readInt(u16, bytes[host_end + 6 ..][0..2], .big);
    const end = host_end + 8 + @as(usize, data_len);
    if (bytes.len < end) return error.Incomplete;
    return .{
        .session_id = session_id,
        .host = bytes[6..host_end],
        .port = port,
        .msg_id = msg_id,
        .frag_id = frag_id,
        .frag_count = frag_count,
        .data = bytes[host_end + 8 .. end],
    };
}

pub fn buildUdpMessage(
    allocator: std.mem.Allocator,
    session_id: u32,
    host: []const u8,
    port: u16,
    msg_id: u16,
    frag_id: u8,
    frag_count: u8,
    data: []const u8,
) ![]u8 {
    if (host.len > max_host_bytes or data.len > std.math.maxInt(u16) or
        frag_count == 0 or frag_id >= frag_count)
    {
        return error.InvalidLength;
    }
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.append(allocator, @intCast(session_id >> 24));
    try output.append(allocator, @intCast((session_id >> 16) & 0xff));
    try output.append(allocator, @intCast((session_id >> 8) & 0xff));
    try output.append(allocator, @intCast(session_id & 0xff));
    try output.append(allocator, @intCast(host.len >> 8));
    try output.append(allocator, @intCast(host.len & 0xff));
    try output.appendSlice(allocator, host);
    try output.append(allocator, @intCast(port >> 8));
    try output.append(allocator, @intCast(port & 0xff));
    try output.append(allocator, @intCast(msg_id >> 8));
    try output.append(allocator, @intCast(msg_id & 0xff));
    try output.append(allocator, frag_id);
    try output.append(allocator, frag_count);
    try output.append(allocator, @intCast(data.len >> 8));
    try output.append(allocator, @intCast(data.len & 0xff));
    try output.appendSlice(allocator, data);
    return output.toOwnedSlice(allocator);
}

pub const xplus = struct {
    pub const salt_len: usize = 16;

    /// Wrap one QUIC packet as `[16-byte salt][XOR-obfuscated payload]`.
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

    /// Remove one xplus wrapper. Returns `InvalidLength` for packets shorter
    /// than the salt and never writes outside the returned buffer.
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
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(key);
        hasher.update(&salt);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }
};

test "Hysteria v3 hello, request, response, and UDP messages round trip" {
    const allocator = std.testing.allocator;
    const hello = try buildClientHello(allocator, 1000, 2000, "secret");
    defer allocator.free(hello);
    const parsed_hello = try parseClientHello(hello);
    try std.testing.expectEqual(@as(u64, 1000), parsed_hello.send_bps);
    try std.testing.expectEqualStrings("secret", parsed_hello.auth);

    const response = try buildResponse(allocator, true, 7, "ok");
    defer allocator.free(response);
    const parsed_response = try parseResponse(response);
    try std.testing.expect(parsed_response.ok);
    try std.testing.expectEqual(@as(u32, 7), parsed_response.udp_session_id);

    const request = try buildRequest(allocator, .tcp, "origin.example", 443);
    defer allocator.free(request);
    const parsed_request = try parseRequest(request);
    try std.testing.expectEqual(RequestType.tcp, parsed_request.request_type);
    try std.testing.expectEqualStrings("origin.example", parsed_request.host);
    try std.testing.expectEqual(@as(u16, 443), parsed_request.port);

    const udp = try buildUdpMessage(
        allocator,
        7,
        "127.0.0.1",
        53,
        9,
        0,
        1,
        "dns",
    );
    defer allocator.free(udp);
    const parsed_udp = try parseUdpMessage(udp);
    try std.testing.expectEqual(@as(u32, 7), parsed_udp.session_id);
    try std.testing.expectEqualStrings("dns", parsed_udp.data);
    try std.testing.expectEqual(@as(u8, 1), parsed_udp.frag_count);
}

test "Hysteria xplus obfuscation round trips and rejects short packets" {
    const allocator = std.testing.allocator;
    const salt = [_]u8{0x11} ** xplus.salt_len;
    const payload = "quic packet bytes";
    const wrapped = try xplus.obfuscate(allocator, "secret", salt, payload);
    defer allocator.free(wrapped);
    try std.testing.expectEqual(@as(usize, xplus.salt_len + payload.len), wrapped.len);
    try std.testing.expectEqualSlices(u8, &salt, wrapped[0..xplus.salt_len]);

    const unwrapped = try xplus.deobfuscate(allocator, "secret", wrapped);
    defer allocator.free(unwrapped);
    try std.testing.expectEqualStrings(payload, unwrapped);
    try std.testing.expectError(
        error.InvalidLength,
        xplus.deobfuscate(allocator, "secret", "short"),
    );
}
