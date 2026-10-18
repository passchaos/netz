//! RFC 9484 request scope and default MASQUE path codec.

const std = @import("std");

const net = std.Io.net;

pub const Error = error{
    BufferTooShort,
    IntegerOverflow,
    InvalidScope,
};

pub const default_path_prefix = "/.well-known/masque/ip/";

/// CONNECT-IP request scope. `target = "*"` and `ip_protocol = null` request
/// wildcard routing. A non-wildcard target is a reg-name or canonical IP
/// address, optionally followed by `/prefix-length`.
pub const Scope = struct {
    target: []const u8 = "*",
    ip_protocol: ?u8 = null,

    pub fn validate(self: Scope) error{InvalidScope}!void {
        try validateTarget(self.target);
    }
};

pub fn defaultPathLen(scope: Scope) Error!usize {
    try scope.validate();
    const target_len = encodedTargetLen(scope.target) catch
        return error.IntegerOverflow;
    const protocol_len: usize = if (scope.ip_protocol) |protocol|
        decimalLen(protocol)
    else
        1;
    return std.math.add(
        usize,
        default_path_prefix.len + 2 + protocol_len,
        target_len,
    ) catch return error.IntegerOverflow;
}

pub fn writeDefaultPath(out: []u8, scope: Scope) Error![]u8 {
    const needed = try defaultPathLen(scope);
    if (out.len < needed) return error.BufferTooShort;
    @memcpy(out[0..default_path_prefix.len], default_path_prefix);
    var offset = default_path_prefix.len;
    offset += writeEncodedTarget(out[offset..], scope.target);
    out[offset] = '/';
    offset += 1;
    if (scope.ip_protocol) |protocol| {
        const text = std.fmt.bufPrint(out[offset..], "{d}", .{protocol}) catch
            return error.BufferTooShort;
        offset += text.len;
    } else {
        out[offset] = '*';
        offset += 1;
    }
    out[offset] = '/';
    offset += 1;
    std.debug.assert(offset == needed);
    return out[0..offset];
}

/// Parse RFC 9484's default path. `Scope.target` borrows `target_out`.
pub fn parseDefaultPath(
    path: []const u8,
    target_out: []u8,
) Error!Scope {
    if (!std.mem.startsWith(u8, path, default_path_prefix) or
        path.len <= default_path_prefix.len + 2 or
        path[path.len - 1] != '/')
    {
        return error.InvalidScope;
    }
    const value = path[default_path_prefix.len .. path.len - 1];
    const separator = std.mem.indexOfScalar(u8, value, '/') orelse
        return error.InvalidScope;
    if (separator == 0 or separator + 1 >= value.len or
        std.mem.indexOfScalar(u8, value[separator + 1 ..], '/') != null)
    {
        return error.InvalidScope;
    }
    const target = try decodeTarget(value[0..separator], target_out);
    var protocol_storage: [3]u8 = undefined;
    const protocol_text = decodeTarget(
        value[separator + 1 ..],
        &protocol_storage,
    ) catch |err| switch (err) {
        error.BufferTooShort => return error.InvalidScope,
        else => |other| return other,
    };
    const protocol = if (std.mem.eql(u8, protocol_text, "*"))
        null
    else protocol: {
        for (protocol_text) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidScope;
        }
        break :protocol std.fmt.parseUnsigned(
            u8,
            protocol_text,
            10,
        ) catch return error.InvalidScope;
    };
    const scope = Scope{ .target = target, .ip_protocol = protocol };
    try scope.validate();
    return scope;
}

fn validateTarget(target: []const u8) error{InvalidScope}!void {
    if (target.len == 0 or std.mem.indexOfScalar(u8, target, '%') != null) {
        return error.InvalidScope;
    }
    if (std.mem.eql(u8, target, "*")) return;

    const slash = std.mem.indexOfScalar(u8, target, '/');
    const address_text = if (slash) |index| target[0..index] else target;
    if (slash) |index| {
        if (index == 0 or index + 1 >= target.len or
            std.mem.indexOfScalar(u8, target[index + 1 ..], '/') != null)
        {
            return error.InvalidScope;
        }
        const prefix_text = target[index + 1 ..];
        for (prefix_text) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidScope;
        }
        if (std.mem.indexOfScalar(u8, address_text, ':') != null) {
            const prefix = std.fmt.parseUnsigned(u8, prefix_text, 10) catch
                return error.InvalidScope;
            if (prefix > 128) return error.InvalidScope;
            const address = net.Ip6Address.parse(address_text, 0) catch
                return error.InvalidScope;
            if (!hostBitsZero(&address.bytes, prefix)) {
                return error.InvalidScope;
            }
            return;
        }
        const prefix = std.fmt.parseUnsigned(u8, prefix_text, 10) catch
            return error.InvalidScope;
        if (prefix > 32) return error.InvalidScope;
        const address = net.Ip4Address.parse(address_text, 0) catch
            return error.InvalidScope;
        if (!hostBitsZero(&address.bytes, prefix)) {
            return error.InvalidScope;
        }
        return;
    }

    if (std.mem.indexOfScalar(u8, address_text, ':') != null) {
        _ = net.Ip6Address.parse(address_text, 0) catch
            return error.InvalidScope;
        return;
    }
    if (net.Ip4Address.parse(address_text, 0)) |_| {
        return;
    } else |_| {}
    for (address_text) |byte| {
        if (!isRegNameByte(byte)) return error.InvalidScope;
    }
}

fn hostBitsZero(bytes: []const u8, prefix_length: u8) bool {
    const full_bytes = prefix_length / 8;
    const partial_bits = prefix_length % 8;
    var index: usize = full_bytes;
    if (partial_bits != 0) {
        const host_mask: u8 = (@as(u8, 1) << @intCast(8 - partial_bits)) - 1;
        if ((bytes[index] & host_mask) != 0) return false;
        index += 1;
    }
    for (bytes[index..]) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn decodeTarget(encoded: []const u8, out: []u8) Error![]const u8 {
    var out_len: usize = 0;
    var index: usize = 0;
    while (index < encoded.len) {
        const decoded = if (encoded[index] == '%') decoded: {
            if (index + 2 >= encoded.len) return error.InvalidScope;
            const high = hexValue(encoded[index + 1]) orelse
                return error.InvalidScope;
            const low = hexValue(encoded[index + 2]) orelse
                return error.InvalidScope;
            index += 3;
            break :decoded (high << 4) | low;
        } else decoded: {
            const byte = encoded[index];
            if (!isUnreserved(byte) and byte != '*') {
                return error.InvalidScope;
            }
            index += 1;
            break :decoded byte;
        };
        if (out_len >= out.len) return error.BufferTooShort;
        out[out_len] = decoded;
        out_len += 1;
    }
    return out[0..out_len];
}

fn encodedTargetLen(target: []const u8) error{IntegerOverflow}!usize {
    if (std.mem.eql(u8, target, "*")) return 1;
    var result: usize = 0;
    for (target) |byte| {
        result = std.math.add(
            usize,
            result,
            if (isUnreserved(byte)) 1 else 3,
        ) catch return error.IntegerOverflow;
    }
    return result;
}

fn writeEncodedTarget(out: []u8, target: []const u8) usize {
    if (std.mem.eql(u8, target, "*")) {
        out[0] = '*';
        return 1;
    }
    const hex = "0123456789ABCDEF";
    var offset: usize = 0;
    for (target) |byte| {
        if (isUnreserved(byte)) {
            out[offset] = byte;
            offset += 1;
        } else {
            out[offset] = '%';
            out[offset + 1] = hex[byte >> 4];
            out[offset + 2] = hex[byte & 0x0f];
            offset += 3;
        }
    }
    return offset;
}

fn isUnreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        byte == '-' or byte == '.' or byte == '_' or byte == '~';
}

fn isRegNameByte(byte: u8) bool {
    if (isUnreserved(byte)) return true;
    return switch (byte) {
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
        else => false,
    };
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn decimalLen(value: u8) usize {
    if (value >= 100) return 3;
    if (value >= 10) return 2;
    return 1;
}
