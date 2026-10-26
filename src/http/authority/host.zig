//! Origin hosts: semantic equality, owned canonical text and hash identity.
const std = @import("std");
const parser = @import("parse.zig");
const ipv6 = @import("ipv6.zig");
const Error = parser.Error || std.mem.Allocator.Error;

pub fn parse(raw: []const u8) parser.Error!parser.Parsed {
    if (raw.len == 0) return error.InvalidAuthority;
    if (raw[0] == '[') {
        if (raw[raw.len - 1] != ']') return error.InvalidAuthority;
        return parser.parse(raw);
    }
    if (std.mem.indexOfScalar(u8, raw, ':') != null) {
        if (raw[0] == 'v' or raw[0] == 'V') {
            try parser.validateFuture(raw);
            return .{ .kind = .future, .host = raw, .port = null };
        }
        return .{ .kind = .ipv6, .host = raw, .port = null, .address = try ipv6.parse(raw) };
    }
    return parser.parse(raw);
}

pub fn equivalent(left: []const u8, right: []const u8) bool {
    const a = parse(left) catch return false;
    const b = parse(right) catch return false;
    if (a.kind != b.kind) return false;
    if (a.kind == .ipv6) return std.mem.eql(u8, &a.address, &b.address);
    var ai: usize = 0;
    var bi: usize = 0;
    while (ai < a.host.len and bi < b.host.len) if (next(a.host, &ai) != next(b.host, &bi)) return false;
    return ai == a.host.len and bi == b.host.len;
}

pub fn canonicalAlloc(allocator: std.mem.Allocator, raw: []const u8) Error![]u8 {
    const parsed = try parse(raw);
    if (parsed.kind == .ipv6) {
        var buffer: [64]u8 = undefined;
        const address: std.Io.net.Ip6Address.Unresolved = .{ .bytes = parsed.address, .interface_name = null };
        const text = std.fmt.bufPrint(&buffer, "{f}", .{address}) catch unreachable;
        return allocator.dupe(u8, text);
    }
    const bracketed = parsed.kind == .future;
    var index: usize = 0;
    var size: usize = 0;
    while (index < parsed.host.len) {
        _ = next(parsed.host, &index);
        size += 1;
    }
    const extra: usize = if (bracketed) 2 else 0;
    const len = std.math.add(usize, size, extra) catch return error.OutOfMemory;
    const bytes = try allocator.alloc(u8, len);
    var written: usize = 0;
    if (bracketed) {
        bytes[0] = '[';
        written = 1;
    }
    index = 0;
    while (index < parsed.host.len) {
        bytes[written] = next(parsed.host, &index);
        written += 1;
    }
    if (bracketed) bytes[written] = ']';
    return bytes;
}

pub fn canonicalInto(out: []u8, raw: []const u8) (parser.Error || error{BufferTooSmall})![]u8 {
    const parsed = try parse(raw);
    if (parsed.kind == .ipv6) {
        const address: std.Io.net.Ip6Address.Unresolved = .{ .bytes = parsed.address, .interface_name = null };
        return std.fmt.bufPrint(out, "{f}", .{address}) catch error.BufferTooSmall;
    }
    const bracketed = parsed.kind == .future;
    var cursor: usize = 0;
    var written: usize = 0;
    if (bracketed) {
        if (out.len == 0) return error.BufferTooSmall;
        out[0] = '[';
        written = 1;
    }
    while (cursor < parsed.host.len) {
        if (written == out.len) return error.BufferTooSmall;
        out[written] = next(parsed.host, &cursor);
        written += 1;
    }
    if (bracketed) {
        if (written == out.len) return error.BufferTooSmall;
        out[written] = ']';
        written += 1;
    }
    return out[0..written];
}

/// Equal host identities hash identically even when the input is borrowed
/// from differently escaped names or different IPv6 textual representations.
pub fn hash(raw: []const u8) parser.Error!u64 {
    const parsed = try parse(raw);
    var hasher = std.hash.Wyhash.init(0);
    std.hash.autoHash(&hasher, @intFromEnum(parsed.kind));
    if (parsed.kind == .ipv6) {
        hasher.update(&parsed.address);
    } else {
        var buffer: [64]u8 = undefined;
        var index: usize = 0;
        while (index < parsed.host.len) {
            var count: usize = 0;
            while (count < buffer.len and index < parsed.host.len) : (count += 1) buffer[count] = next(parsed.host, &index);
            hasher.update(buffer[0..count]);
        }
    }
    return hasher.final();
}

pub fn next(host: []const u8, index: *usize) u8 {
    const byte = host[index.*];
    if (byte == '%') {
        const decoded = (std.fmt.charToDigit(host[index.* + 1], 16) catch unreachable) * 16 +
            (std.fmt.charToDigit(host[index.* + 2], 16) catch unreachable);
        if (parser.unreserved(decoded)) {
            index.* += 3;
            return std.ascii.toLower(decoded);
        }
    }
    index.* += 1;
    return std.ascii.toLower(byte);
}

test {
    _ = @import("host_tests.zig");
}
