//! Bounded RFC 3986 IPv6 literals, including a dotted IPv4 final component.
const std = @import("std");
const Error = error{InvalidAuthority};

pub fn parse(text: []const u8) Error![16]u8 {
    if (text.len == 0) return error.InvalidAuthority;
    var bytes: [16]u8 = @splat(0);
    var words: usize = 0;
    var gap: ?usize = null;
    var cursor: usize = 0;
    if (std.mem.startsWith(u8, text, "::")) {
        gap = 0;
        cursor = 2;
    }
    while (cursor < text.len) {
        const end = if (std.mem.indexOfScalarPos(u8, text, cursor, ':')) |index| index else text.len;
        const part = text[cursor..end];
        if (part.len == 0 or words >= 8) return error.InvalidAuthority;
        if (std.mem.indexOfScalar(u8, part, '.') != null) {
            if (end != text.len or words > 6) return error.InvalidAuthority;
            const ip4 = try parseIp4(part);
            @memcpy(bytes[words * 2 ..][0..4], &ip4);
            words += 2;
        } else {
            if (part.len > 4) return error.InvalidAuthority;
            var word: u16 = 0;
            for (part) |byte| word = (word << 4) | (std.fmt.charToDigit(byte, 16) catch return error.InvalidAuthority);
            std.mem.writeInt(u16, bytes[words * 2 ..][0..2], word, .big);
            words += 1;
        }
        if (end == text.len) break;
        if (end + 1 < text.len and text[end + 1] == ':') {
            if (gap != null) return error.InvalidAuthority;
            gap = words;
            cursor = end + 2;
        } else {
            cursor = end + 1;
            if (cursor == text.len) return error.InvalidAuthority;
        }
    }
    if (gap) |at| {
        if (words >= 8) return error.InvalidAuthority;
        const tail = (words - at) * 2;
        std.mem.copyBackwards(u8, bytes[16 - tail ..], bytes[at * 2 ..][0..tail]);
        @memset(bytes[at * 2 .. 16 - tail], 0);
    } else if (words != 8) return error.InvalidAuthority;
    return bytes;
}

fn parseIp4(text: []const u8) Error![4]u8 {
    var bytes: [4]u8 = undefined;
    var count: usize = 0;
    var parts = std.mem.splitScalar(u8, text, '.');
    while (parts.next()) |part| {
        if (count == 4 or part.len == 0 or part.len > 3 or (part.len > 1 and part[0] == '0')) return error.InvalidAuthority;
        var value: u16 = 0;
        for (part) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidAuthority;
            value = value * 10 + byte - '0';
        }
        if (value > 255) return error.InvalidAuthority;
        bytes[count] = @intCast(value);
        count += 1;
    }
    if (count != 4) return error.InvalidAuthority;
    return bytes;
}

test "HTTP authority IPv6 parser validates compression and IPv4 suffixes" {
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 2, 1 }, &(try parse("2001:db8::192.0.2.1")));
    const pairs = [_][2][]const u8{
        .{ "::", "0:0:0:0:0:0:0:0" },
        .{ "::1", "0:0:0:0:0:0:0:1" },
        .{ "::ffff:192.0.2.1", "::ffff:c000:201" },
        .{ "2001:db8::192.0.2.1", "2001:db8:0:0:0:0:c000:201" },
        .{ "1:2:3:4:5:6:192.0.2.1", "1:2:3:4:5:6:c000:201" },
    };
    for (pairs) |pair| try std.testing.expectEqualSlices(u8, &(try parse(pair[0])), &(try parse(pair[1])));
    for ([_][]const u8{ "", ":", ":1", "1:", ":::1", "1:::2", "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7::8", "00000::1", "gg::1", "::ffff:192.0.02.1", "::ffff:256.0.2.1", "::ffff:1.2.3", "::ffff:1.2.3.4.5", "1:2:3:4:5:6:7:192.0.2.1", "::192.0.2.1:1", "::1%eth0" }) |text| try std.testing.expectError(error.InvalidAuthority, parse(text));
}
