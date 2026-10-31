//! Allocation-free RFC 8941 Digest and Want-Digest dictionaries.
const std = @import("std");
const sf = @import("../../internal/structured_field.zig");
const types = @import("types.zig");
const Set = @import("value.zig").Set;

pub const Field = struct {
    kind: types.Kind = .content,
    present: bool = false,
    values: Set = .{},
};

pub const Preferences = struct {
    sha256: ?u4 = null,
    sha512: ?u4 = null,

    /// The preferences are advisory. Equal positive preferences select SHA-512.
    /// Unlisted and zero-weight algorithms are not selected by this helper.
    pub fn select(self: Preferences, available: types.Algorithms) types.Error!?types.Algorithm {
        if ((self.sha256 orelse 0) > 10 or (self.sha512 orelse 0) > 10) return error.InvalidDigestField;
        const sha256: u4 = if (available.sha256) self.sha256 orelse 0 else 0;
        const sha512: u4 = if (available.sha512) self.sha512 orelse 0 else 0;
        if (sha512 != 0 and sha512 >= sha256) return .sha512;
        if (sha256 != 0) return .sha256;
        return null;
    }

    pub fn writeInto(self: Preferences, output: []u8) types.Error![]u8 {
        if ((self.sha256 orelse 0) > 10 or (self.sha512 orelse 0) > 10) return error.InvalidDigestField;
        var length: usize = 0;
        if (self.sha256) |value| length += 9 + @as(usize, @intFromBool(value == 10));
        if (self.sha512) |value| length += 9 + @as(usize, @intFromBool(value == 10));
        if (self.sha256 != null and self.sha512 != null) length += 2;
        if (output.len < length) return error.BufferTooShort;
        var offset: usize = 0;
        inline for (.{ "sha-256", "sha-512" }, .{ self.sha256, self.sha512 }) |name, preference| {
            if (preference) |value| {
                if (offset != 0) {
                    @memcpy(output[offset..][0..2], ", ");
                    offset += 2;
                }
                @memcpy(output[offset..][0..name.len], name);
                offset += name.len;
                output[offset] = '=';
                offset += 1;
                if (value == 10) {
                    @memcpy(output[offset..][0..2], "10");
                    offset += 2;
                } else {
                    output[offset] = '0' + @as(u8, value);
                    offset += 1;
                }
            }
        }
        std.debug.assert(offset == length);
        return output[0..length];
    }
};

const Member = struct { key: []const u8, value: ?[]const u8 };
const Dictionary = struct {
    entries: [types.max_dictionary_members]Member = undefined,
    len: usize = 0,

    fn put(self: *Dictionary, member: Member) void {
        for (self.entries[0..self.len]) |*previous| {
            if (std.mem.eql(u8, previous.key, member.key)) {
                previous.* = member;
                return;
            }
        }
        std.debug.assert(self.len < self.entries.len);
        self.entries[self.len] = member;
        self.len += 1;
    }
};
const Parser = struct {
    options: types.ParseOptions,
    bytes: usize = 0,
    members: usize = 0,
    lines: usize = 0,
    saw_empty: bool = false,

    fn append(self: *Parser, text: []const u8, dictionary: *Dictionary) types.Error!void {
        if (text.len > self.options.max_field_bytes - self.bytes) return error.DigestFieldTooLarge;
        self.bytes += text.len;
        self.lines += 1;
        var cursor: usize = 0;
        sf.skipOptionalWhitespace(text, &cursor);
        if (cursor == text.len) {
            self.saw_empty = true;
            return;
        }
        while (cursor < text.len) {
            if (self.members == @min(self.options.max_members, types.max_dictionary_members)) return error.TooManyDigestMembers;
            self.members += 1;
            const start = cursor;
            sf.consumeKey(text, &cursor) catch return error.InvalidDigestField;
            const key = text[start..cursor];
            const value: ?[]const u8 = if (cursor < text.len and text[cursor] == '=') blk: {
                cursor += 1;
                const value_start = cursor;
                sf.consumeMember8941(text, &cursor) catch return error.InvalidDigestField;
                break :blk text[value_start..cursor];
            } else blk: {
                sf.consumeParameters8941(text, &cursor) catch return error.InvalidDigestField;
                break :blk null; // implicit Boolean true
            };
            dictionary.put(.{ .key = key, .value = value });
            sf.skipOptionalWhitespace(text, &cursor);
            if (cursor == text.len) break;
            if (text[cursor] != ',') return error.InvalidDigestField;
            cursor += 1;
            sf.skipOptionalWhitespace(text, &cursor);
            if (cursor == text.len) return error.InvalidDigestField;
        }
    }

    fn finish(self: Parser) types.Error!void {
        // Field lines are combined with commas before RFC 8941 processing.
        if (self.lines > 1 and self.saw_empty) return error.InvalidDigestField;
    }
};

fn visitDigest(field: *Field, member: Member) types.Error!void {
    const value = member.value orelse return error.InvalidDigestField;
    if (value.len == 0 or value[0] != ':') return error.InvalidDigestField;
    const end = std.mem.indexOfScalarPos(u8, value, 1, ':') orelse return error.InvalidDigestField;
    const encoded = value[1..end];
    if (std.mem.eql(u8, member.key, "sha-256")) {
        field.values.sha256 = try decode(32, encoded);
    } else if (std.mem.eql(u8, member.key, "sha-512")) {
        field.values.sha512 = try decode(64, encoded);
    }
    // Unsupported and deprecated algorithms remain syntactically validated
    // Byte Sequences, but do not count as an enabled integrity check.
}

fn decode(comptime count: usize, encoded: []const u8) types.Error![count]u8 {
    const decoder = if (std.mem.endsWith(u8, encoded, "=")) std.base64.standard.Decoder else std.base64.standard_no_pad.Decoder;
    const length = decoder.calcSizeForSlice(encoded) catch return error.InvalidDigestField;
    if (length != count) return error.InvalidDigestField;
    var bytes: [count]u8 = undefined;
    decoder.decode(&bytes, encoded) catch return error.InvalidDigestField;
    return bytes;
}

fn visitPreference(preferences: *Preferences, member: Member) types.Error!void {
    const value_text = member.value orelse return error.InvalidDigestField;
    const end = std.mem.indexOfScalar(u8, value_text, ';') orelse value_text.len;
    const number = std.fmt.parseInt(i64, value_text[0..end], 10) catch return error.InvalidDigestField;
    if (number < 0 or number > 10) return error.InvalidDigestField;
    const value: u4 = @intCast(number);
    if (std.mem.eql(u8, member.key, "sha-256")) preferences.sha256 = value;
    if (std.mem.eql(u8, member.key, "sha-512")) preferences.sha512 = value;
}

pub fn parse(value: ?[]const u8, options: types.ParseOptions) types.Error!Field {
    var result: Field = .{ .present = value != null };
    var parser: Parser = .{ .options = options };
    var dictionary: Dictionary = .{};
    if (value) |text| try parser.append(text, &dictionary);
    try parser.finish();
    for (dictionary.entries[0..dictionary.len]) |member| try visitDigest(&result, member);
    return result;
}

pub fn parseMessage(kind: types.Kind, headers: anytype, trailers: anytype, options: types.ParseOptions) types.Error!Field {
    var result: Field = .{ .kind = kind };
    var parser: Parser = .{ .options = options };
    var dictionary: Dictionary = .{};
    inline for (.{ headers, trailers }) |section| {
        for (section) |header| {
            if (!std.ascii.eqlIgnoreCase(header.name, kind.name())) continue;
            result.present = true;
            try parser.append(header.value, &dictionary);
        }
    }
    try parser.finish();
    for (dictionary.entries[0..dictionary.len]) |member| try visitDigest(&result, member);
    return result;
}

pub fn parsePreferences(value: ?[]const u8, options: types.ParseOptions) types.Error!Preferences {
    var result: Preferences = .{};
    var parser: Parser = .{ .options = options };
    var dictionary: Dictionary = .{};
    if (value) |text| try parser.append(text, &dictionary);
    try parser.finish();
    for (dictionary.entries[0..dictionary.len]) |member| try visitPreference(&result, member);
    return result;
}

pub fn parsePreferenceHeaders(kind: types.Kind, headers: anytype, options: types.ParseOptions) types.Error!Preferences {
    var result: Preferences = .{};
    var parser: Parser = .{ .options = options };
    var dictionary: Dictionary = .{};
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, kind.preferenceName())) continue;
        try parser.append(header.value, &dictionary);
    }
    try parser.finish();
    for (dictionary.entries[0..dictionary.len]) |member| try visitPreference(&result, member);
    return result;
}
