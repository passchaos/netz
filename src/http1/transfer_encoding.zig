//! RFC 9112 transfer-coding grammar shared by wire framing and message codecs.
const std = @import("std");
pub const Error = error{InvalidTransferEncoding};

/// Aggregate repeated Transfer-Encoding fields in wire order. Iterator grammar
/// keeps quoted commas and escaped quotes inside parameters, while chunked
/// itself is parameter-free and may occur only once.
pub const State = struct {
    present: bool = false,
    saw_chunked: bool = false,
    final_is_chunked: bool = false,

    pub fn feed(self: *State, value: []const u8) Error!void {
        var codings = Iterator{ .value = value };
        while (try codings.next()) |coding| {
            const chunked = std.ascii.eqlIgnoreCase(coding.name, "chunked");
            if (chunked) {
                if (self.saw_chunked or coding.has_parameters) return error.InvalidTransferEncoding;
                self.saw_chunked = true;
            }
            self.present = true;
            self.final_is_chunked = chunked;
        }
    }
};

pub const Coding = struct {
    name: []const u8,
    has_parameters: bool,
};

pub const Iterator = struct {
    value: []const u8,
    pos: usize = 0,
    done: bool = false,

    pub fn next(self: *Iterator) Error!?Coding {
        if (self.done) return null;
        skipOws(self.value, &self.pos);
        const name_start = self.pos;
        while (self.pos < self.value.len and
            validHeaderNameByte(self.value[self.pos]))
        {
            self.pos += 1;
        }
        if (self.pos == name_start) return error.InvalidTransferEncoding;
        const name = self.value[name_start..self.pos];
        skipOws(self.value, &self.pos);

        var has_parameters = false;
        while (self.pos < self.value.len and self.value[self.pos] == ';') {
            has_parameters = true;
            self.pos += 1;
            skipOws(self.value, &self.pos);
            const parameter_start = self.pos;
            while (self.pos < self.value.len and
                validHeaderNameByte(self.value[self.pos]))
            {
                self.pos += 1;
            }
            if (self.pos == parameter_start) {
                return error.InvalidTransferEncoding;
            }
            skipOws(self.value, &self.pos);
            if (self.pos == self.value.len or self.value[self.pos] != '=') {
                return error.InvalidTransferEncoding;
            }
            self.pos += 1;
            skipOws(self.value, &self.pos);
            if (self.pos == self.value.len) {
                return error.InvalidTransferEncoding;
            }
            if (self.value[self.pos] == '"') {
                try consumeQuotedString(self.value, &self.pos);
            } else {
                const parameter_value_start = self.pos;
                while (self.pos < self.value.len and
                    validHeaderNameByte(self.value[self.pos]))
                {
                    self.pos += 1;
                }
                if (self.pos == parameter_value_start) {
                    return error.InvalidTransferEncoding;
                }
            }
            skipOws(self.value, &self.pos);
        }

        if (self.pos == self.value.len) {
            self.done = true;
        } else {
            if (self.value[self.pos] != ',') {
                return error.InvalidTransferEncoding;
            }
            self.pos += 1;
        }
        return .{ .name = name, .has_parameters = has_parameters };
    }
};

pub fn skipOws(value: []const u8, pos: *usize) void {
    while (pos.* < value.len and
        (value[pos.*] == ' ' or value[pos.*] == '\t'))
    {
        pos.* += 1;
    }
}

fn consumeQuotedString(
    value: []const u8,
    pos: *usize,
) Error!void {
    std.debug.assert(pos.* < value.len and value[pos.*] == '"');
    pos.* += 1;
    while (pos.* < value.len) {
        const byte = value[pos.*];
        pos.* += 1;
        if (byte == '"') return;
        if (byte == '\\') {
            if (pos.* == value.len) return error.InvalidTransferEncoding;
            const escaped = value[pos.*];
            if (!(escaped == '\t' or
                (escaped >= 0x20 and escaped <= 0x7e) or
                escaped >= 0x80))
            {
                return error.InvalidTransferEncoding;
            }
            pos.* += 1;
            continue;
        }
        if (!(byte == '\t' or
            byte == ' ' or
            byte == 0x21 or
            (byte >= 0x23 and byte <= 0x5b) or
            (byte >= 0x5d and byte <= 0x7e) or
            byte >= 0x80))
        {
            return error.InvalidTransferEncoding;
        }
    }
    return error.InvalidTransferEncoding;
}

const valid_header_name_bytes: [256]bool = blk: {
    var table = [_]bool{false} ** 256;
    for ('0'..'9' + 1) |byte| table[byte] = true;
    for ('A'..'Z' + 1) |byte| table[byte] = true;
    for ('a'..'z' + 1) |byte| table[byte] = true;
    for ("!#$%&'*+-.^_`|~") |byte| table[byte] = true;
    break :blk table;
};

inline fn validHeaderNameByte(byte: u8) bool {
    return valid_header_name_bytes[byte];
}
