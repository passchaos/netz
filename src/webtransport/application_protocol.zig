//! RFC 9651 fields for WebTransport application protocol negotiation.

const std = @import("std");
const http3 = @import("../http3/mod.zig");
const sf = @import("../internal/structured_field.zig");

pub const available_header = "wt-available-protocols";
pub const selected_header = "wt-protocol";
pub const String = sf.String;
pub const Request = @import("application_protocol/request.zig").Request;
pub const Error = error{ InvalidApplicationProtocol, ApplicationProtocolNegotiationFailed, NoCommonApplicationProtocol, BufferTooSmall, IntegerOverflow } || std.mem.Allocator.Error;

pub const Policy = struct {
    /// Client offers or server-supported identifiers. Caller-owned policy
    /// values must outlive the operation/server configured with them.
    values: []const []const u8 = &.{},
    required: bool = false,
};

pub const Offered = struct {
    fields: []const http3.Qpack.HeaderField,
    count: usize,

    pub fn iterator(self: Offered) Iterator {
        return .{ .fields = self.fields };
    }

    pub fn contains(self: Offered, selection: String) bool {
        return self.find(selection) != null;
    }

    pub fn find(self: Offered, selection: String) ?String {
        var items = self.iterator();
        while (items.next()) |value| if (value.eqlString(selection)) return value;
        return null;
    }

    pub fn containsValue(self: Offered, selection: []const u8) bool {
        var items = self.iterator();
        while (items.next()) |value| if (value.eql(selection)) return true;
        return false;
    }

    /// Honor the client's advertised preference order among supported values.
    pub fn choose(self: Offered, supported: []const []const u8) ?[]const u8 {
        var items = self.iterator();
        while (items.next()) |value| {
            for (supported) |candidate| if (value.eql(candidate)) return candidate;
        }
        return null;
    }
};

pub const Iterator = struct {
    fields: []const http3.Qpack.HeaderField,
    field_index: usize = 0,
    cursor: usize = 0,

    /// Constructed only from a fully validated Offered field set.
    pub fn next(self: *Iterator) ?String {
        while (self.field_index < self.fields.len) {
            const field = self.fields[self.field_index];
            if (!std.ascii.eqlIgnoreCase(field.name, available_header)) {
                self.field_index += 1;
                self.cursor = 0;
                continue;
            }
            sf.skipOptionalWhitespace(field.value, &self.cursor);
            if (self.cursor == field.value.len) {
                self.field_index += 1;
                self.cursor = 0;
                continue;
            }
            const value = sf.parseString(field.value, &self.cursor) catch unreachable;
            sf.consumeParameters(field.value, &self.cursor) catch unreachable;
            sf.skipOptionalWhitespace(field.value, &self.cursor);
            if (self.cursor != field.value.len) self.cursor += 1;
            return value;
        }
        return null;
    }
};

/// Invalid/non-String members invalidate the entire combined field. Absence
/// and invalid fields are ignored by optional negotiation.
pub fn offered(fields: []const http3.Qpack.HeaderField) ?Offered {
    var lines: usize = 0;
    var count: usize = 0;
    var empty = false;
    for (fields) |field| {
        if (!std.ascii.eqlIgnoreCase(field.name, available_header)) continue;
        lines += 1;
        const members = countLine(field.value) catch return null;
        empty = empty or members == 0;
        count += members;
    }
    if (lines == 0 or (lines > 1 and empty)) return null;
    return .{ .fields = fields, .count = count };
}

pub fn selected(fields: []const http3.Qpack.HeaderField) ?String {
    var result: ?String = null;
    for (fields) |field| {
        if (!std.ascii.eqlIgnoreCase(field.name, selected_header)) continue;
        if (result != null) return null;
        var cursor: usize = 0;
        sf.skipOptionalWhitespace(field.value, &cursor);
        const item = sf.parseString(field.value, &cursor) catch return null;
        sf.consumeParameters(field.value, &cursor) catch return null;
        sf.skipOptionalWhitespace(field.value, &cursor);
        if (cursor != field.value.len) return null;
        result = item;
    }
    return result;
}

pub fn validateResponse(request: []const http3.Qpack.HeaderField, response: []const http3.Qpack.HeaderField, required: bool) Error!?String {
    const choice = selected(response) orelse {
        if (required) return error.ApplicationProtocolNegotiationFailed;
        return null;
    };
    const values = offered(request) orelse return error.ApplicationProtocolNegotiationFailed;
    if (!values.contains(choice)) return error.ApplicationProtocolNegotiationFailed;
    return choice;
}

pub fn validateValues(values: []const []const u8) Error!void {
    for (values) |value| for (value) |byte| {
        if (byte < 0x20 or byte > 0x7e) return error.InvalidApplicationProtocol;
    };
}

pub fn validateRequestPolicy(policy: Policy, additional: []const http3.Qpack.HeaderField) Error!void {
    try validateValues(policy.values);
    var present = false;
    for (additional) |field| if (std.ascii.eqlIgnoreCase(field.name, available_header)) {
        present = true;
    };
    if (policy.values.len != 0 and present) return error.InvalidApplicationProtocol;
    if (policy.required and policy.values.len == 0) {
        const available = offered(additional) orelse return error.InvalidApplicationProtocol;
        if (available.count == 0) return error.InvalidApplicationProtocol;
    }
}

/// Local server output must select one offered value. Malformed peer input is
/// ignored, but malformed local selection is a configuration error.
pub fn serverSelection(request: []const http3.Qpack.HeaderField, response: []const http3.Qpack.HeaderField, policy: Policy) Error!?[]const u8 {
    try validateValues(policy.values);
    const offered_values = offered(request);
    var supplied = false;
    for (response) |field| if (std.ascii.eqlIgnoreCase(field.name, selected_header)) {
        supplied = true;
    };
    if (supplied) {
        const choice = selected(response) orelse return error.InvalidApplicationProtocol;
        const available = offered_values orelse return error.NoCommonApplicationProtocol;
        if (!available.contains(choice)) return error.NoCommonApplicationProtocol;
        if (policy.values.len != 0) {
            for (policy.values) |value| if (choice.eql(value)) return null;
            return error.NoCommonApplicationProtocol;
        }
        return null;
    }
    if (offered_values) |available| {
        if (available.choose(policy.values)) |choice| return choice;
    }
    if (policy.required) return error.NoCommonApplicationProtocol;
    return null;
}

pub fn writeList(allocator: std.mem.Allocator, values: []const []const u8) Error![]u8 {
    try validateValues(values);
    var length: usize = 0;
    for (values, 0..) |value, index| {
        length = try add(length, if (index == 0) 2 else 4);
        for (value) |byte| length = try add(length, if (byte == '"' or byte == '\\') 2 else 1);
    }
    const output = try allocator.alloc(u8, length);
    var position: usize = 0;
    for (values, 0..) |value, index| {
        if (index != 0) {
            @memcpy(output[position..][0..2], ", ");
            position += 2;
        }
        output[position] = '"';
        position += 1;
        for (value) |byte| {
            if (byte == '"' or byte == '\\') {
                output[position] = '\\';
                position += 1;
            }
            output[position] = byte;
            position += 1;
        }
        output[position] = '"';
        position += 1;
    }
    return output;
}

pub fn writeItem(allocator: std.mem.Allocator, value: []const u8) Error![]u8 {
    return writeList(allocator, &.{value});
}

fn countLine(value: []const u8) sf.Error!usize {
    var cursor: usize = 0;
    var count: usize = 0;
    sf.skipOptionalWhitespace(value, &cursor);
    if (cursor == value.len) return 0;
    while (true) {
        _ = try sf.parseString(value, &cursor);
        try sf.consumeParameters(value, &cursor);
        count += 1;
        sf.skipOptionalWhitespace(value, &cursor);
        if (cursor == value.len) return count;
        if (value[cursor] != ',') return error.InvalidStructuredField;
        cursor += 1;
        sf.skipOptionalWhitespace(value, &cursor);
        if (cursor == value.len) return error.InvalidStructuredField;
    }
}

fn add(left: usize, right: usize) Error!usize {
    return std.math.add(usize, left, right) catch error.IntegerOverflow;
}

test {
    _ = @import("application_protocol/tests.zig");
}
