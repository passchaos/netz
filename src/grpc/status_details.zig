//! google.rpc.Status carried by the reserved grpc-status-details-bin trailer.
//! Application Any payloads stay opaque; all views borrow the protobuf image.
const std = @import("std");
const http2 = @import("../http2/mod.zig");
const wire = @import("wire.zig");
const metadata = @import("metadata.zig");
const protobuf = @import("protobuf.zig");

pub const name = "grpc-status-details-bin";
pub const Error = metadata.Error || error{ InvalidStatusDetails, StatusDetailsMismatch };

pub const Any = struct {
    type_url: []const u8 = "",
    value: []const u8 = &.{},
};

pub const View = struct {
    bytes: []const u8,
    /// Null if the sender omitted field 1. Repeated singular fields use the
    /// last value, as required by protobuf, including an explicit zero.
    code: ?wire.Status,
    message: []const u8,

    pub fn details(self: View) DetailIterator {
        return .{ .reader = .{ .bytes = self.bytes } };
    }
};

pub const DetailIterator = struct {
    reader: protobuf.Reader,

    pub fn next(self: *DetailIterator) Error!?Any {
        while (self.reader.next() catch return error.InvalidStatusDetails) |field| {
            if (field.number == 3 and field.wire_type == 2) {
                return try parseAny(self.reader.bytesValue() catch return error.InvalidStatusDetails);
            }
            self.reader.skip(field) catch return error.InvalidStatusDetails;
        }
        return null;
    }
};

pub const Owned = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    view: View,

    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn clone(self: Owned, allocator: std.mem.Allocator) Error!Owned {
        const bytes = try allocator.dupe(u8, self.bytes);
        errdefer allocator.free(bytes);
        return .{ .allocator = allocator, .bytes = bytes, .view = try parse(bytes) };
    }
};

/// Parse the envelope and every Any container, including unknown protobuf
/// fields. Unknown Any.value schemas require no transport dependency.
pub fn parse(bytes: []const u8) Error!View {
    var reader: protobuf.Reader = .{ .bytes = bytes };
    var code_value: ?u64 = null;
    var message: []const u8 = "";
    while (reader.next() catch return error.InvalidStatusDetails) |field| {
        if (field.number == 1 and field.wire_type == 0) {
            code_value = reader.varint() catch return error.InvalidStatusDetails;
        } else if (field.number == 2 and field.wire_type == 2) {
            message = reader.string() catch return error.InvalidStatusDetails;
        } else if (field.number == 3 and field.wire_type == 2) {
            _ = try parseAny(reader.bytesValue() catch return error.InvalidStatusDetails);
        } else reader.skip(field) catch return error.InvalidStatusDetails;
    }
    // google.rpc.Status.code is int32, not an enum on the protobuf wire.
    // Decode its low 32 bits before validating the canonical gRPC range.
    const code: ?wire.Status = if (code_value) |raw| blk: {
        const value: i32 = @bitCast(@as(u32, @truncate(raw)));
        if (value < 0 or value > 16) return error.InvalidStatusDetails;
        break :blk @enumFromInt(value);
    } else null;
    return .{ .bytes = bytes, .code = code, .message = message };
}

pub fn validate(status: wire.Status, bytes: []const u8) Error!View {
    if (status == .ok) return error.InvalidStatusDetails;
    const view = try parse(bytes);
    if (view.code) |code| if (code != status) return error.StatusDetailsMismatch;
    return view;
}

/// Decode one reserved metadata value from terminal trailers or a true
/// trailers-only response. Initial nonterminal headers cannot carry details.
/// HTTP's decoded field-list bound caps the single exact-sized allocation.
pub fn fromMetadataAlloc(
    allocator: std.mem.Allocator,
    status: wire.Status,
    headers: []const http2.Hpack.HeaderField,
    trailers: []const http2.Hpack.HeaderField,
) Error!?Owned {
    var initial_count: usize = 0;
    var trailing_count: usize = 0;
    for (headers) |field| if (std.mem.eql(u8, field.name, name)) {
        initial_count += 1;
    };
    for (trailers) |field| if (std.mem.eql(u8, field.name, name)) {
        trailing_count += 1;
    };
    if (initial_count + trailing_count == 0) return null;
    if (initial_count + trailing_count != 1 or (initial_count != 0 and trailers.len != 0)) return error.InvalidStatusDetails;
    const fields = if (initial_count != 0) headers else trailers;
    var status_value: ?[]const u8 = null;
    for (fields) |field| if (std.mem.eql(u8, field.name, "grpc-status")) {
        if (status_value != null) return error.InvalidStatusDetails;
        status_value = field.value;
    };
    const raw_status = status_value orelse return error.InvalidStatusDetails;
    const parsed_status = wire.Status.parse(raw_status) catch return error.InvalidStatusDetails;
    if (parsed_status != status) return error.StatusDetailsMismatch;
    const size = try metadata.decodedFieldsUpperBound(fields, name);
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var iterator = try metadata.ValueIterator.init(fields, name, bytes);
    const first = (try iterator.next()) orelse return error.InvalidStatusDetails;
    if (try iterator.next() != null) return error.InvalidStatusDetails;
    return .{ .allocator = allocator, .bytes = bytes, .view = try validate(status, first.value) };
}

/// Validate raw google.rpc.Status and encode its reserved binary trailer.
pub fn encodedAlloc(allocator: std.mem.Allocator, status: wire.Status, bytes: []const u8) Error![]u8 {
    _ = try validate(status, bytes);
    const out = try allocator.alloc(u8, std.base64.standard_no_pad.Encoder.calcSize(bytes.len));
    _ = std.base64.standard_no_pad.Encoder.encode(out, bytes);
    return out;
}

/// Construct a canonical envelope without generated protobuf bindings.
pub fn encodeAlloc(allocator: std.mem.Allocator, status: wire.Status, message: []const u8, details: []const Any) Error![]u8 {
    if (status == .ok or !std.unicode.utf8ValidateSlice(message)) return error.InvalidStatusDetails;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &.{ 8, @intFromEnum(status) });
    if (message.len != 0) try appendBytes(&out, allocator, 2, message);
    for (details) |detail| {
        if (!std.unicode.utf8ValidateSlice(detail.type_url)) return error.InvalidStatusDetails;
        var any: std.ArrayList(u8) = .empty;
        defer any.deinit(allocator);
        if (detail.type_url.len != 0) try appendBytes(&any, allocator, 1, detail.type_url);
        if (detail.value.len != 0) try appendBytes(&any, allocator, 2, detail.value);
        try appendBytes(&out, allocator, 3, any.items);
    }
    return out.toOwnedSlice(allocator);
}

fn parseAny(bytes: []const u8) Error!Any {
    var reader: protobuf.Reader = .{ .bytes = bytes };
    var result: Any = .{};
    while (reader.next() catch return error.InvalidStatusDetails) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            result.type_url = reader.string() catch return error.InvalidStatusDetails;
        } else if (field.number == 2 and field.wire_type == 2) {
            result.value = reader.bytesValue() catch return error.InvalidStatusDetails;
        } else reader.skip(field) catch return error.InvalidStatusDetails;
    }
    return result;
}

fn appendBytes(out: *std.ArrayList(u8), allocator: std.mem.Allocator, number: u8, bytes: []const u8) Error!void {
    try out.append(allocator, (number << 3) | 2);
    var len = bytes.len;
    while (len >= 128) {
        try out.append(allocator, @as(u8, @truncate(len)) | 128);
        len >>= 7;
    }
    try out.append(allocator, @intCast(len));
    try out.appendSlice(allocator, bytes);
}

test {
    _ = @import("status_details/tests.zig");
    _ = @import("status_details/runtime_tests.zig");
}
