//! Owned terminal gRPC fields shared by sequential and duplex writers.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const call = @import("../call.zig");
const wire = @import("../wire.zig");
const metadata = @import("../metadata.zig");
const details_mod = @import("../status_details.zig");
pub const Options = @import("../web/response_headers.zig").TerminalOptions;
const Error = call.Error;

pub const Fields = struct {
    allocator: std.mem.Allocator,
    fields: []http2.Hpack.HeaderField,
    status_value: []u8,
    encoded_message: []u8,
    binary: metadata.EncodedFields,
    encoded_details: ?[]u8,
    pushback_value: ?[]u8,

    pub fn deinit(self: *Fields) void {
        self.binary.deinit();
        if (self.encoded_details) |bytes| self.allocator.free(bytes);
        if (self.pushback_value) |bytes| self.allocator.free(bytes);
        self.allocator.free(self.encoded_message);
        self.allocator.free(self.status_value);
        self.allocator.free(self.fields);
        self.* = undefined;
    }
};

pub fn build(allocator: std.mem.Allocator, options: Options) Error!Fields {
    const status = options.status;
    const status_message = options.status_message;
    const trailing_metadata = options.trailing_metadata;
    const trailing_binary_metadata = options.trailing_binary_metadata;
    const encoded_details = if (options.status_details) |bytes| try details_mod.encodedAlloc(allocator, status, bytes) else null;
    errdefer if (encoded_details) |bytes| allocator.free(bytes);
    const pushback_value = if (options.retry_pushback_ms) |ms| try std.fmt.allocPrint(allocator, "{d}", .{ms}) else null;
    errdefer if (pushback_value) |bytes| allocator.free(bytes);
    try call.validateCustomMetadata(trailing_metadata);
    try call.validateCustomBinaryMetadata(trailing_binary_metadata);
    var binary = try metadata.encodeFieldsAlloc(
        allocator,
        trailing_binary_metadata,
    );
    errdefer binary.deinit();
    var status_buffer: [2]u8 = undefined;
    const status_text = std.fmt.bufPrint(
        &status_buffer,
        "{d}",
        .{@intFromEnum(status)},
    ) catch unreachable;
    const status_value = try allocator.dupe(u8, status_text);
    errdefer allocator.free(status_value);
    const encoded_message = if (status_message) |message|
        try wire.encodeStatusMessageAlloc(allocator, message)
    else
        try allocator.alloc(u8, 0);
    errdefer allocator.free(encoded_message);
    const count = std.math.add(
        usize,
        std.math.add(usize, trailing_metadata.len, binary.fields.len) catch
            return error.MessageTooLarge,
        @as(usize, 1) + @intFromBool(status_message != null) + @intFromBool(encoded_details != null) + @intFromBool(pushback_value != null),
    ) catch return error.MessageTooLarge;
    const fields = try allocator.alloc(http2.Hpack.HeaderField, count);
    var list: std.ArrayList(http2.Hpack.HeaderField) = .initBuffer(fields);
    list.appendAssumeCapacity(.{ .name = "grpc-status", .value = status_value });
    if (status_message != null) {
        list.appendAssumeCapacity(.{
            .name = "grpc-message",
            .value = encoded_message,
        });
    }
    if (encoded_details) |bytes| list.appendAssumeCapacity(.{ .name = details_mod.name, .value = bytes, .never_index = true });
    if (pushback_value) |bytes| list.appendAssumeCapacity(.{ .name = "grpc-retry-pushback-ms", .value = bytes });
    list.appendSliceAssumeCapacity(trailing_metadata);
    list.appendSliceAssumeCapacity(binary.fields);
    return .{
        .allocator = allocator,
        .fields = fields,
        .status_value = status_value,
        .encoded_message = encoded_message,
        .binary = binary,
        .encoded_details = encoded_details,
        .pushback_value = pushback_value,
    };
}

test "gRPC terminal fields preserve details and pushback through allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    var fields = try build(allocator, .{
        .status = .permission_denied,
        .status_message = "denied%",
        .status_details = "\x08\x07",
        .retry_pushback_ms = -1,
        .trailing_binary_metadata = &.{.{ .name = "x-end-bin", .value = "\xff" }},
    });
    defer fields.deinit();
    try std.testing.expectEqualStrings("CAc", call.headerValue(fields.fields, "grpc-status-details-bin").?);
    try std.testing.expectEqualStrings("-1", call.headerValue(fields.fields, "grpc-retry-pushback-ms").?);
}
