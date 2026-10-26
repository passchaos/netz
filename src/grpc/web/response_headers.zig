//! Shared initial field construction for gRPC-Web HTTP transports.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const call = @import("../call.zig");
const wire = @import("../wire.zig");
const compression = @import("../compression.zig");
const metadata = @import("../metadata.zig");
const content_type = @import("content_type.zig");

pub const TerminalOptions = struct {
    status: wire.Status,
    status_message: ?[]const u8 = null,
    retry_pushback_ms: ?i64 = null,
    trailing_metadata: []const http2.Hpack.HeaderField = &.{},
    trailing_binary_metadata: []const metadata.BinaryMetadata = &.{},
};

pub const Options = struct {
    content_type: content_type.ContentType,
    compression: compression.Algorithm,
    accepted_encodings: compression.AlgorithmSet,
    initial_metadata: []const http2.Hpack.HeaderField,
    initial_binary_metadata: []const metadata.BinaryMetadata,
    terminal: ?TerminalOptions = null,
};

/// Prepare in place: field values borrow these fixed buffers. Keep the block
/// at a stable address until the transport has copied or written the fields.
pub const Block = struct {
    fields: std.ArrayList(http2.Hpack.HeaderField) = .empty,
    initial_binary: ?metadata.EncodedFields = null,
    trailing_binary: ?metadata.EncodedFields = null,
    encoded_message: ?[]u8 = null,
    inline_fields: [32]http2.Hpack.HeaderField = undefined,
    heap_fields: bool = false,
    status_buffer: [2]u8 = undefined,
    pushback_buffer: [21]u8 = undefined,
    accept_buffer: [32]u8 = undefined,

    pub fn prepare(self: *Block, allocator: std.mem.Allocator, options: Options) call.Error!void {
        self.* = .{};
        errdefer self.deinit(allocator);
        try call.validateCustomMetadata(options.initial_metadata);
        try call.validateCustomBinaryMetadata(options.initial_binary_metadata);
        self.initial_binary = try metadata.encodeFieldsAlloc(allocator, options.initial_binary_metadata);
        var terminal_count: usize = 0;
        if (options.terminal) |terminal| {
            try call.validateCustomMetadata(terminal.trailing_metadata);
            try call.validateCustomBinaryMetadata(terminal.trailing_binary_metadata);
            self.trailing_binary = try metadata.encodeFieldsAlloc(allocator, terminal.trailing_binary_metadata);
            if (terminal.status_message) |message| self.encoded_message = try wire.encodeStatusMessageAlloc(allocator, message);
            terminal_count = try sum(1 + @as(usize, @intFromBool(terminal.status_message != null)) + @as(usize, @intFromBool(terminal.retry_pushback_ms != null)), try sum(terminal.trailing_metadata.len, self.trailing_binary.?.fields.len));
        }
        const count = try sum(try sum(2 + @as(usize, @intFromBool(options.compression != .identity)), options.initial_metadata.len), try sum(self.initial_binary.?.fields.len, terminal_count));
        if (count <= self.inline_fields.len) {
            self.fields = .initBuffer(self.inline_fields[0..count]);
        } else {
            try self.fields.ensureTotalCapacityPrecise(allocator, count);
            self.heap_fields = true;
        }
        self.fields.appendAssumeCapacity(.{ .name = "content-type", .value = options.content_type.canonical() });
        self.fields.appendAssumeCapacity(.{ .name = "grpc-accept-encoding", .value = try compression.formatAcceptEncodingInto(&self.accept_buffer, options.accepted_encodings) });
        if (options.compression != .identity) self.fields.appendAssumeCapacity(.{ .name = "grpc-encoding", .value = options.compression.name() });
        self.fields.appendSliceAssumeCapacity(options.initial_metadata);
        self.fields.appendSliceAssumeCapacity(self.initial_binary.?.fields);
        if (options.terminal) |terminal| {
            self.fields.appendAssumeCapacity(.{ .name = "grpc-status", .value = std.fmt.bufPrint(&self.status_buffer, "{d}", .{@intFromEnum(terminal.status)}) catch unreachable });
            if (self.encoded_message) |message| self.fields.appendAssumeCapacity(.{ .name = "grpc-message", .value = message });
            if (terminal.retry_pushback_ms) |milliseconds| self.fields.appendAssumeCapacity(.{ .name = "grpc-retry-pushback-ms", .value = std.fmt.bufPrint(&self.pushback_buffer, "{d}", .{milliseconds}) catch unreachable });
            self.fields.appendSliceAssumeCapacity(terminal.trailing_metadata);
            self.fields.appendSliceAssumeCapacity(self.trailing_binary.?.fields);
        }
    }

    pub fn deinit(self: *Block, allocator: std.mem.Allocator) void {
        if (self.heap_fields) self.fields.deinit(allocator);
        if (self.initial_binary) |*binary| binary.deinit();
        if (self.trailing_binary) |*binary| binary.deinit();
        if (self.encoded_message) |message| allocator.free(message);
        self.* = .{};
    }
};

fn sum(a: usize, b: usize) call.Error!usize {
    return std.math.add(usize, a, b) catch error.MessageTooLarge;
}

test "gRPC-Web response header block handles heap fields and allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const repeated = [_]http2.Hpack.HeaderField{.{ .name = "x-many", .value = "value" }} ** 40;
    var block: Block = .{};
    try block.prepare(allocator, .{
        .content_type = .{ .format = .proto, .text = true },
        .compression = .gzip,
        .accepted_encodings = compression.AlgorithmSet.supported,
        .initial_metadata = &repeated,
        .initial_binary_metadata = &.{.{ .name = "x-initial-bin", .value = &.{ 1, 2 } }},
        .terminal = .{
            .status = .unavailable,
            .status_message = "try%again",
            .retry_pushback_ms = -123,
            .trailing_binary_metadata = &.{.{ .name = "x-end-bin", .value = &.{0xff} }},
        },
    });
    defer block.deinit(allocator);
    try std.testing.expect(block.heap_fields);
    try std.testing.expectEqualStrings("14", call.headerValue(block.fields.items, "grpc-status").?);
    try std.testing.expectEqualStrings("try%25again", call.headerValue(block.fields.items, "grpc-message").?);
    try std.testing.expectEqualStrings("-123", call.headerValue(block.fields.items, "grpc-retry-pushback-ms").?);
    try std.testing.expectEqualStrings("AQI", call.headerValue(block.fields.items, "x-initial-bin").?);
    try std.testing.expectEqualStrings("/w", call.headerValue(block.fields.items, "x-end-bin").?);
}
