//! Request descriptions outlive callers when local interruption wins an RPC.
const std = @import("std");
const call = @import("../../call.zig");
const Header = @import("../../../http2/mod.zig").Hpack.HeaderField;
const Binary = @import("../../metadata.zig").BinaryMetadata;

pub const Inputs = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    metadata: []Header,
    binary_metadata: []Binary,
    response_mutations: []call.HeaderMutation,
    response_removals: [][]const u8,

    pub fn deinit(self: *Inputs) void {
        if (self.response_removals.len != 0) self.allocator.free(self.response_removals);
        if (self.response_mutations.len != 0) self.allocator.free(self.response_mutations);
        self.allocator.free(self.binary_metadata);
        self.allocator.free(self.metadata);
        self.allocator.free(self.storage);
    }
};

pub fn clone(allocator: std.mem.Allocator, source: anytype) std.mem.Allocator.Error!struct { inputs: Inputs, options: @TypeOf(source) } {
    const path_len = if (source.xds_path_rewrite) |rewrite|
        rewrite.outputLen(source.path.len)
    else
        source.path.len;
    const host_len = if (source.xds_host_rewrite) |rewrite|
        rewrite.outputLen()
    else if (source.authority) |value|
        value.len
    else
        0;
    const metadata_capacity = try addValue(source.metadata.len, source.xds_request_header_mutations.len);
    var size = path_len;
    try add(&size, host_len);
    if (source.scheme) |value| try add(&size, value.len);
    if (source.xds_cluster) |value| try add(&size, value.len);
    for (source.metadata) |field| {
        try add(&size, field.name.len);
        try add(&size, field.value.len);
    }
    for (source.xds_request_header_mutations) |mutation| {
        try add(&size, mutation.name.len);
        try add(&size, mutation.value.len);
    }
    for (source.xds_response_header_mutations) |mutation| {
        try add(&size, mutation.name.len);
        try add(&size, mutation.value.len);
    }
    for (source.xds_response_header_removals) |name| {
        try add(&size, name.len);
    }
    for (source.binary_metadata) |field| {
        try add(&size, field.name.len);
        try add(&size, field.value.len);
    }
    const storage = try allocator.alloc(u8, size);
    errdefer allocator.free(storage);
    const metadata = try allocator.alloc(Header, metadata_capacity);
    errdefer allocator.free(metadata);
    const binary = try allocator.alloc(Binary, source.binary_metadata.len);
    errdefer allocator.free(binary);
    const response_mutations = if (source.xds_response_header_mutations.len == 0)
        @as([]call.HeaderMutation, &.{})
    else
        try allocator.alloc(call.HeaderMutation, source.xds_response_header_mutations.len);
    errdefer if (response_mutations.len != 0) allocator.free(response_mutations);
    const response_removals = if (source.xds_response_header_removals.len == 0)
        @as([][]const u8, &.{})
    else
        try allocator.alloc([]const u8, source.xds_response_header_removals.len);
    errdefer if (response_removals.len != 0) allocator.free(response_removals);
    var options = source;
    var offset: usize = 0;
    options.path = if (source.xds_path_rewrite) |rewrite| blk: {
        const rewritten = try rewrite.write(
            allocator,
            source.path,
            storage[offset..][0..path_len],
        );
        offset += path_len;
        break :blk rewritten;
    } else copy(storage, &offset, source.path);
    options.authority = if (source.xds_host_rewrite) |rewrite| blk: {
        const rewritten = try rewrite.write(
            allocator,
            source.path,
            storage[offset..][0..host_len],
        );
        offset += host_len;
        break :blk rewritten;
    } else if (source.authority) |value| copy(storage, &offset, value) else null;
    options.scheme = if (source.scheme) |value| copy(storage, &offset, value) else null;
    options.xds_cluster = if (source.xds_cluster) |value| copy(storage, &offset, value) else null;
    options.xds_path_rewrite = null;
    options.xds_host_rewrite = null;
    var metadata_count: usize = 0;
    for (source.metadata) |field| {
        metadata[metadata_count] = .{
            .name = copy(storage, &offset, field.name),
            .value = copy(storage, &offset, field.value),
            .never_index = field.never_index,
        };
        metadata_count += 1;
    }
    for (source.xds_request_header_removals) |name| {
        removeHeader(metadata[0..metadata_count], &metadata_count, name);
    }
    for (source.xds_request_header_mutations) |mutation| {
        const present = findHeader(metadata[0..metadata_count], mutation.name) != null;
        switch (mutation.action) {
            .append => {},
            .add_if_absent => if (present) continue,
            .overwrite => removeHeader(
                metadata[0..metadata_count],
                &metadata_count,
                mutation.name,
            ),
            .overwrite_if_exists => {
                if (!present) continue;
                removeHeader(
                    metadata[0..metadata_count],
                    &metadata_count,
                    mutation.name,
                );
            },
        }
        metadata[metadata_count] = .{
            .name = copy(storage, &offset, mutation.name),
            .value = copy(storage, &offset, mutation.value),
            .never_index = false,
        };
        metadata_count += 1;
    }
    options.xds_request_header_mutations = &.{};
    options.xds_request_header_removals = &.{};
    for (source.binary_metadata, binary) |field, *owned| owned.* = .{ .name = copy(storage, &offset, field.name), .value = copy(storage, &offset, field.value) };
    for (source.xds_response_header_mutations, response_mutations) |mutation, *owned| {
        owned.* = .{
            .name = copy(storage, &offset, mutation.name),
            .value = copy(storage, &offset, mutation.value),
            .action = mutation.action,
        };
    }
    for (source.xds_response_header_removals, response_removals) |name, *owned| {
        owned.* = copy(storage, &offset, name);
    }
    options.metadata = metadata[0..metadata_count];
    options.binary_metadata = binary;
    options.xds_response_header_mutations = response_mutations;
    options.xds_response_header_removals = response_removals;
    return .{ .inputs = .{
        .allocator = allocator,
        .storage = storage,
        .metadata = metadata,
        .binary_metadata = binary,
        .response_mutations = response_mutations,
        .response_removals = response_removals,
    }, .options = options };
}

fn findHeader(headers: []const Header, name: []const u8) ?usize {
    for (headers, 0..) |field, index| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return index;
    }
    return null;
}

fn removeHeader(headers: []Header, count: *usize, name: []const u8) void {
    var write: usize = 0;
    for (headers[0..count.*]) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) continue;
        headers[write] = field;
        write += 1;
    }
    count.* = write;
}

fn addValue(current: usize, amount: usize) std.mem.Allocator.Error!usize {
    return std.math.add(usize, current, amount) catch error.OutOfMemory;
}
fn add(size: *usize, amount: usize) std.mem.Allocator.Error!void {
    size.* = std.math.add(usize, size.*, amount) catch return error.OutOfMemory;
}
fn copy(storage: []u8, offset: *usize, bytes: []const u8) []const u8 {
    const result = storage[offset.*..][0..bytes.len];
    @memcpy(result, bytes);
    offset.* += bytes.len;
    return result;
}

test "shared request inputs apply xDS header mutations and removals" {
    const allocator = std.testing.allocator;
    const metadata = [_]Header{
        .{ .name = "x-keep", .value = "one" },
        .{ .name = "x-remove", .value = "gone" },
        .{ .name = "x-overwrite", .value = "old" },
    };
    const mutations = [_]call.HeaderMutation{
        .{ .name = "x-add", .value = "added", .action = .append },
        .{ .name = "x-overwrite", .value = "new", .action = .overwrite },
        .{ .name = "x-keep", .value = "ignored", .action = .add_if_absent },
        .{ .name = "x-missing", .value = "ignored", .action = .overwrite_if_exists },
    };
    const removals = [_][]const u8{"x-remove"};
    const response_mutations = [_]call.HeaderMutation{
        .{ .name = "x-response", .value = "mutated", .action = .overwrite },
    };
    const response_removals = [_][]const u8{"x-response-remove"};
    const source = call.UnaryCallOptions{
        .path = "/demo.Service/Get",
        .message = "request",
        .metadata = &metadata,
        .xds_request_header_mutations = &mutations,
        .xds_request_header_removals = &removals,
        .xds_response_header_mutations = &response_mutations,
        .xds_response_header_removals = &response_removals,
    };
    var cloned = try clone(allocator, source);
    defer cloned.inputs.deinit();
    try std.testing.expectEqual(@as(usize, 3), cloned.options.metadata.len);
    try std.testing.expectEqualStrings("one", headerValue(cloned.options.metadata, "x-keep").?);
    try std.testing.expectEqualStrings("added", headerValue(cloned.options.metadata, "x-add").?);
    try std.testing.expectEqualStrings("new", headerValue(cloned.options.metadata, "x-overwrite").?);
    try std.testing.expect(headerValue(cloned.options.metadata, "x-remove") == null);
    try std.testing.expect(headerValue(cloned.options.metadata, "x-missing") == null);
    try std.testing.expectEqual(@as(usize, 0), cloned.options.xds_request_header_mutations.len);
    try std.testing.expectEqual(@as(usize, 0), cloned.options.xds_request_header_removals.len);
    try std.testing.expectEqual(@as(usize, 1), cloned.options.xds_response_header_mutations.len);
    try std.testing.expectEqualStrings("x-response", cloned.options.xds_response_header_mutations[0].name);
    try std.testing.expectEqualStrings("mutated", cloned.options.xds_response_header_mutations[0].value);
    try std.testing.expectEqual(call.HeaderMutationAction.overwrite, cloned.options.xds_response_header_mutations[0].action);
    try std.testing.expectEqual(@as(usize, 1), cloned.options.xds_response_header_removals.len);
    try std.testing.expectEqualStrings("x-response-remove", cloned.options.xds_response_header_removals[0]);
}

fn headerValue(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}
