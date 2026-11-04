//! Request descriptions outlive callers when local interruption wins an RPC.
const std = @import("std");
const Header = @import("../../../http2/mod.zig").Hpack.HeaderField;
const Binary = @import("../../metadata.zig").BinaryMetadata;

pub const Inputs = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    metadata: []Header,
    binary_metadata: []Binary,

    pub fn deinit(self: *Inputs) void {
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
    var size = path_len;
    if (source.authority) |value| try add(&size, value.len);
    if (source.scheme) |value| try add(&size, value.len);
    if (source.xds_cluster) |value| try add(&size, value.len);
    for (source.metadata) |field| {
        try add(&size, field.name.len);
        try add(&size, field.value.len);
    }
    for (source.binary_metadata) |field| {
        try add(&size, field.name.len);
        try add(&size, field.value.len);
    }
    const storage = try allocator.alloc(u8, size);
    errdefer allocator.free(storage);
    const metadata = try allocator.alloc(Header, source.metadata.len);
    errdefer allocator.free(metadata);
    const binary = try allocator.alloc(Binary, source.binary_metadata.len);
    errdefer allocator.free(binary);
    var options = source;
    var offset: usize = 0;
    options.path = if (source.xds_path_rewrite) |rewrite| blk: {
        const rewritten = rewrite.write(
            source.path,
            storage[offset..][0..path_len],
        );
        offset += path_len;
        break :blk rewritten;
    } else copy(storage, &offset, source.path);
    options.authority = if (source.authority) |value| copy(storage, &offset, value) else null;
    options.scheme = if (source.scheme) |value| copy(storage, &offset, value) else null;
    options.xds_cluster = if (source.xds_cluster) |value| copy(storage, &offset, value) else null;
    options.xds_path_rewrite = null;
    for (source.metadata, metadata) |field, *owned| owned.* = .{
        .name = copy(storage, &offset, field.name),
        .value = copy(storage, &offset, field.value),
        .never_index = field.never_index,
    };
    for (source.binary_metadata, binary) |field, *owned| owned.* = .{ .name = copy(storage, &offset, field.name), .value = copy(storage, &offset, field.value) };
    options.metadata = metadata;
    options.binary_metadata = binary;
    return .{ .inputs = .{ .allocator = allocator, .storage = storage, .metadata = metadata, .binary_metadata = binary }, .options = options };
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
