const std = @import("std");

pub const max_parts: usize = 64;

pub const Shape = enum {
    contiguous,
    slices,

    pub fn parse(value: []const u8) error{InvalidArgument}!Shape {
        if (std.mem.eql(u8, value, "contiguous")) return .contiguous;
        if (std.mem.eql(u8, value, "slices")) return .slices;
        return error.InvalidArgument;
    }

    pub fn label(self: Shape) []const u8 {
        return @tagName(self);
    }
};

pub fn validatePartCount(part_count: usize) error{InvalidArgument}!void {
    if (part_count == 0 or part_count > max_parts) {
        return error.InvalidArgument;
    }
}

/// Divide one logical payload into exactly `part_count` borrowed slices.
/// Remainder bytes are assigned to the earliest slices; when there are more
/// parts than bytes, trailing slices are empty.
pub fn split(
    storage: *[max_parts][]const u8,
    payload: []const u8,
    part_count: usize,
) error{InvalidArgument}![]const []const u8 {
    try validatePartCount(part_count);
    const base = payload.len / part_count;
    const remainder = payload.len % part_count;
    var offset: usize = 0;
    for (storage[0..part_count], 0..) |*part, index| {
        const len = base + @intFromBool(index < remainder);
        part.* = payload[offset..][0..len];
        offset += len;
    }
    std.debug.assert(offset == payload.len);
    return storage[0..part_count];
}

pub fn join(
    destination: []u8,
    parts: []const []const u8,
) error{InvalidArgument}![]u8 {
    var total: usize = 0;
    for (parts) |part| {
        total = std.math.add(usize, total, part.len) catch
            return error.InvalidArgument;
    }
    if (destination.len < total) return error.InvalidArgument;
    var offset: usize = 0;
    for (parts) |part| {
        @memcpy(destination[offset..][0..part.len], part);
        offset += part.len;
    }
    return destination[0..total];
}

/// Send the same logical multi-part message either after an explicit caller
/// join or directly through the runtime's single-frame slice API. The join
/// buffer is caller-owned and preallocated, so the benchmark isolates copy and
/// transport-shape cost rather than allocator behavior.
pub fn sendBinary(
    connection: anytype,
    payload: []const u8,
    shape: Shape,
    part_count: usize,
    joined: []u8,
) !void {
    if (shape == .contiguous and part_count == 1) {
        return connection.sendBinary(payload);
    }
    var part_storage: [max_parts][]const u8 = undefined;
    const parts = try split(&part_storage, payload, part_count);
    switch (shape) {
        .contiguous => {
            return connection.sendBinary(try join(joined, parts));
        },
        .slices => return connection.sendBinarySlices(parts),
    }
}

test "WebSocket benchmark send shapes preserve arbitrary slice layouts" {
    const payload = "abcdefghijk";
    var storage: [max_parts][]const u8 = undefined;
    const parts = try split(&storage, payload, 4);
    try std.testing.expectEqual(@as(usize, 4), parts.len);
    try std.testing.expectEqualStrings("abc", parts[0]);
    try std.testing.expectEqualStrings("def", parts[1]);
    try std.testing.expectEqualStrings("ghi", parts[2]);
    try std.testing.expectEqualStrings("jk", parts[3]);
    var joined: [payload.len]u8 = undefined;
    try std.testing.expectEqualStrings(payload, try join(&joined, parts));
    try std.testing.expectError(
        error.InvalidArgument,
        join(joined[0 .. joined.len - 1], parts),
    );

    const sparse = try split(&storage, "xy", 4);
    try std.testing.expectEqualStrings("x", sparse[0]);
    try std.testing.expectEqualStrings("y", sparse[1]);
    try std.testing.expectEqual(@as(usize, 0), sparse[2].len);
    try std.testing.expectEqual(@as(usize, 0), sparse[3].len);
    try std.testing.expectError(error.InvalidArgument, split(&storage, payload, 0));
    try std.testing.expectError(
        error.InvalidArgument,
        split(&storage, payload, max_parts + 1),
    );
    try std.testing.expectEqual(Shape.contiguous, try Shape.parse("contiguous"));
    try std.testing.expectEqual(Shape.slices, try Shape.parse("slices"));
    try std.testing.expectError(error.InvalidArgument, Shape.parse("fragmented"));
}
