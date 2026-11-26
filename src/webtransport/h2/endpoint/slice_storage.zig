//! Size-checked staging into command-owned storage for both H2 endpoint roles.
const std = @import("std");

pub fn byteLength(slices: []const []const u8) error{CapsuleTooLarge}!usize {
    var total: usize = 0;
    for (slices) |slice| total = std.math.add(usize, total, slice.len) catch return error.CapsuleTooLarge;
    return total;
}

pub fn copy(destination: []u8, slices: []const []const u8) void {
    var offset: usize = 0;
    for (slices) |slice| {
        @memcpy(destination[offset..][0..slice.len], slice);
        offset += slice.len;
    }
    std.debug.assert(offset == destination.len);
}
