const std = @import("std");

pub const slab_size: usize = 256;

pub fn unread(
    buffer: *std.ArrayList(u8),
    consumed: usize,
) []u8 {
    std.debug.assert(consumed <= buffer.items.len);
    return buffer.items[consumed..];
}

pub fn unreadLen(buffer: *const std.ArrayList(u8), consumed: usize) usize {
    std.debug.assert(consumed <= buffer.items.len);
    return buffer.items.len - consumed;
}

/// Append transport bytes while bounding retained slack. Socket reads often
/// split a frame into a tiny header prefix and a payload suffix, so exact
/// growth reallocates twice while geometric growth retains roughly 1.5x the
/// frame. A small slab coalesces split reads with at most 255 bytes of slack.
pub fn appendPrecise(
    buffer: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    bytes: []const u8,
) std.mem.Allocator.Error!void {
    const required = std.math.add(
        usize,
        buffer.items.len,
        bytes.len,
    ) catch return error.OutOfMemory;
    if (required > buffer.capacity) {
        const rounded = try roundedCapacity(required);
        try buffer.ensureTotalCapacityPrecise(allocator, rounded);
    }
    buffer.appendSliceAssumeCapacity(bytes);
}

/// Append after a lazily consumed prefix. Compaction happens only when the
/// existing tail capacity cannot hold the new bytes; ordinary parsing can
/// therefore consume many coalesced frames without moving every later frame.
pub fn appendAfterConsumed(
    buffer: *std.ArrayList(u8),
    consumed: *usize,
    allocator: std.mem.Allocator,
    bytes: []const u8,
) std.mem.Allocator.Error!void {
    if (bytes.len == 0) return;
    const destination = try reserveAppendAfterConsumed(
        buffer,
        consumed,
        allocator,
        bytes.len,
    );
    @memcpy(destination, bytes);
    commitAppend(buffer, bytes.len);
}

/// Reserve a bounded tail slice that a transport can fill directly. This is
/// the zero-intermediate-copy counterpart to `appendAfterConsumed`; callers
/// must publish only initialized bytes with `commitAppend`.
pub fn reserveAppendAfterConsumed(
    buffer: *std.ArrayList(u8),
    consumed: *usize,
    allocator: std.mem.Allocator,
    additional: usize,
) std.mem.Allocator.Error![]u8 {
    std.debug.assert(consumed.* <= buffer.items.len);
    if (consumed.* != 0 and
        additional > buffer.capacity - buffer.items.len)
    {
        compact(buffer, consumed);
    }
    const required = std.math.add(
        usize,
        buffer.items.len,
        additional,
    ) catch return error.OutOfMemory;
    if (required > buffer.capacity) {
        const rounded = try roundedCapacity(required);
        try buffer.ensureTotalCapacityPrecise(allocator, rounded);
    }
    return buffer.unusedCapacitySlice()[0..additional];
}

pub fn commitAppend(buffer: *std.ArrayList(u8), initialized: usize) void {
    std.debug.assert(initialized <= buffer.capacity - buffer.items.len);
    buffer.items.len += initialized;
}

/// Consume one parsed frame and return the number of bytes physically moved.
/// The result is primarily useful to assert amortized behavior in tests.
pub fn discardPrefix(
    buffer: *std.ArrayList(u8),
    consumed: *usize,
    len: usize,
) usize {
    std.debug.assert(len <= unreadLen(buffer, consumed.*));
    consumed.* += len;
    if (consumed.* == buffer.items.len) {
        buffer.clearRetainingCapacity();
        consumed.* = 0;
        return 0;
    }
    const remaining = unreadLen(buffer, consumed.*);
    if (consumed.* < slab_size or consumed.* < remaining) return 0;
    compact(buffer, consumed);
    return remaining;
}

fn compact(buffer: *std.ArrayList(u8), consumed: *usize) void {
    std.debug.assert(consumed.* <= buffer.items.len);
    if (consumed.* == 0) return;
    const remaining = unreadLen(buffer, consumed.*);
    if (remaining != 0) {
        @memmove(buffer.items[0..remaining], buffer.items[consumed.*..]);
    }
    buffer.shrinkRetainingCapacity(remaining);
    consumed.* = 0;
}

pub fn roundedCapacity(required: usize) error{OutOfMemory}!usize {
    if (required == 0) return 0;
    const padded = std.math.add(
        usize,
        required,
        slab_size - 1,
    ) catch return error.OutOfMemory;
    return padded & ~(slab_size - 1);
}
