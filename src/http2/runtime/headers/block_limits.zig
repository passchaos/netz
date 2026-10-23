const std = @import("std");

pub const Collected = struct {
    bytes: []const u8,
    limit_exceeded: bool = false,
};

pub fn byteLimit(frame_payload: usize, fields: usize) usize {
    return std.math.mul(usize, frame_payload, fields +| 1) catch std.math.maxInt(usize);
}

/// A terminal frame can be retained once beyond the assembly limit so its
/// complete HPACK input can be discarded safely. An unfinished over-limit
/// section cannot be drained within the configured resource bound.
pub fn completeOverflow(count: usize, max_count: usize, bytes: usize, max_bytes: usize, end_headers: bool) error{MessageTooLarge}!bool {
    const exceeded = count > max_count or bytes > max_bytes;
    if (exceeded and !end_headers) return error.MessageTooLarge;
    return exceeded;
}
