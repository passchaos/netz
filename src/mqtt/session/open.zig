//! Replacement admission is evaluated against the final Session Store state.
//! Prepare the owned identity before retiring any live/durable Session.

const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    SessionLimitExceeded,
    SessionByteLimitExceeded,
};

pub fn finalCount(count: usize, replacing: bool, maximum: usize) Error!usize {
    const result = std.math.add(usize, count, @intFromBool(!replacing)) catch return error.SessionLimitExceeded;
    if (result > maximum) return error.SessionLimitExceeded;
    return result;
}

pub fn prepareClientId(
    allocator: std.mem.Allocator,
    options: anytype,
    client_id: []const u8,
    total_bytes: usize,
    replacement_bytes: usize,
) Error![]u8 {
    const final_base_bytes = total_bytes - replacement_bytes;
    if (client_id.len > options.max_session_bytes or
        client_id.len > options.max_total_bytes -| final_base_bytes)
    {
        return error.SessionByteLimitExceeded;
    }
    return allocator.dupe(u8, client_id);
}
