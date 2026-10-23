//! Replacement admission is evaluated against the final Session Store state.
//! Prepare the owned identity before retiring any live/durable Session.

const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    SessionLimitExceeded,
    SessionByteLimitExceeded,
};

/// Owns admission resources without changing a prior Session's generation or
/// lifetime. The Store must remain alive and unchanged through commit/deinit.
pub fn PreparedOpen(comptime Context: type) type {
    return struct {
        store: *Context.StoreType,
        index: usize,
        previous: ?Context.HandleType,
        client_id: ?[]u8 = null,
        expiry_interval: u32,
        session_present: bool,
        replaced_connection: bool,
        appended_slot: bool = false,
        committed: bool = false,

        pub fn deinit(self: *@This()) void {
            if (!self.committed and self.appended_slot) {
                std.debug.assert(self.index + 1 == self.store.sessions.items.len);
                std.debug.assert(self.store.sessions.items[self.index] == null);
                _ = self.store.sessions.pop();
            }
            if (self.client_id) |id| self.store.allocator.free(id);
            self.* = undefined;
        }
    };
}

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
