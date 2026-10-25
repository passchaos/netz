//! One committed automatic Continue response per connection-owned request.
pub const State = struct {
    sent: bool = false,

    pub fn reset(self: *State) void {
        self.* = .{};
    }
};

/// Commit only after the whole response is written. An uncertain partial
/// write keeps the caller's existing connection-retirement policy; successful
/// writes remain recorded across local request parsing and allocation retries.
pub fn send(comptime Error: type, transport: anytype, comptime write: anytype, state: ?*State, needed: bool) Error!void {
    if (!needed) return;
    if (state) |progress| {
        if (progress.sent) return;
    }
    try write(transport, "HTTP/1.1 100 Continue\r\n\r\n");
    if (state) |progress| progress.sent = true;
}
