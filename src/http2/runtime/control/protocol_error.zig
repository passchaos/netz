//! Terminal protocol output uses one finite caller-supplied cleanup budget.
const std = @import("std");

pub fn goAway(connection: anytype, last: u31, code: anytype, detail: []const u8, before: ?std.Io.Clock.Timestamp, comptime send: anytype) void {
    connection.aggregate_timeout_unusable = true;
    if (connection.terminal_write_failed) return;
    if (before) |deadline| {
        send(connection, last, code, detail, deadline) catch {
            connection.terminal_write_failed = true;
        };
    } else {
        connection.terminal_write_failed = true;
    }
}
