//! One absolute budget for HTTP responses emitted before WebSocket framing.
//! Unbounded callers retain their scatter write; bounded callers advance the
//! header and body under the same deadline without renewing it.

const std = @import("std");

pub fn Writer(comptime Context: type) type {
    return struct {
        transport: Context.TransportType,
        deadline: ?std.Io.Clock.Timestamp = null,

        pub fn write(self: @This(), header: []const u8, body: []const u8) Context.ErrorType!void {
            if (self.deadline) |deadline| {
                var committed: usize = 0;
                try Context.writeWithDeadline(self.transport, header, &committed, deadline);
                if (body.len != 0) try Context.writeWithDeadline(self.transport, body, &committed, deadline);
            } else {
                try Context.writeAllParts(self.transport, header, body);
            }
        }
    };
}
