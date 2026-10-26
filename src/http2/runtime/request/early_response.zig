//! Preserve the pending response while ending the upload under its write budget.
const std = @import("std");
const flow_output = @import("../flow/output.zig");

pub fn finish(writer: anytype, sent: usize, deadline: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) void {
    writer.written += sent;
    writer.body_finished = true;
    // The tracked DATA writer rejects writes while a response is pending.
    // Emit only the empty request-half FIN, retaining the response event even
    // if the FIN fails and the parent can no longer safely carry new frames.
    flow_output.writeEmpty(writer.connection.allocator, Hooks.transport(writer.connection), writer.stream_id, true, deadline) catch {
        writer.connection.aggregate_timeout_unusable = true;
    };
}
