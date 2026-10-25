//! Message rejection must follow connection-wide HPACK synchronization.
const std = @import("std");
const http2 = @import("../../mod.zig");
const message = @import("../headers/message.zig");

pub fn read(connection: anytype, frame: http2.Frame, forbids_body: bool, deadline: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) Hooks.ErrorType![]http2.Hpack.HeaderField {
    const fields = Hooks.readHeaders(connection, frame, deadline) catch |err| {
        // The admitted field section cannot be replayed after losing its
        // assembly or decode progress. Retire every subsequent batch read.
        if (err == error.OutOfMemory or err == error.Timeout) connection.aggregate_timeout_unusable = true;
        return @as(Hooks.ErrorType![]http2.Hpack.HeaderField, err);
    };
    errdefer Hooks.freeHeaders(connection.allocator, fields);
    if (forbids_body) return error.InvalidContentLength;
    if ((frame.header.flags & 1) == 0) return error.UnexpectedFrame;
    try message.validateHeaderBlock(fields, .response_trailers);
    return fields;
}
