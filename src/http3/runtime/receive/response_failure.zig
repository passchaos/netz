//! Incremental response parsing transfers or retains stream-local rejection
//! ownership without retiring another request on the same connection.
const std = @import("std");
const runtime_error = @import("../error.zig");
const events = @import("../stream/events.zig");

pub const Failure = struct {
    stream_id: u62,
    err: runtime_error.Error,
    application_error_code: u64,

    pub fn fromError(stream_id: ?u62, err: anyerror) ?Failure {
        const id = stream_id orelse return null;
        const code = runtime_error.messageStreamErrorCode(err) orelse return null;
        return .{ .stream_id = id, .err = @errorCast(err), .application_error_code = code };
    }
};

pub const Result = union(enum) {
    event: events.Response,
    /// The caller owns RESET_STREAM/STOP_SENDING submission and retry.
    failure: Failure,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .event => |*event| event.deinit(allocator),
            .failure => {},
        }
        self.* = undefined;
    }
};

pub const Pending = @import("pending_failure.zig").For(Failure);
