//! A malformed message whose stream is known can transfer rejection ownership
//! to an endpoint adapter without attempting socket I/O inside the parser.
const std = @import("std");
const http3 = @import("../../mod.zig");
const runtime_error = @import("../error.zig");
const events = @import("../stream/events.zig");

pub const Failure = struct {
    stream_id: u62,
    err: runtime_error.Error,
    application_error_code: u64,

    pub fn fromError(stream_id: ?u62, err: anyerror) ?Failure {
        const id = stream_id orelse return null;
        const code = if (err == error.RequestIncomplete)
            http3.ApplicationErrorCode.request_incomplete
        else
            runtime_error.messageStreamErrorCode(err) orelse return null;
        return .{ .stream_id = id, .err = @errorCast(err), .application_error_code = code };
    }
};

pub const Result = union(enum) {
    event: events.Request,
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

pub fn capture(output: ?*?Failure, stream_id: ?u62, err: anyerror) bool {
    const sink = output orelse return false;
    sink.* = Failure.fromError(stream_id, err) orelse return false;
    return true;
}
