//! Stream-local push failure ownership. A parent request remains active while
//! the rejected unidirectional response is stopped independently.
const std = @import("std");
const runtime_error = @import("../../error.zig");
const push_state = @import("state.zig");

pub const Failure = struct {
    push_id: u64,
    request_stream_id: u62,
    stream_id: u62,
    err: runtime_error.Error,
    application_error_code: u64,

    pub fn fromError(streams: *push_state.Set, stream_id: ?u62, err: anyerror) ?Failure {
        const code = runtime_error.messageStreamErrorCode(err) orelse return null;
        const id = stream_id orelse return null;
        const identity = streams.identityForStream(id) orelse return null;
        return .{
            .push_id = identity.push_id,
            .request_stream_id = identity.request_stream_id,
            .stream_id = id,
            .err = @errorCast(err),
            .application_error_code = code,
        };
    }
};

pub const Result = union(enum) {
    event: push_state.PushEvent,
    /// The caller owns scoped rejection submission through tryRejectPush.
    failure: Failure,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .event => |*event| event.deinit(allocator),
            .failure => {},
        }
        self.* = undefined;
    }
};

pub const Pending = @import("../../receive/pending_failure.zig").For(Failure);
