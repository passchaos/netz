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

/// Default polling retains failed messages until their scoped cancellation is
/// submitted. Storage is reserved before parsing and bounded by live requests.
pub const Pending = struct {
    items: std.ArrayList(Failure) = .empty,

    pub fn count(self: *const Pending) usize {
        return self.items.items.len;
    }

    pub fn clear(self: *Pending) void {
        self.items.clearRetainingCapacity();
    }

    pub fn deinit(self: *Pending, allocator: std.mem.Allocator) void {
        self.items.deinit(allocator);
        self.* = .{};
    }

    pub fn reserve(self: *Pending, allocator: std.mem.Allocator) std.mem.Allocator.Error!void {
        try self.items.ensureUnusedCapacity(allocator, 1);
    }

    pub fn append(self: *Pending, failure: Failure) void {
        for (self.items.items) |existing| std.debug.assert(existing.stream_id != failure.stream_id);
        self.items.appendAssumeCapacity(failure);
    }

    pub fn take(self: *Pending, target: ?u62) ?Failure {
        for (self.items.items, 0..) |failure, index| {
            if (target) |id| if (failure.stream_id != id) continue;
            return self.items.orderedRemove(index);
        }
        return null;
    }

    /// One submission per matching owner. Congestion or pacing on a failed
    /// stream does not prevent another buffered request from being parsed.
    pub fn poll(self: *Pending, context: anytype, target: ?u62, comptime submit: anytype) runtime_error.Error!?Failure {
        for (self.items.items, 0..) |failure, index| {
            if (target) |id| if (failure.stream_id != id) continue;
            submit(context, failure) catch |err| switch (err) {
                error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => continue,
                else => return err,
            };
            return self.items.orderedRemove(index);
        }
        return null;
    }
};
