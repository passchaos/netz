//! Retained CLOSE payloads and one-packet DATA progress for a shared server.

const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const control = @import("../session_control.zig");
const pending_close = @import("../session_control/pending_close.zig");
const lifecycle = @import("../connection_lifecycle.zig");

pub const Error = control.Error;

pub fn clear(target: anytype) void {
    if (target.pending_close) |*pending| pending.deinit();
    target.pending_close = null;
    target.close_write = .{};
}

pub fn prepare(target: anytype, code: u32, reason: []const u8) Error!void {
    if (target.pending_close) |*pending| {
        if (!try pending.matches(code, reason)) return error.InvalidSessionState;
        return;
    }
    try lifecycle.ensureOpen(&target.control, target.h3, &target.streams);
    var pending = try pending_close.Pending.init(target.h3.established.connection.endpoint.allocator, code, reason);
    errdefer pending.deinit();
    try target.control.beginLocalClose();
    target.pending_close = pending;
    target.close_write = .{};
}

pub fn advanceOnce(target: anytype) Error!control.TerminateProgress {
    if (target.pending_close == null) return .complete;
    if (target.control.local_close_failed or target.control.handledInvalidCapsule()) {
        clear(target);
        return .complete;
    }
    if (target.control.terminal_reported) {
        if (target.close_write.wire_sent != 0) {
            try target.h3.tryCancelRequest(target.session_id.value, webtransport.ApplicationErrorCode.session_gone);
            target.control.recordLocalCloseFailure(0);
            target.close_response_pending = false;
            clear(target);
            return .submitted;
        }
        target.control.local_close_started = false;
        target.close_response_pending = true;
        clear(target);
        return .complete;
    }
    const pending = &target.pending_close.?;
    target.h3.tryWriteResponseBody(target.session_id.value, pending.bytes(), true, &target.close_write) catch |err| switch (err) {
        error.RequestCancelled, error.RequestRejected, error.StreamStopped => {
            target.control.recordLocalCloseFailure(0);
            clear(target);
            return .complete;
        },
        else => return err,
    };
    if (target.close_write.complete) {
        const code = pending.code;
        clear(target);
        try target.control.recordLocalClose(code);
        target.close_response_pending = false;
    }
    return .submitted;
}
