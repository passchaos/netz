//! A suspended complete upload shares the response reader and absolute budget.
const std = @import("std");
const http2 = @import("../../mod.zig");
const cleanup = @import("../response/cleanup.zig");

pub const Upload = struct {
    /// Optional bytes emitted before `body` as separate DATA slices.
    prefix: []const u8 = &.{},
    body: []const u8,
    trailers: []const http2.Hpack.HeaderField,
    /// Total bytes already committed across `prefix` and `body`.
    written: usize = 0,
    finished: bool = false,

    pub fn progress(self: *Upload, connection: anytype, stream_id: u31, deadline: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) Hooks.ErrorType!void {
        if (self.finished) return;
        if (self.written < self.prefix.len) {
            var sent: usize = 0;
            const slices = [_][]const u8{ self.prefix[self.written..], self.body };
            Hooks.slices(connection, stream_id, &slices, self.trailers.len == 0, &sent, deadline) catch |err| {
                self.written += sent;
                if (err == error.ResponseAvailable) return;
                // Response cleanup must not append a refund or CANCEL after
                // an indeterminate request frame prefix.
                if (connection.aggregate_timeout_unusable) connection.terminal_write_failed = true;
                return err;
            };
            self.written += sent;
        } else if (self.written < self.prefix.len + self.body.len) {
            var sent: usize = 0;
            Hooks.data(connection, stream_id, self.body[self.written - self.prefix.len ..], self.trailers.len == 0, &sent, deadline) catch |err| {
                self.written += sent;
                if (err == error.ResponseAvailable) return;
                // Response cleanup must not append a refund or CANCEL after
                // an indeterminate request frame prefix.
                if (connection.aggregate_timeout_unusable) connection.terminal_write_failed = true;
                return err;
            };
            self.written += sent;
        }
        if (self.trailers.len != 0) {
            Hooks.headers(connection, stream_id, self.trailers, true, deadline) catch |err| {
                if (connection.aggregate_timeout_unusable) connection.terminal_write_failed = true;
                return err;
            };
        }
        self.finished = true;
    }

    /// A complete response makes the unsent suffix unnecessary. Cancel the
    /// upload as a stream operation; a short DATA FIN would contradict an
    /// already advertised Content-Length. Preserve the received result even
    /// when bounded cleanup fails, while the parent retires unsafe reuse.
    pub fn finishResponse(self: *Upload, connection: anytype, stream_id: u31, deadline: ?std.Io.Clock.Timestamp) void {
        if (self.finished) return;
        const before = cleanup.cleanupDeadline(connection, deadline);
        if (before == null) {
            // A zero cleanup budget forbids transport output. The unfinished
            // stream cannot be reused after its local owner is discarded.
            connection.aggregate_timeout_unusable = true;
            connection.terminal_write_failed = true;
        }
        connection.abortExtendedConnect(stream_id, before);
        if (connection.aggregate_timeout_unusable) connection.terminal_write_failed = true;
        self.finished = true;
    }
};
