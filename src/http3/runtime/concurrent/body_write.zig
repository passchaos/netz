//! Retain exact DATA progress across owner retries without resending a prefix.
const std = @import("std");

pub const Progress = struct {
    /// Application DATA bytes whose submission is confirmed by the adapter.
    committed_bytes: usize = 0,
    /// True only after the requested FIN was submitted successfully.
    fin_committed: bool = false,
    /// False if a failed send cannot establish its exact visible prefix.
    /// The send direction is then unusable, so no suffix retry is permitted.
    retryable: bool = true,
};

pub const State = struct {
    progress: Progress = .{},
    completed: bool = false,

    /// `send` reports progress for this attempt, including when it returns an
    /// error. The state accumulates it before returning to the command loop.
    /// Callers retry the same logical input; only its uncommitted suffix is
    /// passed to the adapter on the next owner turn.
    pub fn write(self: *State, data: []const u8, fin: bool, deadline: ?std.Io.Clock.Timestamp, context: anytype, comptime send: anytype) anyerror!void {
        if (!self.progress.retryable) return error.ConnectionUnusable;
        if (self.completed) return;
        if (self.progress.committed_bytes > data.len) return error.Unexpected;
        const remaining = data[self.progress.committed_bytes..];
        var attempt: Progress = .{};
        const result = send(context, remaining, fin, &attempt, deadline);
        if (attempt.committed_bytes > remaining.len or (attempt.fin_committed and (!fin or attempt.committed_bytes != remaining.len))) {
            // A malformed adapter result cannot identify a safe retry suffix.
            self.progress.retryable = false;
            return error.Unexpected;
        }
        self.progress.committed_bytes += attempt.committed_bytes;
        self.progress.fin_committed = attempt.fin_committed;
        self.progress.retryable = self.progress.retryable and attempt.retryable;
        self.completed = self.progress.committed_bytes == data.len and (!fin or self.progress.fin_committed);
        try result;
        if (!self.completed) {
            self.progress.retryable = false;
            return error.Unexpected;
        }
    }
};
