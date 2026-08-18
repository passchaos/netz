//! Session-control adapter for the lightweight protected HTTP/3 runtime.
//!
//! Protected H3 already strips DATA frame headers and exposes caller-buffer
//! payload chunks. This adapter feeds those bytes into the shared Capsule
//! parser while retaining bytes after the first event in fixed storage.

const session_control = @import("session_control.zig");

/// One protected H3 DATA payload chunk plus any bytes retained after an event.
///
/// The capacity includes the largest valid WT_CLOSE_SESSION capsule and
/// conservative varint headroom. Runtime readers use this same limit, so when
/// an event ends inside a chunk its unconsumed suffix always fits in `pending`.
pub const buffer_capacity: usize =
    4 + session_control.max_close_reason + 16;

pub const Error = session_control.Error || error{
    BufferTooShort,
};

pub const Reader = struct {
    control: session_control.Control,
    pending: [buffer_capacity]u8 = undefined,
    pending_start: usize = 0,
    pending_end: usize = 0,

    pub fn init(control: session_control.Control) Reader {
        return .{ .control = control };
    }

    pub fn consume(
        self: *Reader,
        bytes: []const u8,
    ) Error!?session_control.Event {
        if (self.pending_start != self.pending_end) {
            return error.InvalidSessionState;
        }
        // Reject oversized direct use before mutating the incremental parser.
        // Runtime callers share `buffer_capacity`, making this guard an API
        // misuse check rather than a protocol-size restriction.
        if (bytes.len > self.pending.len) return error.BufferTooShort;
        return self.consumeAndRetain(bytes);
    }

    pub fn pollPending(
        self: *Reader,
    ) Error!?session_control.Event {
        if (self.pending_start == self.pending_end) return null;
        const bytes = self.pending[self.pending_start..self.pending_end];
        const result = try self.control.feedCapsulePayload(bytes);
        self.pending_start += result.consumed;
        if (self.pending_start == self.pending_end) {
            self.pending_start = 0;
            self.pending_end = 0;
        }
        return result.event;
    }

    pub fn finish(
        self: *Reader,
    ) Error!?session_control.Event {
        if (try self.pollPending()) |event| return event;
        return self.control.finishCapsulePayload();
    }

    fn consumeAndRetain(
        self: *Reader,
        bytes: []const u8,
    ) Error!?session_control.Event {
        const result = try self.control.feedCapsulePayload(bytes);
        if (result.event) |event| {
            const remaining = bytes[result.consumed..];
            if (remaining.len > self.pending.len) {
                return error.BufferTooShort;
            }
            @memcpy(self.pending[0..remaining.len], remaining);
            self.pending_start = 0;
            self.pending_end = remaining.len;
            return event;
        }
        return null;
    }
};
