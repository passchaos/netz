//! Session-control adapter for the lightweight protected HTTP/3 runtime.
//!
//! Protected H3 already strips DATA frame headers and exposes caller-buffer
//! payload chunks. This adapter feeds those bytes into the shared Capsule
//! parser while retaining bytes after the first event in bounded storage.

const std = @import("std");
const session_control = @import("session_control.zig");

/// Maximum protected H3 DATA chunk accepted by the adapter. Retained suffixes
/// through 128 bytes stay inline; larger suffixes allocate their exact size.
pub const buffer_capacity: usize =
    4 + session_control.max_close_reason + 16;
const inline_pending_capacity: usize = 128;

pub const Error = session_control.Error || error{
    BufferTooShort,
};

pub const Reader = struct {
    control: session_control.Control,
    pending_inline: [inline_pending_capacity]u8 = undefined,
    pending_heap: ?[]u8 = null,
    pending_start: usize = 0,
    pending_end: usize = 0,

    pub fn init(control: session_control.Control) Reader {
        return .{ .control = control };
    }

    pub fn deinit(self: *Reader) void {
        self.clearPending();
        self.control.deinit();
        self.* = undefined;
    }

    fn pendingBytes(self: *const Reader) []const u8 {
        const bytes = self.pending_heap orelse &self.pending_inline;
        return bytes[self.pending_start..self.pending_end];
    }

    fn clearPending(self: *Reader) void {
        if (self.pending_heap) |bytes| {
            std.crypto.secureZero(u8, bytes);
            self.control.allocator.free(bytes);
            self.pending_heap = null;
        }
        self.pending_start = 0;
        self.pending_end = 0;
    }

    fn retain(self: *Reader, bytes: []const u8) !void {
        std.debug.assert(self.pending_start == self.pending_end);
        std.debug.assert(self.pending_heap == null);
        if (bytes.len <= self.pending_inline.len) {
            @memcpy(self.pending_inline[0..bytes.len], bytes);
        } else {
            self.pending_heap = try self.control.allocator.dupe(u8, bytes);
        }
        self.pending_start = 0;
        self.pending_end = bytes.len;
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
        if (bytes.len > buffer_capacity) return error.BufferTooShort;
        return self.consumeAndRetain(bytes);
    }

    pub fn pollPending(
        self: *Reader,
    ) Error!?session_control.Event {
        if (self.pending_start == self.pending_end) return null;
        const bytes = self.pendingBytes();
        const result = try self.control.feedCapsulePayload(bytes);
        self.pending_start += result.consumed;
        if (self.pending_start == self.pending_end) {
            self.clearPending();
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
        const control_snapshot = self.control;
        const result = try self.control.feedCapsulePayload(bytes);
        if (result.event) |event| {
            const remaining = bytes[result.consumed..];
            if (remaining.len > buffer_capacity) {
                self.control.restoreSnapshot(control_snapshot);
                return error.BufferTooShort;
            }
            self.retain(remaining) catch |err| {
                self.control.restoreSnapshot(control_snapshot);
                return err;
            };
            return event;
        }
        return null;
    }
};
