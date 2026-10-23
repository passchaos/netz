//! Failed CONNECT attempts retain HTTP/3 ownership until scoped cancellation
//! reaches the socket. Cleanup never waits beyond the opening operation.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const session_control = @import("../session_control.zig");

const Attempt = struct {
    stream_id: u62,
    application_error_code: u64,
    connect_cancelled: bool = false,

    fn poll(self: *Attempt, h3: *http3.runtime.HandshakeClient) session_control.Error!bool {
        if (!self.connect_cancelled) {
            try h3.connect_datagrams.rejectEarlyAssociation(self.stream_id);
            try h3.tryCancelRequest(self.stream_id, self.application_error_code);
            self.connect_cancelled = true;
        }
        // Discover early WT streams without claiming a sibling's streams or
        // allocating a registry entry for each abandoned stream.
        var streams = try webtransport.StreamRegistry.init(h3.allocator, .init(self.stream_id), .client, .{});
        defer streams.deinit();
        return try session_control.terminateStreamsOnce(&h3.established.connection, &streams) == .complete;
    }
};

pub const Pending = struct {
    attempts: std.ArrayList(Attempt) = .empty,

    pub fn deinit(self: *Pending, allocator: std.mem.Allocator) void {
        self.attempts.deinit(allocator);
        self.* = .{};
    }

    pub fn count(self: *const Pending) usize {
        return self.attempts.items.len;
    }

    pub fn contains(self: *const Pending, session_id: u62) bool {
        for (self.attempts.items) |attempt| if (attempt.stream_id == session_id) return true;
        return false;
    }

    /// Reserve before transmitting CONNECT so every later failure can retain
    /// its owner even if the allocator has since exhausted its budget.
    pub fn reserve(self: *Pending, allocator: std.mem.Allocator) std.mem.Allocator.Error!void {
        try self.attempts.ensureUnusedCapacity(allocator, 1);
    }

    pub fn abandon(self: *Pending, h3: *http3.runtime.HandshakeClient, stream_id: u62, code: u64) void {
        self.attempts.appendAssumeCapacity(.{ .stream_id = stream_id, .application_error_code = code });
        // Preserve the opening error. Transport or allocation failures keep
        // this attempt available for the next owning connection operation.
        self.advance(h3) catch {};
    }

    /// Each turn attempts CONNECT cancellation and at most one associated
    /// stream terminal submission per owner. Backpressure lets siblings run.
    pub fn advance(self: *Pending, h3: *http3.runtime.HandshakeClient) session_control.Error!void {
        var index: usize = 0;
        while (index < self.attempts.items.len) {
            const complete = self.attempts.items[index].poll(h3) catch |err| switch (err) {
                error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => false,
                else => return err,
            };
            if (complete) {
                _ = self.attempts.orderedRemove(index);
            } else {
                index += 1;
            }
        }
    }
};
