//! Test hooks for local bounded-read admission and cancellation faults.
const std = @import("std");
const websocket = @import("../../mod.zig");

pub const Fault = enum { executor, cancellation };

pub const InterruptedIo = struct {
    pub threadlocal var next: ?Fault = null;
    pub threadlocal var delegate: std.Io = undefined;

    pub fn awaitConcurrent(userdata: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        if (next) |fault| {
            next = null;
            return if (fault == .executor) error.ConcurrencyUnavailable else error.Canceled;
        }
        return delegate.vtable.batchAwaitConcurrent(userdata, batch, timeout);
    }
};

/// Seed an already-buffered non-final frame and wait for an injected error
/// before allowing the real peer to send its continuation.
pub fn caller(connection: anytype, io: std.Io, release: *std.Io.Event, fault: Fault) !void {
    const allocator = std.testing.allocator;
    try websocket.writeFrame(&connection.inbuf, allocator, .text, "accepted-\xe2", .{ .fin = false });
    var output: [64]u8 = undefined;
    InterruptedIo.next = fault;
    const expected = if (fault == .executor) error.ConcurrencyUnavailable else error.Canceled;
    try std.testing.expectError(expected, connection.receiveMessageIntoWithTimeout(&output, .fromSeconds(2)));
    try std.testing.expect(!connection.receive_failed.load(.acquire));
    try std.testing.expect(connection.message_into.active());
    try std.testing.expect(!connection.close_sent.load(.acquire));
    var replacement: [64]u8 = undefined;
    try std.testing.expectError(error.BufferTooShort, connection.receiveMessageIntoWithTimeout(&replacement, .fromSeconds(2)));
    try std.testing.expect(connection.message_into.active());
    release.set(io);
    const message = try connection.receiveMessageIntoWithTimeout(&output, .fromSeconds(2));
    try std.testing.expectEqualStrings("accepted-\xe2\x98\x83", message.payload);
    var next = try connection.receiveMessageWithTimeout(.fromSeconds(2));
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("following", next.payload);
    try connection.sendBinary("still writable");
}

pub fn suffix(allocator: std.mem.Allocator) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try websocket.writeFrame(&bytes, allocator, .continuation, "\x98\x83", .{});
    try websocket.writeFrame(&bytes, allocator, .binary, "following", .{});
    return bytes.toOwnedSlice(allocator);
}
