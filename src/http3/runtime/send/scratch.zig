const std = @import("std");
const quic = @import("../../../quic/mod.zig");

/// Reusable storage for one HTTP/3 request-stream send operation.
///
/// Handshake connections copy protected payloads into recovery-owned storage,
/// while the preconfigured-key runtime submits each datagram synchronously.
/// Encoded bytes and borrowing STREAM descriptors can therefore be cleared as
/// soon as a serialized send returns.
pub const Message = struct {
    encoded: std.ArrayList(u8) = .empty,
    frames: std.ArrayList(quic.Frame) = .empty,

    pub fn reset(self: *Message) void {
        self.encoded.clearRetainingCapacity();
        self.frames.clearRetainingCapacity();
    }

    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        self.frames.deinit(allocator);
        self.encoded.deinit(allocator);
        self.* = undefined;
    }
};

/// Reusable storage for one server-push operation. Parent and pushed message
/// bytes coexist while STREAM descriptors borrow both ranges.
pub const Push = struct {
    parent: std.ArrayList(u8) = .empty,
    pushed: std.ArrayList(u8) = .empty,
    frames: std.ArrayList(quic.Frame) = .empty,

    pub fn reset(self: *Push) void {
        self.parent.clearRetainingCapacity();
        self.pushed.clearRetainingCapacity();
        self.frames.clearRetainingCapacity();
    }

    pub fn deinit(self: *Push, allocator: std.mem.Allocator) void {
        self.frames.deinit(allocator);
        self.pushed.deinit(allocator);
        self.parent.deinit(allocator);
        self.* = undefined;
    }
};

/// Independent storage for control and QPACK streams, whose encodings must
/// coexist with request/response/Push bytes until connection send ownership.
pub const Critical = struct {
    payload: std.ArrayList(u8) = .empty,
    frames: std.ArrayList(quic.Frame) = .empty,

    pub fn reset(self: *Critical) void {
        self.payload.clearRetainingCapacity();
        self.frames.clearRetainingCapacity();
    }

    pub fn deinit(self: *Critical, allocator: std.mem.Allocator) void {
        self.frames.deinit(allocator);
        self.payload.deinit(allocator);
        self.* = undefined;
    }
};
