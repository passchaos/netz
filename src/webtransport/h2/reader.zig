//! Incremental Capsule envelopes across arbitrary HTTP/2 DATA boundaries.
const std = @import("std");
const quic = @import("../../quic/mod.zig");
const capsules = @import("capsule.zig");

pub const Error = capsules.Error || error{CapsuleTooLarge};
const Stage = enum { kind, length, reserve, payload, skip, complete, failed };
const VarInt = struct {
    bytes: [8]u8 = undefined,
    len: u4 = 0,
    expected: u4 = 0,
    fn feed(self: *VarInt, byte: u8) ?u64 {
        if (self.len == 0) self.expected = @intCast(quic.varint.encodedLen(byte));
        self.bytes[self.len] = byte;
        self.len += 1;
        if (self.len != self.expected) return null;
        const number = (quic.varint.decodeSlice(self.bytes[0..self.len]) catch unreachable).value;
        self.len = 0;
        return number;
    }
};

pub const Reader = struct {
    allocator: std.mem.Allocator,
    max_payload: usize,
    buffer: std.ArrayList(u8) = .empty,
    stage: Stage = .kind,
    integer: VarInt = .{},
    kind: u64 = 0,
    remaining: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, max_payload: usize) Reader {
        return .{ .allocator = allocator, .max_payload = max_payload };
    }
    pub fn deinit(self: *Reader) void {
        self.buffer.deinit(self.allocator);
        self.* = undefined;
    }

    /// Advance the caller's retained slice only for consumed bytes. OOM leaves
    /// the slice at the first unconsumed payload byte and retains its envelope.
    /// Capsule payloads borrow the Reader until the next call to next/deinit.
    pub fn next(self: *Reader, input: *[]const u8) Error!?capsules.Capsule {
        while (true) switch (self.stage) {
            .complete => {
                self.buffer.clearRetainingCapacity();
                self.stage = .kind;
            },
            .kind => {
                if (input.*.len == 0) return null;
                if (self.integer.feed(input.*[0])) |kind| {
                    self.kind = kind;
                    self.stage = .length;
                }
                input.* = input.*[1..];
            },
            .length => {
                if (input.*.len == 0) return null;
                if (self.integer.feed(input.*[0])) |len| {
                    self.remaining = len;
                    self.stage = if (capsules.known(self.kind) and self.kind != capsules.CapsuleType.padding) .reserve else .skip;
                }
                input.* = input.*[1..];
            },
            .reserve => {
                if (self.remaining > self.max_payload) return error.CapsuleTooLarge;
                const len = std.math.cast(usize, self.remaining) orelse return error.CapsuleTooLarge;
                try self.buffer.ensureTotalCapacity(self.allocator, len);
                self.stage = .payload;
            },
            .payload => {
                const amount: usize = @intCast(@min(input.*.len, self.remaining));
                self.buffer.appendSliceAssumeCapacity(input.*[0..amount]);
                input.* = input.*[amount..];
                self.remaining -= amount;
                if (self.remaining != 0) return null;
                const capsule = capsules.parsePayload(self.kind, self.buffer.items) catch |err| {
                    self.stage = .failed;
                    return err;
                };
                self.stage = .complete;
                return capsule;
            },
            .skip => {
                const amount: usize = @intCast(@min(input.*.len, self.remaining));
                input.* = input.*[amount..];
                self.remaining -= amount;
                if (self.remaining != 0) return null;
                self.stage = .kind;
            },
            .failed => return error.InvalidCapsule,
        };
    }

    /// Clean CONNECT FIN is allowed only between complete capsules. Unknown
    /// payload truncation is an incomplete capsule just like known payloads.
    pub fn finish(self: *const Reader) Error!void {
        if ((self.stage == .kind and self.integer.len == 0) or self.stage == .complete) return;
        return error.InvalidCapsule;
    }
};

test {
    _ = @import("reader_tests.zig");
}
