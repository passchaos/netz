//! Bound tests for owning and caller-buffer receive APIs.
const std = @import("std");

pub const Mode = enum { into, owned, batch, progress };
pub const Output = struct {
    storage: [3][32]u8 = undefined,
    slices: [3][]u8 = undefined,
    received: usize = 99,

    pub fn init(self: *Output) void {
        for (&self.slices, &self.storage) |*slice, *buffer| slice.* = buffer;
    }
};

pub fn withinBudget(session: anytype, io: std.Io, mode: Mode, bounded: bool, output: *Output) !void {
    const Receiver = struct {
        fn run(target: @TypeOf(session), shape: Mode, timed: bool, out: *Output) !void {
            switch (shape) {
                .into => {
                    out.slices[0] = if (timed) try target.receiveConnectDatagramIntoWithTimeout(0, out.slices[0], .fromMilliseconds(100)) else try target.receiveConnectDatagramInto(0, out.slices[0]);
                    out.received = 1;
                },
                .owned => {
                    var datagram = if (timed) try target.receiveConnectDatagramWithTimeout(0, .fromMilliseconds(100)) else try target.receiveConnectDatagram(0);
                    defer datagram.deinit(std.testing.allocator);
                    @memcpy(out.storage[0][0..datagram.payload.len], datagram.payload);
                    out.slices[0] = out.storage[0][0..datagram.payload.len];
                    out.received = 1;
                },
                .batch => {
                    if (timed) try target.receiveConnectDatagramsIntoWithTimeout(0, &out.slices, &out.received, .fromMilliseconds(100)) else try target.receiveConnectDatagramsInto(0, &out.slices, &out.received);
                },
                .progress => {
                    if (comptime @hasDecl(@typeInfo(@TypeOf(target)).pointer.child, "receiveDetachedRequestProgress")) {
                        if (timed) try target.receiveDetachedRequestProgressWithTimeout(0, .fromMilliseconds(100)) else try target.receiveDetachedRequestProgress(0);
                    } else {
                        if (timed) try target.receiveDetachedResponseProgressWithTimeout(0, .fromMilliseconds(100)) else try target.receiveDetachedResponseProgress(0);
                    }
                },
            }
        }
    };
    const Wake = union(enum) { done: anyerror!void, expired: std.Io.Cancelable!void };
    var storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &storage);
    defer select.cancelDiscard();
    try select.concurrent(.done, Receiver.run, .{ session, mode, bounded, output });
    try select.concurrent(.expired, std.Io.sleep, .{ io, std.Io.Duration.fromSeconds(1), std.Io.Clock.awake });
    switch (try select.await()) {
        .done => |result| try result,
        .expired => |result| {
            try result;
            return error.TestUnexpectedResult;
        },
    }
}
