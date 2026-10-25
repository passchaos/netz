//! Bound regression tests for ordinary and deadline-bound send APIs.
const std = @import("std");

pub fn withinBudget(session: anytype, io: std.Io, batch: bool, bounded: bool, stream_id: u62, values: []const []const u8, committed: *usize) !void {
    const Sender = struct {
        fn run(target: @TypeOf(session), many: bool, timed: bool, id: u62, payloads: []const []const u8, count: *usize) !void {
            if (many) {
                if (timed) try target.sendConnectDatagramsWithTimeout(id, payloads, count, .fromMilliseconds(100)) else try target.sendConnectDatagrams(id, payloads, count);
            } else {
                if (timed) try target.sendConnectDatagramWithTimeout(id, payloads[0], .fromMilliseconds(100)) else try target.sendConnectDatagram(id, payloads[0]);
            }
        }
    };
    const Wake = union(enum) { done: anyerror!void, expired: std.Io.Cancelable!void };
    var storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &storage);
    defer select.cancelDiscard();
    try select.concurrent(.done, Sender.run, .{ session, batch, bounded, stream_id, values, committed });
    try select.concurrent(.expired, std.Io.sleep, .{ io, std.Io.Duration.fromSeconds(1), std.Io.Clock.awake });
    switch (try select.await()) {
        .done => |result| try result,
        .expired => |result| {
            try result;
            return error.TestUnexpectedResult;
        },
    }
}
