//! Stream send waits must keep CLOSE ahead of another application packet.
const std = @import("std");
const control = @import("../../session_control.zig");
const support = @import("../../flow/progress/support.zig");
const Pair = support.Pair;
const Shape = enum { send, slices, write, write_slices, batch, finish };

test "WebTransport stream send waits observe CLOSE before further submission" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |pacing| {
            for ([_]bool{ false, true }) |seeded| {
                for ([_]bool{ false, true }) |bounded| {
                    inline for (std.enums.values(Shape)) |shape| {
                        var pair: Pair = undefined;
                        try pair.init(threaded.io());
                        defer pair.deinit();
                        const session = if (role == .client) &pair.client else &pair.server;
                        const connection = pair.connection(role);
                        const id = try session.openUnidirectionalStream();
                        if (seeded) try session.sendStream(id, "seed", false);
                        var storage: [64]u8 = undefined;
                        const close = try control.writeCloseInto(&storage, 91, "during stream wait");
                        if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, close, false) else try pair.client.h3.sendRequestBodyPaced(0, close, false);
                        const previous = connection.congestion.congestion_window;
                        defer connection.congestion.congestion_window = previous;
                        if (pacing) support.pace(connection, threaded.io(), if (bounded) 1 else 1000) else connection.congestion.congestion_window = 0;
                        const before_offset = session.streams.get(id).?.send_offset;
                        const before_bytes = session.streams.get(id).?.bytes_sent;
                        var committed: usize = 99;
                        const Sender = struct {
                            fn run(target: @TypeOf(session), stream_id: u62, count: *usize, timed: bool) !void {
                                count.* = 0;
                                switch (shape) {
                                    .send => if (timed) try target.sendStreamWithTimeout(stream_id, "late", true, count, .fromMilliseconds(100)) else try target.sendStream(stream_id, "late", true),
                                    .slices => if (timed) try target.sendStreamSlicesWithTimeout(stream_id, &.{ "la", "te" }, true, count, .fromMilliseconds(100)) else try target.sendStreamSlices(stream_id, &.{ "la", "te" }, true),
                                    .write => count.* = if (timed) try target.writeStreamWithTimeout(stream_id, "late", .fromMilliseconds(100)) else try target.writeStream(stream_id, "late"),
                                    .write_slices => count.* = if (timed) try target.writeStreamSlicesWithTimeout(stream_id, &.{ "la", "te" }, .fromMilliseconds(100)) else try target.writeStreamSlices(stream_id, &.{ "la", "te" }),
                                    .batch => {
                                        var counts = [_]usize{99};
                                        defer count.* = counts[0];
                                        _ = if (timed) try target.writeStreamsWithTimeout(&.{.{ .stream_id = stream_id, .data = "late" }}, &counts, .fromMilliseconds(100)) else try target.writeStreams(&.{.{ .stream_id = stream_id, .data = "late" }}, &counts);
                                    },
                                    .finish => if (timed) try target.finishStreamWithTimeout(stream_id, .fromMilliseconds(100)) else try target.finishStream(stream_id),
                                }
                            }
                        };
                        try std.testing.expectError(error.InvalidSessionState, support.withinBudget(threaded.io(), Sender.run, .{ session, id, &committed, bounded }));
                        if (shape == .send or shape == .slices or shape == .batch) try std.testing.expectEqual(@as(usize, 0), committed);
                        try std.testing.expectEqual(before_offset, session.streams.get(id).?.send_offset);
                        try std.testing.expectEqual(before_bytes, session.streams.get(id).?.bytes_sent);
                        try std.testing.expect(!session.streams.get(id).?.local_fin);
                        connection.congestion.congestion_window = previous;
                        connection.pacer.enabled = false;
                        const event = (try pair.poll(role)).?;
                        try std.testing.expect(event == .closed);
                        try std.testing.expectEqualStrings("during stream wait", event.closed.reason);
                        try std.testing.expect(!connection.closing());
                    }
                }
            }
        }
    }
}
