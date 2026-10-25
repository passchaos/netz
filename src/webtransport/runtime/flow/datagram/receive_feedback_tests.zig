//! QPACK feedback must not delay a ready WebTransport payload.
const std = @import("std");
const quic = @import("../../../../quic/mod.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;

test "WebTransport DATAGRAM receive preserves payloads under QPACK feedback backpressure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ .client, .server }) |role| {
        for ([_]bool{ false, true }) |pacing| {
            for ([_]bool{ false, true }) |into| {
                var pair: Pair = undefined;
                try pair.init(threaded.io());
                defer pair.deinit();
                const session = if (role == .client) &pair.client else &pair.server;
                try session.h3.qpack_decode.recordStreamCancellation(0);
                const peer = pair.connection(if (role == .client) .server else .client);
                try peer.send(&.{.{ .datagram = .{ .data = "\x00ready" } }});
                const connection = pair.connection(role);
                const previous = connection.congestion.congestion_window;
                defer connection.congestion.congestion_window = previous;
                if (pacing) {
                    connection.pacer.enabled = true;
                    connection.setMaxPacingRateBytesPerSecond(1);
                    quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(threaded.io()).nanoseconds));
                } else connection.congestion.congestion_window = 0;
                const Receiver = struct {
                    fn run(target: @TypeOf(session), caller_buffer: bool) !void {
                        if (caller_buffer) {
                            var output: [16]u8 = undefined;
                            const payload = try target.receiveDatagramIntoWithTimeout(&output, .fromMilliseconds(100));
                            try std.testing.expectEqualStrings("ready", payload);
                        } else {
                            var payload = try target.receiveDatagramWithTimeout(.fromMilliseconds(100));
                            defer payload.deinit(std.testing.allocator);
                            try std.testing.expectEqualStrings("ready", payload.datagram.payload);
                        }
                    }
                };
                const Wake = union(enum) { done: anyerror!void, expired: std.Io.Cancelable!void };
                var storage: [2]Wake = undefined;
                var select: std.Io.Select(Wake) = .init(threaded.io(), &storage);
                defer select.cancelDiscard();
                try select.concurrent(.done, Receiver.run, .{ session, into });
                try select.concurrent(.expired, std.Io.sleep, .{ threaded.io(), std.Io.Duration.fromSeconds(1), std.Io.Clock.awake });
                switch (try select.await()) {
                    .done => |result| try result,
                    .expired => |result| {
                        try result;
                        return error.TestUnexpectedResult;
                    },
                }
                try std.testing.expectEqual(@as(usize, 1), session.h3.qpack_decode.pendingDecoderInstructions().len);
                try std.testing.expect(!session.control.state.closed and !connection.closing());
            }
        }
    }
}
