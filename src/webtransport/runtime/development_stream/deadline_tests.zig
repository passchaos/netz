const std = @import("std");
const runtime = @import("../../runtime.zig");
const http3 = @import("../../../http3/mod.zig");
const NativeIo = @import("../../../internal/testing/deadline_send_io.zig").Native;
const native_protocol_io = @import("../../../internal/testing/native_protocol_io.zig");

fn futureDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
}

test "WebTransport development stream deadline isolates a visible prefix" {
    try native_protocol_io.run(visiblePrefixDeadline);
}

fn visiblePrefixDeadline(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const limits: runtime.Limits = .{
        .http3 = .{
            .max_stream_frame_data = 32,
            .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            },
        },
        .max_session_streams = 2,
    };
    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithDeadline(
                futureDeadline(self.server.h3.quic_server.endpoint.io),
            );
            defer session.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
            var sibling = try session.receiveStreamWithDeadline(
                futureDeadline(self.server.h3.quic_server.endpoint.io),
            );
            defer sibling.deinit();
            try std.testing.expectEqualStrings("sibling", sibling.payload);
        }
    };
    var shared = Shared{ .server = &server };
    var thread = try io.concurrent(Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.cancel(io);

    var client = try runtime.ClientSession.connectWithDeadline(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/development-stream-deadline",
            .limits = limits,
        },
        futureDeadline(io),
    );
    defer client.deinit();
    const failed_stream = try client.openBidirectionalStream();
    client.h3.quic_client.endpoint.limits.max_datagram_size = 96;

    const original_io = client.h3.quic_client.endpoint.io;
    var progress: http3.runtime.DevelopmentBodyWriteProgress = .{};
    {
        var timed: NativeIo = .{
            .backend = .init(allocator, .{ .async_limit = .nothing }),
            .delegate_io = original_io,
            .now_ns = .init(@intCast(std.Io.Clock.awake.now(original_io).nanoseconds)),
            .advance_after_send_ns = std.time.ns_per_s,
        };
        defer timed.backend.deinit();
        client.h3.quic_client.endpoint.io = timed.io();
        defer client.h3.quic_client.endpoint.io = original_io;

        const payload = [_]u8{0xb7} ** 256;
        try std.testing.expectError(
            error.Timeout,
            client.sendStreamWithDeadline(
                failed_stream,
                &payload,
                true,
                &progress,
                .{
                    .clock = .awake,
                    .raw = .fromNanoseconds(timed.now_ns.load(.acquire) + 1),
                },
            ),
        );
        try std.testing.expect(progress.send_attempted);
        try std.testing.expect(!progress.completed);
        try std.testing.expectEqual(@as(usize, 1), timed.send_calls.load(.acquire));
        const failed_state = client.streams.get(failed_stream).?;
        try std.testing.expect(failed_state.prefix_sent);
        try std.testing.expect(failed_state.send_reset != null);
        try std.testing.expect(
            client.h3.development_stream_sends
                .findEntry(failed_stream).?.unusable,
        );
        try std.testing.expectError(
            error.InvalidStreamState,
            client.sendStream(failed_stream, "must-not-replay", false),
        );
    }

    client.h3.quic_client.endpoint.limits.max_datagram_size = 4096;
    const sibling = try client.openBidirectionalStream();
    try client.sendStreamWithTimeout(
        sibling,
        "sibling",
        true,
        &progress,
        .fromSeconds(1),
    );
    try std.testing.expect(progress.completed);

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}
