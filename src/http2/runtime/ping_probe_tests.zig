const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const Fixture = @import("duplex/testing.zig").Fixture;

const allocator = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
}

test "HTTP/2 background PING probe preserves application pumping and matches the exact ACK" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var stream = try fixture.open();
    defer stream.deinit();

    const payload = [8]u8{ 'N', 'Z', 'G', 'K', 0, 0, 0, 1 };
    const stale = [8]u8{ 'N', 'Z', 'G', 'K', 0, 0, 0, 0 };
    try fixture.connection.beginPingProbeWithDeadline(payload, deadline(fixture.io));
    try std.testing.expect(fixture.connection.pingProbePending());
    try std.testing.expectError(
        error.WriteInProgress,
        fixture.connection.beginPingProbeWithDeadline(stale, deadline(fixture.io)),
    );

    var wake: std.Io.Event = .unset;
    try fixture.frame(.ping, 1, 0, &stale);
    try std.testing.expectEqual(
        runtime.ClientDuplexPumpEvent.progress,
        try fixture.connection.pumpClientUntilOrWake(
            deadline(fixture.io),
            .fromSeconds(1),
            &wake,
        ),
    );
    try std.testing.expect(fixture.connection.pingProbePending());
    try std.testing.expect(!fixture.connection.takePingProbeAcknowledged());

    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    try fixture.headers(&encoder, stream.streamId(), true, &.{
        .{ .name = ":status", .value = "200" },
    });
    try std.testing.expectEqual(
        stream.streamId(),
        (try fixture.connection.pumpClientUntilOrWake(
            deadline(fixture.io),
            .fromSeconds(1),
            &wake,
        )).stream,
    );
    var head = (try stream.pollResponseEvent()).?;
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.head.status);
    try std.testing.expect(fixture.connection.pingProbePending());

    try fixture.frame(.ping, 1, 0, &payload);
    try std.testing.expectEqual(
        runtime.ClientDuplexPumpEvent.progress,
        try fixture.connection.pumpClientUntilOrWake(
            deadline(fixture.io),
            .fromSeconds(1),
            &wake,
        ),
    );
    try std.testing.expect(!fixture.connection.pingProbePending());
    try std.testing.expectError(
        error.WriteInProgress,
        fixture.connection.beginPingProbeWithDeadline(stale, deadline(fixture.io)),
    );
    try std.testing.expect(fixture.connection.takePingProbeAcknowledged());
    try std.testing.expect(!fixture.connection.takePingProbeAcknowledged());

    try fixture.connection.beginPingProbeWithDeadline(stale, deadline(fixture.io));
    fixture.connection.abandonPingProbe();
    try std.testing.expect(!fixture.connection.pingProbePending());
}

test "HTTP/2 background PING probe validates the write deadline before state" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();

    try std.testing.expectError(
        error.Timeout,
        fixture.connection.beginPingProbeWithDeadline(
            [_]u8{0} ** 8,
            .fromNow(fixture.io, .{ .raw = .zero, .clock = .awake }),
        ),
    );
    try std.testing.expect(!fixture.connection.pingProbePending());
    try std.testing.expect(!fixture.connection.takePingProbeAcknowledged());
}
