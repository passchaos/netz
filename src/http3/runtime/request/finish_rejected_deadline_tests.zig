//! Rejected-request cleanup keeps STOP_SENDING and QPACK output bounded.
const std = @import("std");
const http3 = @import("../../mod.zig");
const requests = @import("../receive/test_support/request_pair.zig");

fn paceBeyondDeadline(connection: anytype) void {
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(@intCast(
        std.Io.Clock.awake.now(connection.endpoint.io).nanoseconds,
    ));
}

fn admitRequest(pair: *requests.Pair, path: []const u8) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try (http3.Request{
        .method = "GET",
        .path = path,
        .authority = "localhost",
    }).write(&bytes, std.testing.allocator);
    try pair.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = bytes.items,
    } }});
    var event = (try pair.server.pollRequestEventOnce()) orelse
        return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(
        event == .message and event.message.value == .head,
    );
}

test "HTTP/3 rejected-request deadline retains STOP_SENDING under pacing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: requests.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try admitRequest(&pair, "/rejected-blocked");
    const connection = &pair.server.established.connection;
    paceBeyondDeadline(connection);
    try std.testing.expectError(
        error.Timeout,
        pair.server.finishRejectedRequestWithTimeout(
            0,
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(pair.server.request_lifecycle.contains(0));
    try std.testing.expect(
        connection.recvStreamStats(0).?.stop_sending_sent == null,
    );
    if (connection.sendStreamStats(0)) |stats| {
        try std.testing.expect(stats.reset == null);
    }
    try std.testing.expect(!connection.closing());

    connection.pacer.enabled = false;
    try pair.server.finishRejectedRequestWithTimeout(0, .fromSeconds(1));
    try std.testing.expect(!pair.server.request_lifecycle.contains(0));
    if (connection.sendStreamStats(0)) |stats| {
        try std.testing.expect(stats.reset == null);
    }
    try std.testing.expectEqual(
        http3.ApplicationErrorCode.request_cancelled,
        connection.recvStreamStats(0).?.stop_sending_sent.?.application_error_code,
    );
}

test "HTTP/3 rejected-request deadline validates guards before output" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: requests.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try admitRequest(&pair, "/rejected-guards");

    try std.testing.expectError(
        error.Timeout,
        pair.server.finishRejectedRequestWithTimeout(0, .fromMilliseconds(0)),
    );
    const real_deadline = std.Io.Clock.Timestamp{
        .clock = .real,
        .raw = std.Io.Clock.real.now(threaded.io()).addDuration(
            .fromSeconds(1),
        ),
    };
    try std.testing.expectError(
        error.Timeout,
        pair.server.finishRejectedRequestWithDeadline(0, real_deadline),
    );
    try std.testing.expect(pair.server.request_lifecycle.contains(0));

    pair.server.dispatcher_bound = true;
    defer pair.server.dispatcher_bound = false;
    try std.testing.expectError(
        error.InvalidDispatcherState,
        pair.server.finishRejectedRequestWithDeadline(0, .fromNow(
            threaded.io(),
            .{ .clock = .awake, .raw = .fromSeconds(1) },
        )),
    );
    try std.testing.expect(pair.server.request_lifecycle.contains(0));
}

test "HTTP/3 rejected-request cleanup rejects unknown streams" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: requests.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try admitRequest(&pair, "/rejected-unknown");
    try std.testing.expectError(
        error.UnexpectedStream,
        pair.server.finishRejectedRequestWithTimeout(
            4,
            .fromSeconds(1),
        ),
    );
    try std.testing.expect(pair.server.request_lifecycle.contains(0));
}
