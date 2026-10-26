//! Deadline-bound request cancellation preserves one-attempt retry ownership.
const std = @import("std");
const http3 = @import("../../mod.zig");
const requests = @import("../receive/test_support/request_pair.zig");
const responses = @import("../receive/test_support/response_pair.zig");

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

test "HTTP/3 server cancellation deadline retains request under pacing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: requests.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try admitRequest(&pair, "/server-cancel");
    const connection = &pair.server.established.connection;
    paceBeyondDeadline(connection);
    try std.testing.expectError(
        error.Timeout,
        pair.server.cancelRequestWithTimeout(
            0,
            http3.ApplicationErrorCode.request_cancelled,
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(pair.server.request_lifecycle.contains(0));
    try std.testing.expect(connection.sendStreamStats(0).?.reset == null);
    try std.testing.expect(
        connection.recvStreamStats(0).?.stop_sending_sent == null,
    );
    try std.testing.expect(!connection.closing());

    connection.pacer.enabled = false;
    try pair.server.cancelRequestWithTimeout(
        0,
        http3.ApplicationErrorCode.request_cancelled,
        .fromSeconds(1),
    );
    try std.testing.expect(!pair.server.request_lifecycle.contains(0));
    try std.testing.expectEqual(
        http3.ApplicationErrorCode.request_cancelled,
        connection.sendStreamStats(0).?.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        http3.ApplicationErrorCode.request_cancelled,
        connection.recvStreamStats(0).?.stop_sending_sent.?.application_error_code,
    );
}

test "HTTP/3 client cancellation deadline retains response owner under pacing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: responses.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const connection = &pair.client.established.connection;
    try std.testing.expect(pair.client.request_lifecycle.contains(0));
    paceBeyondDeadline(connection);
    try std.testing.expectError(
        error.Timeout,
        pair.client.cancelRequestWithDeadline(
            0,
            http3.ApplicationErrorCode.request_cancelled,
            .fromNow(threaded.io(), .{
                .clock = .awake,
                .raw = .fromMilliseconds(20),
            }),
        ),
    );
    try std.testing.expect(pair.client.request_lifecycle.contains(0));
    try std.testing.expect(connection.sendStreamStats(0).?.reset == null);
    try std.testing.expect(
        connection.recvStreamStats(0).?.stop_sending_sent == null,
    );
    try std.testing.expect(!connection.closing());

    connection.pacer.enabled = false;
    try pair.client.cancelRequestWithTimeout(
        0,
        http3.ApplicationErrorCode.request_cancelled,
        .fromSeconds(1),
    );
    try std.testing.expect(!pair.client.request_lifecycle.contains(0));
    try std.testing.expectEqual(
        http3.ApplicationErrorCode.request_cancelled,
        connection.recvStreamStats(0).?.stop_sending_sent.?.application_error_code,
    );
}

test "HTTP/3 cancellation deadlines reject zero budgets and foreign clocks" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var request_pair: requests.Pair = undefined;
    try request_pair.init(threaded.io());
    defer request_pair.deinit();
    try admitRequest(&request_pair, "/server-guards");

    try std.testing.expectError(
        error.Timeout,
        request_pair.server.cancelRequestWithTimeout(
            0,
            http3.ApplicationErrorCode.request_cancelled,
            .fromMilliseconds(0),
        ),
    );
    try std.testing.expect(request_pair.server.request_lifecycle.contains(0));

    const real_deadline = std.Io.Clock.Timestamp{
        .clock = .real,
        .raw = std.Io.Clock.real.now(threaded.io()).addDuration(
            .fromSeconds(1),
        ),
    };
    try std.testing.expectError(
        error.Timeout,
        request_pair.server.cancelRequestWithDeadline(
            0,
            http3.ApplicationErrorCode.request_cancelled,
            real_deadline,
        ),
    );
    try std.testing.expect(request_pair.server.request_lifecycle.contains(0));

    var response_pair: responses.Pair = undefined;
    try response_pair.init(threaded.io());
    defer response_pair.deinit();
    try std.testing.expectError(
        error.Timeout,
        response_pair.client.cancelRequestWithDeadline(
            0,
            http3.ApplicationErrorCode.request_cancelled,
            real_deadline,
        ),
    );
    try std.testing.expect(response_pair.client.request_lifecycle.contains(0));
}

test "HTTP/3 deadline cancellation keeps endpoint owner guards" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{
        .clock = .awake,
        .raw = .fromSeconds(1),
    });

    var request_pair: requests.Pair = undefined;
    try request_pair.init(threaded.io());
    defer request_pair.deinit();
    try admitRequest(&request_pair, "/dispatcher-bound");
    request_pair.server.dispatcher_bound = true;
    try std.testing.expectError(
        error.InvalidDispatcherState,
        request_pair.server.cancelRequestWithDeadline(
            0,
            http3.ApplicationErrorCode.request_cancelled,
            deadline,
        ),
    );
    try std.testing.expect(request_pair.server.request_lifecycle.contains(0));
    try std.testing.expectError(
        error.InvalidDispatcherState,
        request_pair.server.rejectRequestWithDeadline(0, deadline),
    );

    var response_pair: responses.Pair = undefined;
    try response_pair.init(threaded.io());
    defer response_pair.deinit();
    response_pair.client.dispatcher_bound = true;
    defer response_pair.client.dispatcher_bound = false;
    try std.testing.expectError(
        error.InvalidDispatcherState,
        response_pair.client.cancelRequestWithDeadline(
            0,
            http3.ApplicationErrorCode.request_cancelled,
            deadline,
        ),
    );
    response_pair.client.dispatcher_bound = false;
    response_pair.client.callback_reader_active = true;
    defer response_pair.client.callback_reader_active = false;
    try std.testing.expectError(
        error.ConcurrentRead,
        response_pair.client.cancelRequestWithDeadline(
            0,
            http3.ApplicationErrorCode.request_cancelled,
            deadline,
        ),
    );
    try std.testing.expect(response_pair.client.request_lifecycle.contains(0));
}

test "HTTP/3 rejection deadline validates before request mutation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: requests.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try admitRequest(&pair, "/reject");
    try std.testing.expectError(
        error.Timeout,
        pair.server.rejectRequestWithDeadline(0, .{
            .clock = .real,
            .raw = std.Io.Clock.real.now(threaded.io()).addDuration(
                .fromSeconds(1),
            ),
        }),
    );
    try std.testing.expect(pair.server.request_lifecycle.contains(0));
    if (pair.server.established.connection.sendStreamStats(0)) |stats| {
        try std.testing.expect(stats.reset == null);
    }
    try pair.server.rejectRequestWithTimeout(0, .fromSeconds(1));
    try std.testing.expect(!pair.server.request_lifecycle.contains(0));
    try std.testing.expectEqual(
        http3.ApplicationErrorCode.request_rejected,
        pair.server.established.connection.sendStreamStats(0).?.reset.?.application_error_code,
    );
}
