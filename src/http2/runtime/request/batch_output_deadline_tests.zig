//! Batch deadlines cover socket output, not only response/flow-control reads.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;
const Mode = enum { heads, heads_callback, body, body_callback, individual_heads, individual_body };

const Observer = struct {
    errors: [2]?anyerror = .{ null, null },
    delivered: usize = 0,
    fn consume(self: *@This(), _: usize, data: []const u8) !void {
        self.delivered += data.len;
    }
    fn result(context: *anyopaque, index: usize, value: runtime.BatchOwnedResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        switch (value) {
            .err => |err| self.errors[index] = err,
            .response => |response| {
                var owned = response;
                owned.deinit(allocator);
            },
        }
    }
};

fn run(connection: *runtime.Connection, mode: Mode, requests: []const runtime.RequestOptions, observer: *Observer) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = .fromMilliseconds(30), .clock = .awake });
    var responses: [2]runtime.OwnedResponse = undefined;
    var streaming: [2]runtime.StreamingResponse = undefined;
    switch (mode) {
        .heads => {
            try connection.requestBatchIntoWithDeadline(requests, &responses, deadline);
            for (&responses) |*response| response.deinit(allocator);
        },
        .heads_callback => {
            try connection.requestBatchStreamingIntoWithDeadline(requests, &streaming, deadline, observer, Observer.consume);
            for (&streaming) |*response| response.deinit(allocator);
        },
        .body => {
            try connection.requestBodyBatchIntoWithDeadline(requests, 16_384, &responses, deadline);
            for (&responses) |*response| response.deinit(allocator);
        },
        .body_callback => {
            try connection.requestBodyBatchStreamingIntoWithDeadline(requests, 16_384, &streaming, deadline, observer, Observer.consume);
            for (&streaming) |*response| response.deinit(allocator);
        },
        .individual_heads, .individual_body => {
            const deadlines = [_]?std.Io.Clock.Timestamp{ deadline, .fromNow(connection.io, .{ .raw = .fromSeconds(2), .clock = .awake }) };
            const output: runtime.BatchOwnedResponseObserver = .{ .context = observer, .on_result = Observer.result };
            if (mode == .individual_heads) try connection.requestBatchWithPerStreamDeadlines(requests, &deadlines, output) else try connection.requestBodyBatchWithPerStreamDeadlines(requests, 16_384, &deadlines, output);
        },
    }
}

fn exercise(mode: Mode, data: bool) !void {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    try fixture.startRescue();
    const large = "x" ** (256 * 1024);
    const requests = [_]runtime.RequestOptions{
        .{ .method = "POST", .path = "/one", .authority = "localhost", .headers = if (data) &.{} else &.{.{ .name = "x-large", .value = large }}, .body = if (data) large else &.{} },
        .{ .method = "POST", .path = "/two", .authority = "localhost", .body = if (data) large else &.{} },
    };
    var observer: Observer = .{};
    const started = std.Io.Clock.awake.now(fixture.connection.io);
    try std.testing.expectError(error.Timeout, run(&fixture.connection, mode, &requests, &observer));
    try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.send_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), observer.delivered);
    if (mode == .individual_heads or mode == .individual_body) {
        try std.testing.expectEqual(@as(?anyerror, error.Timeout), observer.errors[0]);
        try std.testing.expectEqual(@as(?anyerror, error.Timeout), observer.errors[1]);
    }
}

test "HTTP/2 batch output deadline bounds blocked opening HEADERS" {
    for (std.enums.values(Mode)) |mode| try exercise(mode, false);
}

test "HTTP/2 batch output deadline bounds shared and individual DATA bursts" {
    for ([_]Mode{ .body, .body_callback, .individual_body }) |mode| try exercise(mode, true);
}
