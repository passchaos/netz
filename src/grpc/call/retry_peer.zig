//! Scripted HTTP/2 peer for retry lifecycle and metadata evidence.
const std = @import("std");
const grpc = @import("../mod.zig");
const http2 = @import("../../http2/mod.zig");

pub const Step = enum {
    refused,
    canceled,
    head_refused,
    interim_refused,
    unavailable,
    pushback_stop,
    pushback_delay,
    ok,
    silent,
};
pub const Peer = struct {
    server: *http2.runtime.Server,
    steps: []const Step,
    previous: []const []const u8,
    upload_stalled: bool = false,
    first_delay: std.Io.Duration = .zero,
    throttler: ?*grpc.RetryThrottler = null,
    tokens: []const u64 = &.{},
    attempts: usize = 0,
    timeouts: [16]i96 = @splat(0),
    err: ?anyerror = null,

    pub fn run(self: *Peer) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }
    fn inspect(self: *Peer, fields: []const http2.Hpack.HeaderField, index: usize) !void {
        const value = grpc.call.headerValue(fields, "grpc-previous-rpc-attempts");
        if (std.mem.eql(u8, self.previous[index], "-")) try std.testing.expect(value == null) else try std.testing.expectEqualStrings(self.previous[index], value.?);
        self.timeouts[index] = (try grpc.Timeout.parse(grpc.call.headerValue(fields, "grpc-timeout").?)).duration().nanoseconds;
        if (self.throttler) |throttler| try std.testing.expectEqual(self.tokens[index], throttler.milliTokens());
        self.attempts += 1;
        if (index == 0 and self.first_delay.nanoseconds != 0) try std.Io.sleep(self.server.io, self.first_delay, .awake);
    }
    fn serve(self: *Peer) !void {
        const allocator = self.server.allocator;
        var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
        defer connection.close();
        for (self.steps, 0..) |step, index| {
            if (self.upload_stalled and step != .ok) {
                var stream = try connection.acceptDuplexRequestWithTimeout(.fromSeconds(2));
                defer stream.deinit();
                try self.inspect(stream.headers, index);
                if (step == .head_refused) try stream.startResponseWithTimeout(.{ .headers = &.{.{ .name = "content-type", .value = "application/grpc" }} }, .fromSeconds(2));
                if (step == .interim_refused) try connection.writeInformationalResponseWithTimeout(stream.stream_id, 103, &.{}, .fromSeconds(2));
                try stream.reset(.refused_stream);
                continue;
            }
            var request = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer request.deinit(allocator);
            try self.inspect(request.headers, index);
            var parsed = try grpc.parseUnaryRequest(allocator, &request, 1024);
            defer parsed.deinit();
            try std.testing.expectEqualStrings("request", parsed.message.payload);
            switch (step) {
                .refused => try connection.sendResetStream(request.stream_id, .refused_stream),
                .canceled => try connection.sendResetStream(request.stream_id, .cancel),
                .head_refused => {
                    var writer = try connection.startResponseWithTimeout(request.stream_id, .{ .headers = &.{.{ .name = "content-type", .value = "application/grpc" }} }, .fromSeconds(2));
                    writer.finished = true;
                    try connection.sendResetStream(request.stream_id, .refused_stream);
                },
                .interim_refused => {
                    try connection.writeInformationalResponseWithTimeout(request.stream_id, 103, &.{}, .fromSeconds(2));
                    try connection.sendResetStream(request.stream_id, .refused_stream);
                },
                .unavailable => try grpc.writeUnaryResponse(&connection, allocator, request.stream_id, .{ .status = .unavailable, .retry_pushback_ms = 0, .trailers_only = true }),
                .pushback_stop => try writeDuplicatePushback(
                    &connection,
                    request.stream_id,
                    "0",
                    "-1",
                ),
                .pushback_delay => try writeDuplicatePushback(
                    &connection,
                    request.stream_id,
                    "-1",
                    "0",
                ),
                .ok => try grpc.writeUnaryResponse(&connection, allocator, request.stream_id, .{ .message = "reply" }),
                .silent => {
                    var reset = try connection.readResetStreamWithTimeout(.fromSeconds(2));
                    defer reset.deinit(allocator);
                    try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
                    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);
                },
            }
        }
    }
};

fn writeDuplicatePushback(
    connection: *http2.runtime.Connection,
    stream_id: u31,
    first: []const u8,
    second: []const u8,
) !void {
    try connection.writeResponse(stream_id, .{ .headers = &.{
        .{ .name = "content-type", .value = "application/grpc+proto" },
        .{ .name = "grpc-status", .value = "14" },
        .{ .name = "grpc-retry-pushback-ms", .value = first },
        .{ .name = "grpc-retry-pushback-ms", .value = second },
    } });
}
