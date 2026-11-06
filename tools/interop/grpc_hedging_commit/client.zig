//! Production SharedChannel hedging against independent Node HTTP/2 peers.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const allocator = std.heap.c_allocator;

const Case = struct {
    name: []const u8,
    body: []const u8,
    status: grpc.Status = .ok,
    attempts: u64,
    delayed: u64 = 0,
    accelerated: u64 = 0,
    canceled: u64 = 0,
    tokens: u64 = 4000,
    reset_code: i64 = -1,
    exhausted: u64 = 0,
};

const cases = [_]Case{
    .{ .name = "head_cancels_loser", .body = "b-committed", .attempts = 2, .delayed = 1, .canceled = 1 },
    .{ .name = "head_suppresses_later", .body = "a-held", .attempts = 1 },
    .{ .name = "head_unavailable_wins", .body = "", .status = .unavailable, .attempts = 1, .tokens = 3000 },
    .{ .name = "trailers_only_accelerates", .body = "b-accelerated", .attempts = 2, .accelerated = 1 },
    .{ .name = "informational_does_not_commit", .body = "b-informational", .attempts = 2, .delayed = 1, .canceled = 1 },
    .{ .name = "call_wide_transparent_budget", .body = "", .status = .unavailable, .attempts = 2, .accelerated = 1, .tokens = 2000, .reset_code = 7, .exhausted = 1 },
};

fn exercise(io: std.Io, endpoints: []const grpc.ChannelEndpoint, config: Case) !void {
    // Each case starts with endpoint A at the first round-robin position and
    // waits for both production endpoint owners before starting the RPC.
    var client = try grpc.SharedChannel.init(allocator, io, .{
        .resolved = .{ .endpoints = endpoints, .policy = .round_robin },
    }, .{});
    defer client.deinit();
    const ready_by = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    try client.connectWithDeadline(ready_by);
    for (0..endpoints.len) |index| {
        var watch = (try client.watchEndpointConnectivityWithDeadline(index, ready_by)) orelse return error.MissingEndpoint;
        defer watch.deinit();
        try watch.waitForReadyWithDeadline(ready_by);
    }
    var sender = client.sender();
    defer sender.deinit();
    var throttler = try grpc.RetryThrottler.init(4, 1);
    const accelerated = config.accelerated != 0;
    var response = try sender.unaryWithHedging(.{
        .path = "/fixture.Hedging/Unary",
        .authority = "localhost",
        .message = config.name,
        .metadata = &.{
            .{ .name = "x-case", .value = config.name },
            .{ .name = "x-preserved", .value = "preserved" },
        },
        .wait_for_ready = true,
        .timeout = .{ .value = 5, .unit = .second },
    }, .{
        .max_attempts = 2,
        .hedging_delay = if (accelerated) .fromSeconds(3) else .fromMilliseconds(75),
        .non_fatal_status_codes = &.{.unavailable},
        .throttler = &throttler,
    });
    defer response.deinit();
    try std.testing.expectEqual(config.status, response.status);
    if (config.body.len == 0) {
        try std.testing.expect(response.message == null);
    } else try std.testing.expectEqualStrings(config.body, response.message.?.payload);
    const reset_code: i64 = if (response.reset) |reset| @intFromEnum(reset.error_code) else -1;
    try std.testing.expectEqual(config.reset_code, reset_code);
    try std.testing.expectEqual(config.reset_code == -1, response.response_committed);
    try std.testing.expectEqual(config.tokens, throttler.milliTokens());
    const stats = client.hedgingStats();
    try std.testing.expectEqual(@as(u64, 1), stats.calls);
    try std.testing.expectEqual(config.attempts, stats.attempts_started);
    try std.testing.expectEqual(config.delayed, stats.delayed_attempts);
    try std.testing.expectEqual(config.accelerated, stats.accelerated_attempts);
    try std.testing.expectEqual(config.canceled, stats.canceled_losers);
    try std.testing.expectEqual(config.exhausted, stats.exhausted_non_fatal);
    try std.testing.expectEqual(@as(u64, 0), stats.backend_failures);
    try std.testing.expectEqual(@as(u64, 0), stats.deadline_expirations);
    try std.testing.expectEqual(@as(u64, @intFromBool(config.status == .ok)), stats.ok_winners);
    try std.testing.expectEqual(@as(u64, @intFromBool(config.status == .unavailable and config.exhausted == 0)), stats.fatal_winners);
    std.debug.print("HEDGING_COMMIT_CASE {{\"name\":\"{s}\",\"status_code\":{d},\"body\":\"{s}\",\"reset_code\":{d},\"response_committed\":{},\"milli_tokens\":{d},\"attempts_started\":{d},\"delayed_attempts\":{d},\"accelerated_attempts\":{d},\"canceled_losers\":{d},\"throttled_attempts\":{d},\"ok_winners\":{d},\"fatal_winners\":{d},\"exhausted_non_fatal\":{d},\"backend_failures\":{d},\"deadline_expirations\":{d}}}\n", .{
        config.name,                @intFromEnum(response.status), config.body,            reset_code,                 response.response_committed,
        throttler.milliTokens(),    stats.attempts_started,        stats.delayed_attempts, stats.accelerated_attempts, stats.canceled_losers,
        stats.throttled_attempts,   stats.ok_winners,              stats.fatal_winners,    stats.exhausted_non_fatal,  stats.backend_failures,
        stats.deadline_expirations,
    });
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArgument;
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) } } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[2], 10)) } } },
    };
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    for (cases) |config| try exercise(backend.io(), &endpoints, config);
    std.debug.print("HEDGING_COMMIT_RESULT {{\"status\":\"passed\",\"cases\":6,\"runtime\":\"zio\"}}\n", .{});
}
