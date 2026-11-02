//! Share cluster circuit permits across ordinary and background channels.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const circuit = grpc.circuit_breaker;
const allocator = std.heap.c_allocator;
fn options(maximum: u32) circuit.Options {
    return .{ .cluster = "wire-cluster", .eds_service_name = "wire-eds", .max_concurrent_requests = maximum };
}
fn call(sender: grpc.SharedChannelSender, payload: []const u8) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/fixture.Circuit/Unary", .authority = "localhost", .message = payload, .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
}
fn rejected(response: *grpc.UnaryResponse) !void {
    try std.testing.expect(response.was_dropped and response.transport == null and response.status == .unavailable);
    try std.testing.expectEqualStrings("circuit breaker drop", response.status_message);
}
fn waitActive(io: std.Io, client: grpc.SharedChannel, count: u32) !void {
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    while (client.circuitStats().active != count) {
        if (until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    const target: grpc.ChannelTarget = .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) } } };
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var shared = try grpc.SharedChannel.init(allocator, io, target, .{ .channel = .{ .circuit_breaker = options(1) } });
    defer shared.deinit();
    var sender = shared.sender();
    defer sender.deinit();
    var ordinary = try grpc.Channel.init(allocator, io, target, .{ .circuit_breaker = options(1) });
    defer ordinary.deinit();
    var independent_options = options(1);
    independent_options.eds_service_name = "other-eds";
    var independent = try grpc.Channel.init(allocator, io, target, .{ .circuit_breaker = independent_options });
    defer independent.deinit();
    var first = try io.concurrent(call, .{ sender, "hold-one" });
    defer _ = first.cancel(io) catch {};
    try waitActive(io, shared, 1);
    var retry_policy: grpc.RetryPolicy = .{ .max_attempts = 5, .initial_backoff = .fromMilliseconds(1), .max_backoff = .fromMilliseconds(1), .backoff_multiplier = 1, .retryable_status_codes = &.{.unavailable} };
    var throttle = try grpc.call.RetryThrottler.init(10, 1);
    retry_policy.throttler = &throttle;
    var blocked = try ordinary.unaryWithRetry(.{ .path = "/fixture.Circuit/Unary", .message = "must-not-arrive" }, retry_policy);
    defer blocked.deinit();
    try rejected(&blocked);
    try std.testing.expectEqual(throttle.max_milli_tokens, throttle.milli_tokens.load(.acquire));
    var bypass = try independent.unary(.{ .path = "/fixture.Circuit/Unary", .message = "independent", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
    defer bypass.deinit();
    try std.testing.expectEqualStrings("independent", bypass.message.?.payload);
    _ = try shared.updateWithTimeout(.{ .circuit_breaker = .{ .replace = options(2) } }, .fromSeconds(3));
    var second = try call(sender, "release-one");
    defer second.deinit();
    try std.testing.expectEqualStrings("release-one", second.message.?.payload);
    var one = try first.await(io);
    defer one.deinit();
    try std.testing.expectEqualStrings("hold-one", one.message.?.payload);
    try waitActive(io, shared, 0);
    _ = try shared.updateWithTimeout(.{ .circuit_breaker = .{ .replace = options(1) } }, .fromSeconds(3));
    var stream = try sender.startDuplex(.{ .path = "/fixture.Circuit/Duplex", .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true });
    defer stream.deinit();
    var writer = stream.writer();
    defer writer.deinit();
    var reader = stream.reader();
    defer reader.deinit();
    try writer.writeFinalMessage("stream");
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(3));
        defer event.deinit(allocator);
        if (event == .message) {
            try std.testing.expectEqualStrings("held-stream", event.message.payload);
            break;
        }
    }
    try waitActive(io, shared, 1);
    var hedged = try sender.unaryWithHedging(.{ .path = "/fixture.Circuit/Unary", .message = "must-not-arrive" }, .{ .max_attempts = 5, .hedging_delay = .fromSeconds(1), .non_fatal_status_codes = &.{.unavailable} });
    defer hedged.deinit();
    try rejected(&hedged);
    try std.testing.expectEqual(@as(u64, 1), shared.hedgingStats().attempts_started);
    _ = try shared.updateWithTimeout(.{ .circuit_breaker = .{ .replace = options(0) } }, .fromSeconds(3));
    try std.testing.expectError(error.CallDropped, sender.startDuplex(.{ .path = "/fixture.Circuit/Duplex" }));
    var zero = try call(sender, "must-not-arrive");
    defer zero.deinit();
    try rejected(&zero);
    // Removing this channel's filter leaves the held stream permit alive in
    // the identity still observed by the ordinary channel.
    _ = try shared.updateWithTimeout(.{ .circuit_breaker = .{ .replace = null } }, .fromSeconds(3));
    try std.testing.expectEqual(@as(u32, 1), ordinary.circuitStats().active);
    try stream.cancelWithTimeout(.fromSeconds(3));
    try std.testing.expectEqual(@as(u32, 0), ordinary.circuitStats().active);
    var resumed = try ordinary.unary(.{ .path = "/fixture.Circuit/Unary", .message = "resumed", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
    defer resumed.deinit();
    try std.testing.expectEqualStrings("resumed", resumed.message.?.payload);
    const stats = ordinary.circuitStats();
    try std.testing.expectEqual(@as(u64, 4), stats.admitted);
    try std.testing.expectEqual(@as(u64, 4), stats.rejected);
    std.debug.print("CIRCUIT_RESULT {{\"status\":\"passed\",\"shared_identity\":true,\"independent_eds\":true,\"limit_update\":true,\"stream_cancel\":true,\"retry_stopped\":true,\"hedging_attempts\":1,\"active\":{d},\"admitted\":{d},\"rejected\":{d}}}\n", .{ stats.active, stats.admitted, stats.rejected });
}
