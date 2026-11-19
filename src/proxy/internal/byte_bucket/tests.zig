const std = @import("std");
const ByteBucket = @import("../byte_bucket.zig").ByteBucket;

test "byte bucket enforces a rate and refills over time" {
    var bucket = ByteBucket.init(1000, 0);
    try std.testing.expect(bucket.tryConsume(1000, 0));
    try std.testing.expect(!bucket.tryConsume(1000, 0));
    try std.testing.expect(bucket.tryConsume(500, std.time.ns_per_s / 2));
    try std.testing.expect(bucket.tryConsume(500, std.time.ns_per_s));
    try std.testing.expect(bucket.tryConsume(1000, 2 * std.time.ns_per_s));
}

test "byte bucket with zero rate is unlimited" {
    var bucket = ByteBucket.init(0, 0);
    try std.testing.expect(bucket.tryConsume(std.math.maxInt(u64), 0));
    try std.testing.expect(bucket.tryConsume(std.math.maxInt(u64), 1));
}

test "byte bucket carries fractional credit across frequent polls" {
    var bucket = ByteBucket.init(1, 0);
    try std.testing.expect(bucket.tryConsume(1, 0));
    for (1..1000) |ms| {
        try std.testing.expect(!bucket.tryConsume(1, @intCast(ms * std.time.ns_per_ms)));
    }
    try std.testing.expect(bucket.tryConsume(1, std.time.ns_per_s));
}

test "byte bucket maximum wire rate and full clock span do not overflow" {
    var bucket = ByteBucket.init(std.math.maxInt(u64), std.math.minInt(i64));
    try std.testing.expect(bucket.tryConsume(1, std.math.minInt(i64)));
    try std.testing.expect(bucket.tryConsume(1, std.math.maxInt(i64)));
    try std.testing.expectEqual(std.math.maxInt(u64) - 1, bucket.tokens);
    try std.testing.expect(bucket.tryConsume(1, std.math.minInt(i64)));
}

test "byte bucket burst is independent of rate and refunds are bounded" {
    var bucket = ByteBucket.initWithBurst(1000, 16, 0);
    try std.testing.expect(bucket.tryConsume(16, 0));
    try std.testing.expectEqual(@as(u64, 8), bucket.available(1000, 8 * std.time.ns_per_ms));
    try std.testing.expectEqual(@as(u64, 8), bucket.tokens);
    bucket.refund(std.math.maxInt(u64));
    try std.testing.expectEqual(@as(u64, 16), bucket.tokens);
    try std.testing.expect(!bucket.tryConsume(17, std.time.ns_per_s));
}

test "byte bucket bounded wait progresses beyond a single burst" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var bucket = ByteBucket.initWithBurst(1_000_000, 1, @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds));
    try bucket.waitWithDeadline(3, io, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expect(bucket.tokens <= 1);
}

test "byte bucket expired wait leaves initial credit intact" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var bucket = ByteBucket.init(1, 0);
    try std.testing.expectError(error.Timeout, bucket.waitWithDeadline(1, io, .{ .clock = .awake, .raw = .{ .nanoseconds = 0 } }));
    try std.testing.expectEqual(@as(u64, 1), bucket.tokens);
}

test "byte bucket deadline refunds a partial uncommitted reservation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var bucket = ByteBucket.init(1, @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds));
    try std.testing.expectError(error.Timeout, bucket.waitWithDeadline(2, io, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2) })));
    try std.testing.expectEqual(@as(u64, 1), bucket.tokens);
}

test "byte bucket canceled wait refunds its reservation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var bucket = ByteBucket.init(1, @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds));
    var future = io.async(ByteBucket.wait, .{ &bucket, @as(u64, 2), io });
    try std.testing.expectError(error.Canceled, future.cancel(io));
    try std.testing.expectEqual(@as(u64, 1), bucket.tokens);
}
