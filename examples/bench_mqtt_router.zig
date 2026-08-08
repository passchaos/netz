const std = @import("std");
const netz = @import("netz");

const filter_count: usize = 4096;
const iterations: usize = 20_000;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var router = try netz.mqtt.router.Router.init(allocator);
    defer router.deinit();

    var filters: std.ArrayList([]u8) = .empty;
    defer {
        for (filters.items) |filter| allocator.free(filter);
        filters.deinit(allocator);
    }
    try filters.ensureTotalCapacity(allocator, filter_count + 2);

    var filter_buf: [64]u8 = undefined;
    for (0..filter_count) |i| {
        const filter = try std.fmt.bufPrint(&filter_buf, "devices/{d}/state", .{i});
        const owned = try allocator.dupe(u8, filter);
        try filters.append(allocator, owned);
        try router.subscribe(@intCast(i), .{ .topic_filter = owned });
    }
    const wildcard_one = try allocator.dupe(u8, "devices/+/state");
    try filters.append(allocator, wildcard_one);
    try router.subscribe(100_000, .{ .topic_filter = wildcard_one });
    const wildcard_many = try allocator.dupe(u8, "devices/#");
    try filters.append(allocator, wildcard_many);
    try router.subscribe(100_001, .{ .topic_filter = wildcard_many });

    var matches: [8]netz.mqtt.router.Match = undefined;
    const topic = "devices/2047/state";

    const router_start = nowNs(io);
    var router_total: usize = 0;
    for (0..iterations) |_| {
        router_total += (try router.matchInto(topic, &matches)).len;
    }
    const router_ns = nowNs(io) -| router_start;

    const linear_start = nowNs(io);
    var linear_total: usize = 0;
    for (0..iterations) |_| {
        for (filters.items) |filter| {
            linear_total += @intFromBool(netz.mqtt.topicMatchesFilter(topic, filter));
        }
    }
    const linear_ns = nowNs(io) -| linear_start;
    const speedup_x100 = ratioTimes100(linear_ns, router_ns);

    const unsubscribe_start = nowNs(io);
    var removed: usize = 0;
    for (filters.items[0..filter_count], 0..) |filter, i| {
        try router.unsubscribe(@intCast(i), filter);
        removed += 1;
    }
    const unsubscribe_ns = nowNs(io) -| unsubscribe_start;

    std.debug.print(
        \\MQTT router benchmark
        \\  filters: {d}
        \\  iterations: {d}
        \\  router matches: {d}, ns/op: {d}
        \\  linear matches: {d}, ns/op: {d}
        \\  router speedup: {d}.{d:0>2}x
        \\  unsubscribed exact filters: {d}, ns/op: {d}
        \\
    , .{
        filters.items.len,
        iterations,
        router_total,
        router_ns / iterations,
        linear_total,
        linear_ns / iterations,
        speedup_x100 / 100,
        speedup_x100 % 100,
        removed,
        unsubscribe_ns / removed,
    });
}

fn ratioTimes100(numerator: u64, denominator: u64) u64 {
    if (denominator == 0) return 0;
    return (numerator *| 100) / denominator;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
