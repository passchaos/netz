const std = @import("std");
const netz = @import("netz");

const filter_count: usize = 4096;
const iterations: usize = 20_000;
const shared_member_count: usize = 64;
const shared_iterations: usize = 100_000;

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
    const shared = try benchmarkSharedStrategies(allocator, io);

    std.debug.print(
        \\MQTT router benchmark
        \\  filters: {d}
        \\  iterations: {d}
        \\  router matches: {d}, ns/op: {d}
        \\  linear matches: {d}, ns/op: {d}
        \\  router speedup: {d}.{d:0>2}x
        \\  unsubscribed exact filters: {d}, ns/op: {d}
        \\  shared members: {d}, shared iterations: {d}
        \\  round-robin shared selection: {d} ns/op
        \\  sticky shared selection: {d} ns/op
        \\  random shared selection: {d} ns/op
        \\  rendezvous shared selection: {d} ns/op
        \\  shared checksum: {d}
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
        shared_member_count,
        shared_iterations,
        shared.round_robin_ns / shared_iterations,
        shared.sticky_ns / shared_iterations,
        shared.random_ns / shared_iterations,
        shared.rendezvous_ns / shared_iterations,
        shared.checksum,
    });
}

const SharedBenchmark = struct {
    round_robin_ns: u64,
    sticky_ns: u64,
    random_ns: u64,
    rendezvous_ns: u64,
    checksum: u64,
};

fn benchmarkSharedStrategies(
    allocator: std.mem.Allocator,
    io: std.Io,
) !SharedBenchmark {
    var round_robin = try initSharedRouter(
        allocator,
        .round_robin,
    );
    defer round_robin.deinit();
    var sticky = try initSharedRouter(allocator, .sticky);
    defer sticky.deinit();
    var random = try initSharedRouter(allocator, .random);
    defer random.deinit();
    var rendezvous = try initSharedRouter(
        allocator,
        .rendezvous_hash,
    );
    defer rendezvous.deinit();

    const rr_ns, const rr_checksum = try measureShared(
        &round_robin,
        io,
        false,
    );
    const sticky_ns, const sticky_checksum = try measureShared(
        &sticky,
        io,
        false,
    );
    const random_ns, const random_checksum = try measureShared(
        &random,
        io,
        false,
    );
    const rendezvous_ns, const rendezvous_checksum = try measureShared(
        &rendezvous,
        io,
        true,
    );
    return .{
        .round_robin_ns = rr_ns,
        .sticky_ns = sticky_ns,
        .random_ns = random_ns,
        .rendezvous_ns = rendezvous_ns,
        .checksum = rr_checksum +% sticky_checksum +%
            random_checksum +% rendezvous_checksum,
    };
}

fn initSharedRouter(
    allocator: std.mem.Allocator,
    strategy: netz.mqtt.router.SharedSubscriptionStrategy,
) !netz.mqtt.router.Router {
    var router = try netz.mqtt.router.Router.initWithOptions(
        allocator,
        .{
            .shared_subscription_strategy = strategy,
            .random_seed = 0x1234_5678,
        },
    );
    errdefer router.deinit();
    for (0..shared_member_count) |member| {
        try router.subscribe(
            @intCast(200_000 + member),
            .{ .topic_filter = "$share/workers/devices/+/state" },
        );
    }
    return router;
}

fn measureShared(
    router: *netz.mqtt.router.Router,
    io: std.Io,
    vary_topic: bool,
) !struct { u64, u64 } {
    var storage: [1]netz.mqtt.router.Match = undefined;
    var topic_buffer: [64]u8 = undefined;
    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..shared_iterations) |iteration| {
        const topic = if (vary_topic)
            try std.fmt.bufPrint(
                &topic_buffer,
                "devices/{d}/state",
                .{iteration & 1023},
            )
        else
            "devices/2047/state";
        const matches = try router.matchInto(topic, &storage);
        checksum +%= matches[0].subscriber_id;
    }
    return .{ nowNs(io) -| started, checksum };
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
