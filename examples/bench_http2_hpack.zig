const std = @import("std");
const netz = @import("netz");

const iterations: usize = 100_000;
const churn_iterations: usize = 50_000;

const headers = [_]netz.http2.Hpack.HeaderField{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":authority", .value = "example.com" },
    .{ .name = ":path", .value = "/assets/app.js" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "user-agent", .value = "netz-hpack-bench/1" },
    .{ .name = "cache-control", .value = "no-cache" },
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stateful_encoder = netz.http2.Hpack.Encoder{};
    defer stateful_encoder.deinit(allocator);
    var stateful_decoder = netz.http2.Hpack.Decoder{};
    defer stateful_decoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);

    const stateful_start = nowNs(io);
    var stateful_total: usize = 0;
    for (0..iterations) |_| {
        block.clearRetainingCapacity();
        try stateful_encoder.encodeBlock(&block, allocator, &headers);
        stateful_total += block.items.len;
        const decoded = try stateful_decoder.decodeBlock(allocator, block.items);
        netz.http2.Hpack.freeDecodedFields(allocator, decoded);
    }
    const stateful_ns = nowNs(io) -| stateful_start;

    const stateless_start = nowNs(io);
    var stateless_total: usize = 0;
    for (0..iterations) |_| {
        block.clearRetainingCapacity();
        try netz.http2.Hpack.encodeLiteralBlock(&block, allocator, &headers);
        stateless_total += block.items.len;
        const decoded = try netz.http2.Hpack.decodeLiteralBlock(allocator, block.items);
        netz.http2.Hpack.freeDecodedFields(allocator, decoded);
    }
    const stateless_ns = nowNs(io) -| stateless_start;
    const speedup_x100 = ratioTimes100(stateless_ns, stateful_ns);
    const churn_ns = try measureDynamicTableChurn(allocator, io);

    std.debug.print(
        \\HTTP/2 HPACK benchmark
        \\  iterations: {d}
        \\  stateful total bytes: {d}, ns/op: {d}
        \\  stateless total bytes: {d}, ns/op: {d}
        \\  stateful speedup: {d}.{d:0>2}x
        \\  dynamic table churn iterations: {d}, ns/insert: {d}
        \\
    , .{
        iterations,
        stateful_total,
        stateful_ns / iterations,
        stateless_total,
        stateless_ns / iterations,
        speedup_x100 / 100,
        speedup_x100 % 100,
        churn_iterations,
        churn_ns / churn_iterations,
    });
}

fn measureDynamicTableChurn(allocator: std.mem.Allocator, io: std.Io) !u64 {
    var table = netz.http2.Hpack.DynamicTable{};
    defer table.deinit(allocator);
    table.setLimit(allocator, 4096);

    var names: [churn_iterations][24]u8 = undefined;
    var values: [churn_iterations][24]u8 = undefined;
    const started = nowNs(io);
    for (0..churn_iterations) |index| {
        const name = try std.fmt.bufPrint(
            &names[index],
            "x-hpack-churn-{d:0>5}",
            .{index},
        );
        const value = try std.fmt.bufPrint(
            &values[index],
            "value-{d:0>8}",
            .{index},
        );
        try table.add(allocator, name, value);
    }
    return nowNs(io) -| started;
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
