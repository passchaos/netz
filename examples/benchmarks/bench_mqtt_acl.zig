const std = @import("std");
const sampling = @import("support").bench_sampling;
const netz = @import("netz");

const rule_count: usize = 512;
const iterations: usize = 20_000;

const Context = struct {
    acl: *const netz.mqtt.acl_file.File,
    identity: netz.mqtt.acl_file.Identity,
    topic: []const u8,
    iterations: usize,
};

pub fn main(init: std.process.Init) !void {
    _ = init;
    const allocator = std.heap.smp_allocator;

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(allocator);
    try source.appendSlice(allocator, "user alice\n");
    for (0..rule_count) |index| {
        var line: [64]u8 = undefined;
        const text = try std.fmt.bufPrint(
            &line,
            "topic read devices/alice/{d:0>4}/state\n",
            .{index},
        );
        try source.appendSlice(allocator, text);
    }

    var acl = try netz.mqtt.acl_file.parse(allocator, source.items);
    defer acl.deinit();

    const identity = netz.mqtt.acl_file.Identity{
        .client_id = "bench-client",
        .username = "alice",
    };
    var late_topic_buf: [64]u8 = undefined;
    const late_topic = try std.fmt.bufPrint(
        &late_topic_buf,
        "devices/alice/{d:0>4}/state",
        .{rule_count - 1},
    );
    const missing_topic = "devices/bob/0000/state";

    var late = try sampling.run(
        allocator,
        io,
        .{
            .iterations = iterations,
            .samples = 5,
            .warmup = 1,
        },
        Context{
            .acl = &acl,
            .identity = identity,
            .topic = late_topic,
            .iterations = iterations,
        },
        allowWork,
    );
    defer late.deinit(allocator);

    var missing = try sampling.run(
        allocator,
        io,
        .{
            .iterations = iterations,
            .samples = 5,
            .warmup = 1,
        },
        Context{
            .acl = &acl,
            .identity = identity,
            .topic = missing_topic,
            .iterations = iterations,
        },
        allowWork,
    );
    defer missing.deinit(allocator);

    std.debug.print(
        \\MQTT ACL authorization benchmark
        \\  io backend: zio-std-io
        \\  rules: {d}
        \\  iterations: {d}
        \\  late-match: {d} ns/op
        \\  no-match:   {d} ns/op
        \\  checksum: {d}
        \\
    , .{
        rule_count,
        iterations,
        sampling.nsPerOp(late, iterations),
        sampling.nsPerOp(missing, iterations),
        late.last_result +% missing.last_result,
    });
    sampling.printDistribution("late-match", late);
    sampling.printDistribution("no-match", missing);
}

fn allowWork(
    context: Context,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var count: u64 = 0;
    for (0..context.iterations) |_| {
        count += @intFromBool(context.acl.allows(
            .read,
            context.identity,
            context.topic,
        ));
    }
    return count;
}
