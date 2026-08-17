const std = @import("std");
const netz = @import("netz");

const retained_count: usize = 4096;
const warmup_iterations: usize = 2000;
const iterations: usize = 100_000;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    var store = netz.mqtt.retained.Store.init(allocator, .{
        .max_messages = retained_count,
    });
    defer store.deinit();
    const now = std.Io.Timestamp.zero;

    var topic_buffer: [64]u8 = undefined;
    var payload: [64]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index *% 19);
    for (0..retained_count) |index| {
        const topic = try std.fmt.bufPrint(
            &topic_buffer,
            "devices/{d}/state",
            .{index},
        );
        _ = try store.applyPublish(topic, &payload, .{
            .retain = true,
            .qos = .at_least_once,
            .now = now,
        });
    }

    var exact_storage: [1]netz.mqtt.retained.Match = undefined;
    var wildcard_storage: [retained_count]netz.mqtt.retained.Match = undefined;
    var checksum: u64 = 0;
    for (0..warmup_iterations) |index| {
        const device = index % retained_count;
        const topic = try std.fmt.bufPrint(
            &topic_buffer,
            "devices/{d}/state",
            .{device},
        );
        const matches = try store.matchInto(topic, now, &exact_storage);
        checksum +%= matches[0].payload[0];
    }

    const io = init.io;
    const exact_started = nowNs(io);
    for (0..iterations) |index| {
        const device = index % retained_count;
        const topic = try std.fmt.bufPrint(
            &topic_buffer,
            "devices/{d}/state",
            .{device},
        );
        const matches = try store.matchInto(topic, now, &exact_storage);
        checksum +%= matches[0].payload[device % payload.len];
    }
    const exact_elapsed = nowNs(io) -| exact_started;

    const wildcard_started = nowNs(io);
    const wildcard_iterations: usize = 200;
    for (0..wildcard_iterations) |_| {
        const matches = try store.matchInto(
            "devices/+/state",
            now,
            &wildcard_storage,
        );
        checksum +%= matches.len;
    }
    const wildcard_elapsed = nowNs(io) -| wildcard_started;

    std.debug.print(
        \\MQTT retained store benchmark
        \\  retained messages: {d}
        \\  exact lookup ns/op: {d}
        \\  wildcard full-scan ns/op: {d}
        \\  wildcard matches/op: {d}
        \\  checksum: {d}
        \\
    , .{
        retained_count,
        exact_elapsed / iterations,
        wildcard_elapsed / wildcard_iterations,
        retained_count,
        checksum,
    });
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
