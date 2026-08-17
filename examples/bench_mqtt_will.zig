const std = @import("std");
const netz = @import("netz");

const will_count: usize = 4096;
const cycles: usize = 50;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    var scheduler = netz.mqtt.will_scheduler.Scheduler.init(
        allocator,
        .{ .max_wills = will_count },
    );
    defer scheduler.deinit();

    var client_buffer: [32]u8 = undefined;
    var property = [_]netz.mqtt.Property{
        .{ .four_byte = .{
            .id = .will_delay_interval,
            .value = 30,
        } },
    };
    const message = netz.mqtt.LastWill{
        .topic = "status/worker",
        .payload = "offline",
        .qos = .at_least_once,
        .properties = &property,
    };
    var handles: [will_count]netz.mqtt.will_scheduler.Handle = undefined;

    const io = init.io;
    var checksum: u64 = 0;
    var set_ns: u64 = 0;
    var schedule_ns: u64 = 0;
    var poll_ns: u64 = 0;
    for (0..cycles) |cycle| {
        var started = nowNs(io);
        for (&handles, 0..) |*handle, index| {
            const client_id = try std.fmt.bufPrint(
                &client_buffer,
                "worker-{d}",
                .{index},
            );
            handle.* = try scheduler.set(client_id, message, 60);
        }
        set_ns += nowNs(io) -| started;

        started = nowNs(io);
        for (handles) |handle| {
            _ = try scheduler.close(
                handle,
                .ungraceful,
                .zero,
            );
        }
        schedule_ns += nowNs(io) -| started;

        var due: [will_count]netz.mqtt.will_scheduler.Handle = undefined;
        started = nowNs(io);
        const ready = try scheduler.pollDue(
            std.Io.Timestamp.fromNanoseconds(30 * std.time.ns_per_s),
            &due,
        );
        for (ready) |handle| {
            checksum +%= (try scheduler.view(handle)).payload.len;
            try scheduler.releaseDue(handle);
        }
        poll_ns += nowNs(io) -| started;
        checksum +%= cycle;
    }

    const operations = will_count * cycles;
    std.debug.print(
        \\MQTT Will Delay scheduler benchmark
        \\  wills/cycle: {d}
        \\  cycles: {d}
        \\  set ns/op: {d}
        \\  schedule ns/op: {d}
        \\  poll+release ns/op: {d}
        \\  checksum: {d}
        \\
    , .{
        will_count,
        cycles,
        set_ns / operations,
        schedule_ns / operations,
        poll_ns / operations,
        checksum,
    });
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
