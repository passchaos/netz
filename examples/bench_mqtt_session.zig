const std = @import("std");
const netz = @import("netz");

const session_count: usize = 4096;
const resume_iterations: usize = 100_000;
const queued_per_session: usize = 4;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    var store = netz.mqtt.session.Store.init(allocator, .{
        .max_sessions = session_count,
        .max_queued_per_session = queued_per_session,
    });
    defer store.deinit();
    const now = std.Io.Timestamp.zero;

    var client_buffer: [32]u8 = undefined;
    for (0..session_count) |index| {
        const client_id = try std.fmt.bufPrint(
            &client_buffer,
            "client-{d}",
            .{index},
        );
        const opened = try store.open(client_id, false, 3600, now);
        try store.disconnect(opened.handle, null, now);
    }

    const io = init.io;
    var checksum: u64 = 0;
    const resume_started = nowNs(io);
    for (0..resume_iterations) |index| {
        const client_index = index % session_count;
        const client_id = try std.fmt.bufPrint(
            &client_buffer,
            "client-{d}",
            .{client_index},
        );
        const opened = try store.open(client_id, false, 3600, now);
        checksum +%= @intFromBool(opened.session_present);
        try store.disconnect(opened.handle, null, now);
    }
    const resume_elapsed = nowNs(io) -| resume_started;

    const queue_started = nowNs(io);
    for (0..session_count) |session_index| {
        const client_id = try std.fmt.bufPrint(
            &client_buffer,
            "client-{d}",
            .{session_index},
        );
        const opened = try store.open(client_id, false, 3600, now);
        for (0..queued_per_session) |message_index| {
            const topic = try std.fmt.bufPrint(
                &client_buffer,
                "jobs/{d}/{d}",
                .{ session_index, message_index },
            );
            _ = try store.enqueuePublish(opened.handle, topic, "payload", .{
                .qos = .at_least_once,
                .now = now,
            });
        }
        try store.disconnect(opened.handle, null, now);
    }
    const queue_elapsed = nowNs(io) -| queue_started;

    var transmissions: [queued_per_session]netz.mqtt.session.Transmission =
        undefined;
    const drain_started = nowNs(io);
    for (0..session_count) |index| {
        const client_id = try std.fmt.bufPrint(
            &client_buffer,
            "client-{d}",
            .{index},
        );
        const opened = try store.open(client_id, false, 3600, now);
        const drained = try store.drainInto(
            opened.handle,
            now,
            queued_per_session,
            &transmissions,
        );
        checksum +%= drained.len;
    }
    const drain_elapsed = nowNs(io) -| drain_started;

    std.debug.print(
        \\MQTT persistent session benchmark
        \\  sessions: {d}
        \\  resume ns/op: {d}
        \\  offline queue ns/message: {d}
        \\  reconnect drain ns/session: {d}
        \\  queued messages/session: {d}
        \\  checksum: {d}
        \\
    , .{
        session_count,
        resume_elapsed / resume_iterations,
        queue_elapsed / (session_count * queued_per_session),
        drain_elapsed / session_count,
        queued_per_session,
        checksum,
    });
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
