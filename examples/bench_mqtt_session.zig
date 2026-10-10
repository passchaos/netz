const std = @import("std");
const netz = @import("netz");
const CountingAllocator = @import("support/counting_allocator.zig")
    .CountingAllocator;

const session_count: usize = 4096;
const resume_iterations: usize = 100_000;
const queued_per_session: usize = 4;
const fanout_sessions: usize = 64;
const fanout_messages: usize = 256;
const fanout_samples: usize = 7;
const full_window_inflight: usize = 16_384;
const full_window_iterations: usize = 20_000;
const full_window_samples: usize = 7;
const inflight_churn_iterations: usize = 20_000;
const inflight_churn_samples: usize = 7;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    var backend = try netz.runtime.Backend.init(init.gpa);
    defer backend.deinit();
    const io = backend.io();
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

    var independent_fanout_ns: [fanout_samples]u64 = undefined;
    var shared_fanout_ns: [fanout_samples]u64 = undefined;
    var independent_fanout: ?FanoutResult = null;
    var shared_fanout: ?FanoutResult = null;
    for (0..fanout_samples) |sample| {
        const independent_first = sample % 4 == 0 or sample % 4 == 3;
        if (independent_first) {
            const independent = try benchmarkOfflineFanout(io, false);
            const shared = try benchmarkOfflineFanout(io, true);
            try recordFanoutResult(
                &independent_fanout,
                &independent_fanout_ns,
                sample,
                independent,
            );
            try recordFanoutResult(
                &shared_fanout,
                &shared_fanout_ns,
                sample,
                shared,
            );
        } else {
            const shared = try benchmarkOfflineFanout(io, true);
            const independent = try benchmarkOfflineFanout(io, false);
            try recordFanoutResult(
                &shared_fanout,
                &shared_fanout_ns,
                sample,
                shared,
            );
            try recordFanoutResult(
                &independent_fanout,
                &independent_fanout_ns,
                sample,
                independent,
            );
        }
    }
    std.mem.sort(u64, &independent_fanout_ns, {}, lessThanU64);
    std.mem.sort(u64, &shared_fanout_ns, {}, lessThanU64);

    const full_window = try benchmarkFullWindowDrain(io);
    checksum +%= full_window.checksum;
    const inflight_churn = try benchmarkInflightSlotChurn(io);
    checksum +%= inflight_churn.checksum;

    std.debug.print(
        \\MQTT persistent session benchmark
        \\  io backend: zio-std-io
        \\  sessions: {d}
        \\  resume ns/op: {d}
        \\  offline queue ns/message: {d}
        \\  reconnect drain ns/session: {d}
        \\  queued messages/session: {d}
        \\  offline fanout sessions: {d}
        \\  offline fanout messages: {d}
        \\  offline fanout samples: {d}
        \\  independent fanout ns/target: {d}
        \\  shared fanout ns/target: {d}
        \\  independent fanout allocations: {d}
        \\  shared fanout allocations: {d}
        \\  independent fanout live bytes: {d}
        \\  shared fanout live bytes: {d}
        \\  full-window inflight: {d}
        \\  full-window empty-drain iterations/sample: {d}
        \\  full-window empty-drain samples: {d}
        \\  full-window empty-drain median ns/op: {d}
        \\  tail-slot churn iterations/sample: {d}
        \\  tail-slot churn samples: {d}
        \\  tail-slot churn median ns/op: {d}
        \\  checksum: {d}
        \\
    , .{
        session_count,
        resume_elapsed / resume_iterations,
        queue_elapsed / (session_count * queued_per_session),
        drain_elapsed / session_count,
        queued_per_session,
        fanout_sessions,
        fanout_messages,
        fanout_samples,
        independent_fanout_ns[fanout_samples / 2],
        shared_fanout_ns[fanout_samples / 2],
        independent_fanout.?.allocations,
        shared_fanout.?.allocations,
        independent_fanout.?.live_bytes,
        shared_fanout.?.live_bytes,
        full_window_inflight,
        full_window_iterations,
        full_window_samples,
        full_window.median_ns,
        inflight_churn_iterations,
        inflight_churn_samples,
        inflight_churn.median_ns,
        checksum,
    });
}

const FanoutResult = struct {
    elapsed_ns: u64,
    deliveries: usize,
    allocations: usize,
    live_bytes: usize,
};

const FullWindowResult = struct {
    median_ns: u64,
    checksum: u64,
};

const InflightChurnResult = struct {
    median_ns: u64,
    checksum: u64,
};

fn benchmarkFullWindowDrain(io: std.Io) !FullWindowResult {
    const allocator = std.heap.smp_allocator;
    var store = netz.mqtt.session.Store.init(allocator, .{
        .max_sessions = 1,
        .max_queued_per_session = full_window_inflight,
        .max_inflight_per_session = full_window_inflight,
    });
    defer store.deinit();
    const opened = try store.open("full-window", false, 3_600, .zero);
    for (0..full_window_inflight) |_| {
        _ = try store.enqueuePublish(
            opened.handle,
            "bench/full-window",
            "payload",
            .{ .qos = .at_least_once, .now = .zero },
        );
    }

    const initial = try allocator.alloc(
        netz.mqtt.session.Transmission,
        full_window_inflight,
    );
    defer allocator.free(initial);
    const drained = try store.drainInto(
        opened.handle,
        .zero,
        @intCast(full_window_inflight),
        initial,
    );
    if (drained.len != full_window_inflight) {
        return error.InvalidBenchmarkState;
    }

    var probe: [1]netz.mqtt.session.Transmission = undefined;
    var checksum: u64 = 0;
    for (0..100) |_| {
        const empty = try store.drainInto(
            opened.handle,
            .zero,
            @intCast(full_window_inflight),
            &probe,
        );
        checksum +%= empty.len;
    }

    var samples: [full_window_samples]u64 = undefined;
    for (&samples) |*sample| {
        const started = nowNs(io);
        for (0..full_window_iterations) |_| {
            std.mem.doNotOptimizeAway(&store);
            const empty = try store.drainInto(
                opened.handle,
                .zero,
                @intCast(full_window_inflight),
                &probe,
            );
            std.mem.doNotOptimizeAway(empty.len);
            checksum +%= empty.len;
        }
        sample.* = (nowNs(io) -| started) / full_window_iterations;
    }
    std.mem.doNotOptimizeAway(checksum);
    std.mem.sort(u64, &samples, {}, lessThanU64);
    return .{
        .median_ns = samples[full_window_samples / 2],
        .checksum = checksum,
    };
}

fn benchmarkInflightSlotChurn(io: std.Io) !InflightChurnResult {
    const allocator = std.heap.smp_allocator;
    var store = netz.mqtt.session.Store.init(allocator, .{
        .max_sessions = 1,
        .max_queued_per_session = full_window_inflight,
        .max_inflight_per_session = full_window_inflight,
    });
    defer store.deinit();
    const opened = try store.open("inflight-churn", false, 3_600, .zero);
    for (0..full_window_inflight) |_| {
        _ = try store.enqueuePublish(
            opened.handle,
            "bench/inflight-churn",
            "payload",
            .{ .qos = .at_least_once, .now = .zero },
        );
    }

    const initial = try allocator.alloc(
        netz.mqtt.session.Transmission,
        full_window_inflight,
    );
    defer allocator.free(initial);
    const drained = try store.drainInto(
        opened.handle,
        .zero,
        @intCast(full_window_inflight),
        initial,
    );
    if (drained.len != full_window_inflight) {
        return error.InvalidBenchmarkState;
    }
    var packet_id = drained[drained.len - 1].publish.packet_id;
    var checksum: u64 = packet_id;
    var samples: [inflight_churn_samples]u64 = undefined;
    for (&samples) |*sample| {
        const started = nowNs(io);
        for (0..inflight_churn_iterations) |_| {
            std.mem.doNotOptimizeAway(&store);
            if (try store.handleAck(
                opened.handle,
                .puback,
                packet_id,
                0,
            ) != .completed) return error.InvalidBenchmarkState;
            const replacement = try store.beginImmediatePublish(
                opened.handle,
                "bench/inflight-churn",
                "payload",
                .{ .qos = .at_least_once, .now = .zero },
                @intCast(full_window_inflight),
            );
            packet_id = replacement.packet_id;
            checksum +%= packet_id;
            std.mem.doNotOptimizeAway(packet_id);
        }
        sample.* = (nowNs(io) -| started) / inflight_churn_iterations;
    }
    std.mem.doNotOptimizeAway(checksum);
    std.mem.sort(u64, &samples, {}, lessThanU64);
    return .{
        .median_ns = samples[inflight_churn_samples / 2],
        .checksum = checksum,
    };
}

fn recordFanoutResult(
    expected: *?FanoutResult,
    samples: []u64,
    index: usize,
    result: FanoutResult,
) !void {
    if (expected.*) |first| {
        if (result.deliveries != first.deliveries or
            result.allocations != first.allocations or
            result.live_bytes != first.live_bytes)
        {
            return error.InvalidBenchmarkState;
        }
    } else {
        expected.* = result;
    }
    samples[index] = result.elapsed_ns / result.deliveries;
}

fn benchmarkOfflineFanout(io: std.Io, shared_wire: bool) !FanoutResult {
    var counting = CountingAllocator.init(std.heap.smp_allocator);
    const allocator = counting.allocator();
    const result = result: {
        var store = netz.mqtt.session.Store.init(allocator, .{
            .max_sessions = fanout_sessions,
            .max_queued_per_session = fanout_messages,
        });
        defer store.deinit();
        var handles: [fanout_sessions]netz.mqtt.session.Handle = undefined;
        for (&handles, 0..) |*handle, index| {
            var client_id: [32]u8 = undefined;
            handle.* = (try store.open(
                try std.fmt.bufPrint(&client_id, "fanout-{d}", .{index}),
                false,
                3_600,
                .zero,
            )).handle;
            try store.disconnect(handle.*, null, .zero);
        }
        const before = counting.snapshot();
        var payload: [256]u8 = undefined;
        for (&payload, 0..) |*byte, index| {
            byte.* = @truncate(index *% 17 +% 3);
        }
        const publish: netz.mqtt.Publish = .{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = "bench/offline/fanout",
            .packet_id = 1,
            .properties = &.{},
            .payload = &payload,
        };
        const started = nowNs(io);
        for (0..fanout_messages) |_| {
            if (shared_wire) {
                const publication = try netz.mqtt.session.SharedPublication
                    .createFromPublish(allocator, publish, 1, .zero);
                defer publication.release();
                for (handles) |handle| {
                    var changed = false;
                    _ = try store
                        .enqueueSharedPublicationTrackingSnapshotChange(
                        handle,
                        publication,
                        .{ .qos = publish.qos, .now = .zero },
                        &changed,
                    );
                    if (!changed) return error.InvalidBenchmarkState;
                }
            } else {
                for (handles) |handle| {
                    _ = try store.enqueuePublish(
                        handle,
                        publish.topic,
                        publish.payload,
                        .{ .qos = publish.qos, .now = .zero },
                    );
                }
            }
        }
        const elapsed_ns = nowNs(io) -| started;
        const after = counting.snapshot();
        const deliveries = fanout_sessions * fanout_messages;
        const stats = store.aggregateStats();
        if (stats.queued_count != deliveries) {
            return error.InvalidBenchmarkState;
        }
        break :result FanoutResult{
            .elapsed_ns = elapsed_ns,
            .deliveries = deliveries,
            .allocations = after.alloc_count - before.alloc_count,
            .live_bytes = after.current_bytes - before.current_bytes,
        };
    };
    if (counting.snapshot().current_bytes != 0) {
        return error.BenchmarkMemoryLeak;
    }
    return result;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

fn lessThanU64(_: void, a: u64, b: u64) bool {
    return a < b;
}
