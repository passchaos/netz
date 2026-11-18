//! Full-state serialization and unchanged durable MQTT journal append costs.
const std = @import("std");
const netz = @import("netz");
const CountingAllocator = @import("support").counting_allocator.CountingAllocator;
const options = @import("support").mqtt_commit_log_bench.options;
const fixture_mod = @import("support").mqtt_commit_log_bench.fixture;
const metrics = @import("support").mqtt_commit_log_bench.metrics;
const Log = netz.mqtt.persistence.commit_log.Log;

pub fn main(init: std.process.Init) !void {
    const config = try options.parse(init);
    if (config.help) {
        std.debug.print("{s}", .{options.help_text});
        return;
    }
    var backend = try netz.runtime.Backend.init(init.gpa);
    defer backend.deinit();
    const base = backend.io();
    var probe = metrics.SyncProbe{ .base = base };
    metrics.SyncProbe.active = &probe;
    defer metrics.SyncProbe.active = null;
    var table = base.vtable.*;
    table.fileSync = metrics.SyncProbe.sync;
    const io = std.Io{ .userdata = base.userdata, .vtable = &table };
    var work = try options.WorkDirectory.create(init.gpa, io, config.directory);
    defer work.deinit();
    std.debug.print(
        "record=config benchmark=mqtt-commit-log io=zio-std-io iterations={d} samples={d} " ++
            "session_cases=1,32,256 queued_per_session={d} payload_bytes={d} metadata_bytes={d} " ++
            "warmup=1 order=rotating fixed_monotonic_ns={d} fixed_realtime_ns={d} " ++
            "durability=production-fsync sync_probe=true allocation_scope=broker-and-persistence " ++
            "snapshot_export={any} complete=true\n",
        .{ config.iterations, config.samples, options.queued_per_session, options.payload_bytes, config.metadata_bytes, fixture_mod.monotonic.nanoseconds, fixture_mod.realtime.nanoseconds, config.snapshot_output != null },
    );
    var result_count: usize = 0;
    for (options.session_counts) |session_count| {
        result_count += try runCase(io, work.dir, &probe, config, session_count);
    }
    try work.cleanup();
    std.debug.print("record=complete benchmark=mqtt-commit-log cases={d} results={d} owned_directory_removed=true teardown_live_bytes=0 complete=true\n", .{ options.session_counts.len, result_count });
}

fn runCase(io: std.Io, dir: std.Io.Dir, probe: *metrics.SyncProbe, config: options.Config, session_count: usize) !usize {
    var counting = CountingAllocator.init(std.heap.smp_allocator);
    const allocator = counting.allocator();
    var results: [options.max_samples * 3]metrics.Result = undefined;
    var result_count: usize = 0;
    {
        var fixture = try fixture_mod.Fixture.init(allocator, io, session_count, config.metadata_bytes);
        defer fixture.deinit();
        const encoded = try fixture.capture();
        defer allocator.free(encoded);
        const baseline = try fixture.validate(encoded, false);
        if (session_count == 1) if (config.snapshot_output) |path| {
            // Export is caller-selected and intentionally survives cleanup of
            // this run's temporary journal directory. Never overwrite a file.
            var file = try std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true });
            defer file.close(io);
            try file.writeStreamingAll(io, encoded);
            try file.sync(io);
        };
        const phases = [_]metrics.Phase{ .encode_live, .log_append, .broker_append_commit };
        for (0..config.samples) |sample| {
            for (0..phases.len) |order| {
                const phase = phases[(sample + order) % phases.len];
                results[result_count] = try measure(phase, sample, order, &fixture, encoded, baseline, dir, &counting, probe, config);
                result_count += 1;
            }
        }
    }
    const teardown = counting.snapshot();
    if (teardown.current_bytes != 0 or teardown.total_allocated != teardown.total_freed) return error.BenchmarkAllocationLeak;
    // Validation, teardown, and printing are outside every timed region.
    for (results[0..result_count]) |result| result.print();
    return result_count;
}

fn measure(phase: metrics.Phase, sample: usize, order: usize, fixture: *fixture_mod.Fixture, encoded: []const u8, baseline: fixture_mod.Verification, dir: std.Io.Dir, counting: *CountingAllocator, probe: *metrics.SyncProbe, config: options.Config) !metrics.Result {
    const io = fixture.broker.io;
    const total_encoded_bytes = try std.math.mul(usize, encoded.len, config.iterations);
    var result = metrics.Result{
        .phase = phase,
        .sample = sample,
        .order = order,
        .sessions = fixture.session_count,
        .metadata_bytes = config.metadata_bytes,
        .iterations = config.iterations,
        .snapshot_bytes = encoded.len,
        .serialized_bytes = 0,
        .journal_bytes = 0,
        .sequence = 0,
        .verified = undefined,
        .fixture_crc32 = baseline.snapshot_crc32,
        .fixture_sha256 = baseline.snapshot_sha256,
        .measured = undefined,
    };
    switch (phase) {
        .encode_live => {
            const warm = try fixture.capture();
            fixture.allocator.free(warm);
            const marker = metrics.Marker.begin(counting, probe, io);
            for (0..config.iterations) |_| {
                const payload = try fixture.capture();
                fixture.allocator.free(payload);
            }
            result.measured = marker.finish(counting, probe, io);
            result.serialized_bytes = total_encoded_bytes;
            const final = try fixture.capture();
            defer fixture.allocator.free(final);
            if (!std.mem.eql(u8, final, encoded)) return error.UnstableFixedSnapshot;
            result.verified = try fixture.validate(final, false);
        },
        .log_append => {
            var path_buffer: [64]u8 = undefined;
            const path = try std.fmt.bufPrint(&path_buffer, "append-{d}.log", .{fixture.session_count});
            var log = try Log.createWithInitial(fixture.allocator, io, dir, path, .{}, encoded);
            defer log.deinit();
            const initial_len = log.valid_len;
            if (try log.append(encoded) != 2) return error.UnexpectedCommitSequence;
            const record_bytes = log.valid_len - initial_len;
            try requireHistoryRoom(&log, record_bytes, config.iterations);
            const before_len = log.valid_len;
            const marker = metrics.Marker.begin(counting, probe, io);
            for (0..config.iterations) |_| result.sequence = try log.append(encoded);
            result.measured = marker.finish(counting, probe, io);
            result.journal_bytes = log.valid_len - before_len;
            try validateMeasuredLog(&log, result, record_bytes);
            result.verified = try recover(fixture, dir, path, log.next_sequence, log.valid_len, encoded, false);
        },
        .broker_append_commit => {
            var path_buffer: [64]u8 = undefined;
            const path = try std.fmt.bufPrint(&path_buffer, "broker-{d}.log", .{fixture.session_count});
            if (fixture.broker.commit_log == null) {
                try fixture.broker.createCommitLog(dir, path, .{});
            } else {
                try fixture.broker.compactCommitLog();
            }
            const log = &fixture.broker.commit_log.?;
            const initial_len = log.valid_len;
            if (try fixture.broker.appendCommit() != 2) return error.UnexpectedCommitSequence;
            const record_bytes = log.valid_len - initial_len;
            try requireHistoryRoom(log, record_bytes, config.iterations);
            const before_len = log.valid_len;
            const marker = metrics.Marker.begin(counting, probe, io);
            for (0..config.iterations) |_| result.sequence = try fixture.broker.appendCommit();
            result.measured = marker.finish(counting, probe, io);
            result.serialized_bytes = total_encoded_bytes;
            result.journal_bytes = log.valid_len - before_len;
            try validateMeasuredLog(log, result, record_bytes);
            result.verified = try recover(fixture, dir, path, log.next_sequence, log.valid_len, null, true);
        },
    }
    if (result.verified.snapshot_bytes != result.snapshot_bytes) return error.BenchmarkSnapshotSizeChanged;
    if (result.measured.live_before != result.measured.live_after) return error.BenchmarkSteadyStateAllocationLeak;
    const expected_syncs: u64 = if (phase == .encode_live) 0 else @intCast(config.iterations);
    if (result.measured.sync_calls != expected_syncs) return error.BenchmarkSyncCountMismatch;
    return result;
}

fn requireHistoryRoom(log: *const Log, record_bytes: usize, iterations: usize) !void {
    const required = try std.math.mul(usize, record_bytes, iterations);
    // A compaction would measure a different operation. Refuse an oversized
    // sample before timing rather than changing the production journal bound.
    if (required > log.options.max_file_bytes -| log.valid_len) return error.BenchmarkHistoryLimitExceeded;
}

fn validateMeasuredLog(log: *const Log, result: metrics.Result, record_bytes: usize) !void {
    if (result.sequence != result.iterations + 2 or log.next_sequence != result.iterations + 3 or
        result.journal_bytes != try std.math.mul(usize, record_bytes, result.iterations)) return error.UnexpectedCommitSequence;
}

fn recover(fixture: *fixture_mod.Fixture, dir: std.Io.Dir, path: []const u8, next_sequence: u64, valid_len: usize, expected: ?[]const u8, live_timestamps: bool) !fixture_mod.Verification {
    var reopened = try Log.open(fixture.allocator, fixture.broker.io, dir, path, .{});
    defer reopened.deinit();
    if (reopened.next_sequence != next_sequence or reopened.valid_len != valid_len) return error.RestoredCommitLogMismatch;
    const latest = try reopened.latestAlloc();
    defer fixture.allocator.free(latest);
    if (expected) |payload| if (!std.mem.eql(u8, latest, payload)) return error.RestoredCommitLogMismatch;
    return fixture.validate(latest, live_timestamps);
}
