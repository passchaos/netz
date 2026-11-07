//! Allocation and delegated file-sync telemetry outside benchmark setup.
const std = @import("std");
const telemetry = @import("../counting_allocator.zig");
const fixture = @import("fixture.zig");
const options = @import("options.zig");

pub const Phase = enum { encode_live, log_append, broker_append_commit };

pub const SyncProbe = struct {
    base: std.Io,
    calls: std.atomic.Value(u64) = .init(0),
    elapsed_ns: std.atomic.Value(u64) = .init(0),
    pub var active: ?*SyncProbe = null;

    /// Delegate the real sync unchanged. Only the benchmark's I/O vtable
    /// installs this hook; no durability operation or return value is altered.
    pub fn sync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
        const self = active.?;
        const start = nowNs(self.base);
        defer {
            _ = self.calls.fetchAdd(1, .monotonic);
            _ = self.elapsed_ns.fetchAdd(nowNs(self.base) -| start, .monotonic);
        }
        return self.base.vtable.fileSync(userdata, file);
    }
};

pub const Measurement = struct {
    elapsed_ns: u64,
    allocations: usize,
    frees: usize,
    resizes: usize,
    remaps: usize,
    allocated_bytes: usize,
    freed_bytes: usize,
    live_before: usize,
    live_after: usize,
    peak_extra_bytes: usize,
    sync_calls: u64,
    sync_elapsed_ns: u64,
};

pub const Marker = struct {
    before: telemetry.Snapshot,
    sync_calls: u64,
    sync_elapsed_ns: u64,
    started_ns: u64,

    pub fn begin(counting: *telemetry.CountingAllocator, probe: *SyncProbe, io: std.Io) Marker {
        // This benchmark has one owner and no running broker workers.
        counting.peak_bytes.store(counting.current_bytes.load(.monotonic), .monotonic);
        return .{
            .before = counting.snapshot(),
            .sync_calls = probe.calls.load(.monotonic),
            .sync_elapsed_ns = probe.elapsed_ns.load(.monotonic),
            .started_ns = nowNs(io),
        };
    }

    pub fn finish(self: Marker, counting: *telemetry.CountingAllocator, probe: *SyncProbe, io: std.Io) Measurement {
        const elapsed_ns = nowNs(io) -| self.started_ns;
        const after = counting.snapshot();
        return .{
            .elapsed_ns = elapsed_ns,
            .allocations = after.alloc_count - self.before.alloc_count,
            .frees = after.free_count - self.before.free_count,
            .resizes = after.resize_count - self.before.resize_count,
            .remaps = after.remap_count - self.before.remap_count,
            .allocated_bytes = after.total_allocated - self.before.total_allocated,
            .freed_bytes = after.total_freed - self.before.total_freed,
            .live_before = self.before.current_bytes,
            .live_after = after.current_bytes,
            .peak_extra_bytes = after.peak_bytes -| self.before.current_bytes,
            .sync_calls = probe.calls.load(.monotonic) - self.sync_calls,
            .sync_elapsed_ns = probe.elapsed_ns.load(.monotonic) - self.sync_elapsed_ns,
        };
    }
};

pub const Result = struct {
    phase: Phase,
    sample: usize,
    order: usize,
    sessions: usize,
    metadata_bytes: usize,
    iterations: usize,
    snapshot_bytes: usize,
    serialized_bytes: usize,
    journal_bytes: usize,
    sequence: u64,
    verified: fixture.Verification,
    fixture_crc32: u32,
    fixture_sha256: [32]u8,
    measured: Measurement,

    /// Called only after the owning case has verified its zero-live-byte
    /// teardown, so every complete record includes that measured invariant.
    pub fn print(self: Result) void {
        const fixture_hash = std.fmt.bytesToHex(self.fixture_sha256, .lower);
        const snapshot_hash = std.fmt.bytesToHex(self.verified.snapshot_sha256, .lower);
        std.debug.print(
            "record=result benchmark=mqtt-commit-log io=zio-std-io phase={s} capture_clock={s} " ++
                "sample={d} order={d} sessions={d} offline_sessions={d} queued_per_session={d} queued_messages={d} " ++
                "payload_bytes={d} metadata_bytes={d} iterations={d} warmup=1 " ++
                "elapsed_ns={d} ns_per_op={d} snapshot_bytes={d} serialized_bytes={d} journal_bytes={d} sequence={d} ",
            .{
                @tagName(self.phase),                                           if (self.phase == .broker_append_commit) "live" else "fixed",
                self.sample,                                                    self.order,
                self.sessions,                                                  self.sessions,
                options.queued_per_session,                                     self.sessions * options.queued_per_session,
                options.payload_bytes,                                          self.metadata_bytes,
                self.iterations,                                                self.measured.elapsed_ns,
                self.measured.elapsed_ns / @as(u64, @intCast(self.iterations)), self.snapshot_bytes,
                self.serialized_bytes,                                          self.journal_bytes,
                self.sequence,
            },
        );
        // Keep each format call below Writer's 32-argument bound. Only this
        // final call terminates the single machine-readable result record.
        std.debug.print(
            "allocations={d} frees={d} resizes={d} remaps={d} allocated_bytes={d} freed_bytes={d} " ++
                "live_before={d} live_after={d} peak_extra_bytes={d} " ++
                "file_sync_calls={d} file_sync_elapsed_ns={d} file_sync_probe=true " ++
                "checksum={d} fixture_crc32={d} fixture_sha256={s} snapshot_crc32={d} snapshot_sha256={s} " ++
                "restored_sessions={d} restored_queued_messages={d} compat_retained=1 compat_wills=1 " ++
                "compat_incoming_qos2=1 compat_bridge_qos2=1 teardown_live_bytes=0 complete=true\n",
            .{
                self.measured.allocations,
                self.measured.frees,
                self.measured.resizes,
                self.measured.remaps,
                self.measured.allocated_bytes,
                self.measured.freed_bytes,
                self.measured.live_before,
                self.measured.live_after,
                self.measured.peak_extra_bytes,
                self.measured.sync_calls,
                self.measured.sync_elapsed_ns,
                self.verified.checksum,
                self.fixture_crc32,
                &fixture_hash,
                self.verified.snapshot_crc32,
                &snapshot_hash,
                self.verified.sessions,
                self.verified.queued_messages,
            },
        );
    }
};

fn nowNs(io: std.Io) u64 {
    return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
}
