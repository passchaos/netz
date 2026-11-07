//! Caller-driven periodic Load Reporting Service reporter.
const std = @import("std");
const channel = @import("../../channel/shared.zig");
const codec = @import("codec.zig");
const integration = @import("integration.zig");
const Client = @import("client.zig").Client;
pub const Error = @import("client.zig").Error || std.mem.Allocator.Error;

pub const Options = struct {
    interval_ns: u64 = std.time.ns_per_s,
    locality: codec.Locality = .{},
    /// Automatic runners own this immutable discovery-source key.
    source_key: ?[]const u8 = null,
};

/// `source` and `client` are borrowed; keep both alive for the reporter's
/// lifetime. The source channel must have `enable_lrs_stats` enabled.
pub const Reporter = struct {
    allocator: std.mem.Allocator,
    client: *Client,
    source: channel.SharedChannel,
    locality: codec.Locality,
    interval_ns: u64,
    source_key: ?[]const u8,
    endpoint_granularity: bool = false,
    last_report_ns: ?i96 = null,
    /// True when the previous report contained only zero counters. A second
    /// consecutive all-zero interval is skipped, matching grpc-core LRS.
    last_report_zero: bool = false,
    filter_storage: []u8 = &.{},
    filter_names: [][]const u8 = &.{},
    /// Null reports all clusters; a non-null slice is the server's requested set.
    filter: ?[]const []const u8 = null,

    pub fn init(allocator: std.mem.Allocator, client: *Client, source: channel.SharedChannel, options: Options) Reporter {
        return .{
            .allocator = allocator,
            .client = client,
            .source = source,
            .locality = options.locality,
            .source_key = options.source_key,
            .interval_ns = @max(options.interval_ns, std.time.ns_per_ms),
            .last_report_ns = std.Io.Clock.Timestamp.now(client.sender.state.io, .awake).raw.nanoseconds,
        };
    }
    pub fn deinit(self: *Reporter) void {
        self.clearFilter();
        self.* = undefined;
    }
    /// Apply a server response. `send_all_clusters` clears the filter; otherwise
    /// the exact requested cluster set is retained. A malformed zero interval
    /// falls back to 1 ms.
    pub fn onResponse(self: *Reporter, response: codec.Response) Error!void {
        if (response.interval_ns) |nanoseconds| self.interval_ns = @max(nanoseconds, std.time.ns_per_ms);
        self.endpoint_granularity = response.report_endpoint_granularity;
        if (response.send_all_clusters and self.client.supportsSendAllClusters()) {
            self.clearFilter();
            return;
        }
        var storage_bytes: usize = 0;
        for (response.clusters) |name| storage_bytes += name.len;
        const storage = try self.allocator.alloc(u8, storage_bytes);
        errdefer self.allocator.free(storage);
        const names = try self.allocator.alloc([]const u8, response.clusters.len);
        errdefer self.allocator.free(names);
        var offset: usize = 0;
        for (response.clusters, names) |name, *copy| {
            const value = storage[offset..][0..name.len];
            @memcpy(value, name);
            offset += name.len;
            copy.* = value;
        }
        self.clearFilter();
        self.filter_storage = storage;
        self.filter_names = names;
        self.filter = names;
    }
    fn clearFilter(self: *Reporter) void {
        self.allocator.free(self.filter_names);
        self.allocator.free(self.filter_storage);
        self.filter_names = &.{};
        self.filter_storage = &.{};
        self.filter = null;
    }
    pub fn nextDeadline(self: *Reporter) std.Io.Clock.Timestamp {
        const io = self.client.sender.state.io;
        if (self.last_report_ns) |last| {
            return .{ .clock = .awake, .raw = .{ .nanoseconds = last + @as(i96, @intCast(self.interval_ns)) } };
        }
        return std.Io.Clock.Timestamp.now(io, .awake);
    }
    fn reportNow(self: *Reporter, deadline: std.Io.Clock.Timestamp) Error!bool {
        const io = self.client.sender.state.io;
        const now = std.Io.Clock.Timestamp.now(io, .awake);
        const elapsed_ns: u64 = if (self.last_report_ns) |last| blk: {
            const elapsed = now.raw.nanoseconds - last;
            break :blk if (elapsed > 0) @intCast(elapsed) else 0;
        } else self.interval_ns;
        var snapshot = if (self.source_key) |key|
            try self.source.state.lrs_stats.snapshotDeltaForSource(self.allocator, io, key)
        else
            try self.source.lrsStatsDeltaSnapshot(self.allocator);
        defer snapshot.deinit();
        const zero = snapshotIsZero(&snapshot, self.filter);
        if (zero and self.last_report_zero) {
            self.last_report_ns = now.raw.nanoseconds;
            return false;
        }
        var reports = try integration.buildWithOptions(self.allocator, &snapshot, self.locality, elapsed_ns, self.filter, self.endpoint_granularity);
        defer reports.deinit();
        try self.client.reportWithDeadline(reports.clusters, deadline);
        self.last_report_ns = now.raw.nanoseconds;
        self.last_report_zero = zero;
        return true;
    }
    pub fn reportWithDeadline(self: *Reporter, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try self.reportNow(deadline);
    }
    pub fn reportWithTimeout(self: *Reporter, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.reportWithDeadline(.fromNow(self.client.sender.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    /// Report only when the previous successful report is at least one interval
    /// old. Returns true when a report was written.
    pub fn reportIfDueWithDeadline(self: *Reporter, deadline: std.Io.Clock.Timestamp) Error!bool {
        const now = std.Io.Clock.Timestamp.now(self.client.sender.state.io, .awake).raw.nanoseconds;
        if (self.last_report_ns) |last| {
            if (now < last + @as(i96, @intCast(self.interval_ns))) return false;
        }
        return self.reportNow(deadline);
    }
    pub fn reportIfDueWithTimeout(self: *Reporter, timeout: std.Io.Duration) Error!bool {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.reportIfDueWithDeadline(.fromNow(self.client.sender.state.io, .{ .clock = .awake, .raw = timeout }));
    }
};

fn selected(entry: anytype, filter: ?[]const []const u8) bool {
    const names = filter orelse return true;
    for (names) |name| if (std.mem.eql(u8, name, entry.cluster)) return true;
    return false;
}

fn snapshotIsZero(snapshot: *const channel.LrsStatsSnapshot, filter: ?[]const []const u8) bool {
    for (snapshot.entries) |entry| {
        if (!selected(entry, filter)) continue;
        if (entry.issued != 0 or entry.successful != 0 or entry.error_requests != 0 or entry.dropped != 0 or entry.in_progress != 0) return false;
        for (entry.categories) |category| if (category.count != 0) return false;
        for (entry.endpoints) |endpoint| {
            if (endpoint.issued != 0 or endpoint.successful != 0 or endpoint.error_requests != 0 or endpoint.in_progress != 0) return false;
        }
    }
    return true;
}
