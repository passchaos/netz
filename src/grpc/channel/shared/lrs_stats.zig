//! Per-cluster call counters for xDS Load Reporting Service.
const std = @import("std");
const orca = @import("../../orca.zig");
const selection = @import("lrs_stats_selection.zig");
const key_lookup = @import("lrs_stats_key.zig");
pub const Selection = selection.Selection;
pub const Identity = selection.Identity;
pub const max_clusters: usize = 4096;
pub const max_categories: usize = 256;
pub const max_endpoints: usize = 4096;

pub const CategoryCount = struct { category: []const u8, count: u64 = 0 };

pub const EndpointEntry = struct {
    host: []const u8,
    port: u16,
    ipv6: bool,
    issued: u64 = 0,
    successful: u64 = 0,
    error_requests: u64 = 0,
    in_progress: u64 = 0,
};

pub const Utilization = struct { sum: f64 = 0, count: u64 = 0 };
pub const NamedMetric = struct { name: []const u8, sum: f64 = 0, count: u64 = 0 };

pub const Entry = struct {
    cluster: []const u8,
    service_name: []const u8 = "",
    issued: u64 = 0,
    successful: u64 = 0,
    error_requests: u64 = 0,
    dropped: u64 = 0,
    in_progress: u64 = 0,
    cpu_utilization: Utilization = .{},
    memory_utilization: Utilization = .{},
    application_utilization: Utilization = .{},
    load_metrics: []const NamedMetric = &.{},
    categories: []CategoryCount = &.{},
    endpoints: []EndpointEntry = &.{},
};

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    entries: []Entry,
    categories: []CategoryCount,
    endpoints: []EndpointEntry,
    metrics: []NamedMetric = &.{},
    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.metrics);
        self.allocator.free(self.endpoints);
        self.allocator.free(self.categories);
        self.allocator.free(self.entries);
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

pub fn stripCluster(name: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, name, "cluster:") and name.len > "cluster:".len) name["cluster:".len..] else name;
}

pub fn endpointAddress(endpoint: anytype) ?std.Io.net.IpAddress {
    return switch (endpoint) {
        .cleartext_ip => |value| value.address,
        .tls_address => |value| value.address,
        else => null,
    };
}

pub fn clusterName(endpoint: anytype) ?[]const u8 {
    for (endpoint.hierarchicalPath()) |part| {
        if (std.mem.startsWith(u8, part, "cluster:") and part.len > "cluster:".len) return part["cluster:".len..];
    }
    return null;
}

const EndpointCounter = struct {
    key: []u8,
    host: []const u8,
    port: u16,
    ipv6: bool,
    issued: u64 = 0,
    successful: u64 = 0,
    error_requests: u64 = 0,
    in_progress: u64 = 0,
    reported_issued: u64 = 0,
    reported_successful: u64 = 0,
    reported_error_requests: u64 = 0,
};

const CategoryCounter = struct { count: u64 = 0, reported: u64 = 0 };

const Accum = struct {
    sum: f64 = 0,
    count: u64 = 0,
    reported_sum: f64 = 0,
    reported_count: u64 = 0,
};

const Counter = struct {
    cluster: []const u8,
    service_name: []const u8 = "",
    leases: std.atomic.Value(usize) = .init(0),
    issued: u64 = 0,
    successful: u64 = 0,
    error_requests: u64 = 0,
    dropped: u64 = 0,
    in_progress: u64 = 0,
    cpu_utilization: Accum = .{},
    memory_utilization: Accum = .{},
    application_utilization: Accum = .{},
    named_metrics: std.StringHashMapUnmanaged(Accum) = .empty,
    reported_issued: u64 = 0,
    reported_successful: u64 = 0,
    reported_error_requests: u64 = 0,
    reported_dropped: u64 = 0,
    dropped_categories: std.StringHashMapUnmanaged(CategoryCounter) = .empty,
    endpoints: std.StringHashMapUnmanaged(EndpointCounter) = .empty,

    fn deinit(self: *Counter, gpa: std.mem.Allocator) void {
        var metric_iterator = self.named_metrics.iterator();
        while (metric_iterator.next()) |entry| gpa.free(entry.key_ptr.*);
        self.named_metrics.deinit(gpa);
        var iterator = self.dropped_categories.iterator();
        while (iterator.next()) |entry| gpa.free(entry.key_ptr.*);
        self.dropped_categories.deinit(gpa);
        var endpoint_iterator = self.endpoints.iterator();
        while (endpoint_iterator.next()) |entry| gpa.free(entry.key_ptr.*);
        self.endpoints.deinit(gpa);
    }
};

pub const Propagation = selection.Propagation;

/// A physical call keeps its admitted identity and propagation through completion.
/// Counter storage belongs to Stats; the owning Job/StreamCall retains its State.
pub const Registration = struct {
    counter: *Counter,
    selection: ?*Selection,
    propagation: ?Propagation,

    pub fn release(self: Registration) void {
        if (self.selection) |value| value.release();
        std.debug.assert(self.counter.leases.fetchSub(1, .acq_rel) != 0);
    }
};

pub const Stats = struct {
    /// Null in test-only State literals; real channels set it during init.
    allocator: ?std.mem.Allocator = null,
    mutex: std.Io.Mutex = .init,
    map: std.StringHashMapUnmanaged(*Counter) = .empty,
    /// Null preserves standalone collection; an empty selection disables new calls.
    selection: ?*Selection = null,
    propagation: std.StringHashMapUnmanaged(StoredPropagation) = .empty,

    const StoredPropagation = struct {
        cpu_utilization: bool,
        memory_utilization: bool,
        application_utilization: bool,
        named_metrics_all: bool,
        named_metrics: []const []const u8,
    };

    const Update = enum { issued_success, issued_error, started, aborted, issued, success, error_request, dropped };

    pub fn retainSelection(self: *Stats, io: std.Io) ?*Selection {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return if (self.selection) |value| value.retain() else null;
    }

    /// Transfer ownership without allocation at the channel commit boundary.
    pub fn swapSelection(self: *Stats, io: std.Io, value: ?*Selection) ?*Selection {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const previous = self.selection;
        self.selection = value;
        return previous;
    }

    fn entryLocked(self: *Stats, cluster: []const u8, service_name: []const u8) ?*Counter {
        const gpa = self.allocator orelse return null;
        if (cluster.len == 0) return null;
        if (self.selection) |selected| if (selected.find(cluster, service_name) == null) return null;
        if (self.map.getAdapted(key_lookup.Borrowed{ .cluster = cluster, .service_name = service_name }, key_lookup.Adapted{})) |value| return value;
        if (self.map.count() >= max_clusters) return null;
        // A length prefix makes the cluster/EDS pair unambiguous, including NULs.
        const text_len = std.math.add(usize, cluster.len, service_name.len) catch return null;
        const key_len = std.math.add(usize, 8, text_len) catch return null;
        const key = gpa.alloc(u8, key_len) catch return null;
        std.mem.writeInt(u64, key[0..8], @intCast(cluster.len), .little);
        @memcpy(key[8..][0..cluster.len], cluster);
        @memcpy(key[8 + cluster.len ..], service_name);
        const value = gpa.create(Counter) catch {
            gpa.free(key);
            return null;
        };
        value.* = .{ .cluster = key[8..][0..cluster.len], .service_name = key[8 + cluster.len ..] };
        self.map.put(gpa, key, value) catch {
            gpa.destroy(value);
            gpa.free(key);
            return null;
        };
        return value;
    }

    fn apply(value: anytype, kind: Update) void {
        switch (kind) {
            .issued_success => {
                value.issued +%= 1;
                value.successful +%= 1;
            },
            .issued_error => {
                value.issued +%= 1;
                value.error_requests +%= 1;
            },
            .started => {
                value.issued +%= 1;
                value.in_progress +%= 1;
            },
            .aborted => {
                value.issued -|= 1;
                value.in_progress -|= 1;
            },
            .issued => value.issued +%= 1,
            .success => {
                value.successful +%= 1;
                value.in_progress -|= 1;
            },
            .error_request => {
                value.error_requests +%= 1;
                value.in_progress -|= 1;
            },
            .dropped => {
                if (comptime @hasField(@TypeOf(value.*), "dropped")) value.dropped +%= 1;
            },
        }
    }
    fn endpointUpdate(self: *Stats, counter: *Counter, address: std.Io.net.IpAddress, kind: Update) void {
        const gpa = self.allocator orelse return;
        var buffer: [128]u8 = undefined;
        const borrowed = std.fmt.bufPrint(&buffer, "{f}", .{address}) catch return;
        if (counter.endpoints.getPtr(borrowed)) |value| {
            apply(value, kind);
            return;
        }
        const key = gpa.dupe(u8, borrowed) catch return;
        const gop = counter.endpoints.getOrPut(gpa, key) catch {
            gpa.free(key);
            return;
        };
        if (!gop.found_existing) {
            const ipv6 = address == .ip6;
            const host = if (ipv6)
                key[1..std.mem.indexOfScalar(u8, key, ']').?]
            else
                key[0..std.mem.lastIndexOfScalar(u8, key, ':').?];
            gop.key_ptr.* = key;
            gop.value_ptr.* = .{ .key = key, .host = host, .port = address.getPort(), .ipv6 = ipv6 };
        } else gpa.free(key);
        apply(gop.value_ptr, kind);
    }
    fn update(self: *Stats, io: std.Io, cluster: []const u8, service_name: []const u8, kind: Update) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const value = self.entryLocked(cluster, service_name) orelse return;
        apply(value, kind);
    }

    pub fn record(self: *Stats, io: std.Io, cluster: []const u8, service_name: []const u8, success: bool) void {
        self.update(io, cluster, service_name, if (success) .issued_success else .issued_error);
    }
    pub fn recordIssued(self: *Stats, io: std.Io, cluster: []const u8, service_name: []const u8) void {
        self.update(io, cluster, service_name, .issued);
    }
    fn captureLocked(self: *Stats, cluster: []const u8, service_name: []const u8) ?Registration {
        const value = self.entryLocked(cluster, service_name) orelse return null;
        _ = value.leases.fetchAdd(1, .monotonic);
        const selected = self.selection;
        return .{ .counter = value, .selection = if (selected) |owner| owner.retain() else null, .propagation = if (selected) |owner| owner.find(cluster, service_name).?.propagation else null };
    }

    /// Pin admission before HEADERS without publishing issued/in-progress counts.
    /// Failed opening releases this capture; a successful opening calls start once.
    pub fn capture(self: *Stats, io: std.Io, cluster: []const u8, service_name: []const u8) ?Registration {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.captureLocked(cluster, service_name);
    }

    pub fn start(self: *Stats, io: std.Io, registration: Registration, endpoint: ?std.Io.net.IpAddress) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        apply(registration.counter, .started);
        if (endpoint) |address| self.endpointUpdate(registration.counter, address, .started);
    }

    /// Standalone convenience: capture and start accounting in one locked step.
    pub fn begin(self: *Stats, io: std.Io, cluster: []const u8, service_name: []const u8, endpoint: ?std.Io.net.IpAddress) ?Registration {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const registration = self.captureLocked(cluster, service_name) orelse return null;
        apply(registration.counter, .started);
        if (endpoint) |address| self.endpointUpdate(registration.counter, address, .started);
        return registration;
    }
    pub fn complete(self: *Stats, io: std.Io, registration: Registration, endpoint: ?std.Io.net.IpAddress, success: bool) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const kind: Update = if (success) .success else .error_request;
        apply(registration.counter, kind);
        if (endpoint) |address| self.endpointUpdate(registration.counter, address, kind);
    }
    pub fn recordStarted(self: *Stats, io: std.Io, cluster: []const u8, service_name: []const u8, endpoint: ?std.Io.net.IpAddress) void {
        if (self.begin(io, cluster, service_name, endpoint)) |registration| registration.release();
    }
    pub fn recordAborted(self: *Stats, io: std.Io, cluster: []const u8, service_name: []const u8, endpoint: ?std.Io.net.IpAddress) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const value = self.entryLocked(cluster, service_name) orelse return;
        apply(value, .aborted);
        if (endpoint) |address| self.endpointUpdate(value, address, .aborted);
    }
    pub fn recordCompletion(self: *Stats, io: std.Io, cluster: []const u8, service_name: []const u8, endpoint: ?std.Io.net.IpAddress, success: bool) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const value = self.entryLocked(cluster, service_name) orelse return;
        const kind: Update = if (success) .success else .error_request;
        apply(value, kind);
        if (endpoint) |address| self.endpointUpdate(value, address, kind);
    }
    pub fn recordDropped(self: *Stats, io: std.Io, cluster: []const u8, service_name: []const u8, category: []const u8) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const value = self.entryLocked(cluster, service_name) orelse return;
        value.dropped +%= 1;
        if (category.len == 0) return;
        const gpa = self.allocator orelse return;
        if (value.dropped_categories.count() >= max_categories) {
            if (value.dropped_categories.get(category) == null) return;
        }
        const gop = value.dropped_categories.getOrPut(gpa, category) catch return;
        if (!gop.found_existing) {
            const owned = gpa.dupe(u8, category) catch {
                _ = value.dropped_categories.remove(category);
                return;
            };
            gop.key_ptr.* = owned;
            gop.value_ptr.* = .{};
        }
        gop.value_ptr.count +%= 1;
    }

    pub fn recordOrca(self: *Stats, io: std.Io, cluster: []const u8, report: orca.LoadReport) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const propagation = self.propagation.get(cluster) orelse return;
        var iterator = self.map.iterator();
        const value = while (iterator.next()) |entry| {
            const counter = entry.value_ptr.*;
            if (!std.mem.eql(u8, counter.cluster, cluster)) continue;
            if (self.selection) |selected| if (selected.find(cluster, counter.service_name) == null) continue;
            break counter;
        } else self.entryLocked(cluster, "") orelse return;
        self.metricsLocked(value, propagation, report);
    }

    pub fn recordRegisteredOrca(self: *Stats, io: std.Io, registration: Registration, report: orca.LoadReport) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const propagation = registration.propagation orelse blk: {
            const stored = self.propagation.get(registration.counter.cluster) orelse return;
            break :blk Propagation{ .cpu_utilization = stored.cpu_utilization, .memory_utilization = stored.memory_utilization, .application_utilization = stored.application_utilization, .named_metrics_all = stored.named_metrics_all, .named_metrics = stored.named_metrics };
        };
        self.metricsLocked(registration.counter, propagation, report);
    }

    fn metricsLocked(self: *Stats, value: *Counter, propagation: anytype, report: orca.LoadReport) void {
        if (propagation.cpu_utilization) accumulate(&value.cpu_utilization, report.cpu_utilization);
        if (propagation.memory_utilization) accumulate(&value.memory_utilization, report.memory_utilization);
        if (propagation.application_utilization) accumulate(&value.application_utilization, report.application_utilization);
        const gpa = self.allocator orelse return;
        for (report.named_metrics) |metric| {
            if (metric.value == 0 or metric.name.len == 0) continue;
            if (!propagation.named_metrics_all) {
                var selected = false;
                for (propagation.named_metrics) |name| if (std.mem.eql(u8, name, metric.name)) {
                    selected = true;
                    break;
                };
                if (!selected) continue;
            }
            const gop = value.named_metrics.getOrPut(gpa, metric.name) catch return;
            if (!gop.found_existing) {
                const owned = gpa.dupe(u8, metric.name) catch {
                    _ = value.named_metrics.remove(metric.name);
                    return;
                };
                gop.key_ptr.* = owned;
                gop.value_ptr.* = .{};
            }
            accumulate(gop.value_ptr, metric.value);
        }
    }

    pub fn setPropagation(self: *Stats, io: std.Io, cluster: []const u8, propagation: Propagation) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const gpa = self.allocator orelse return;
        if (self.propagation.fetchRemove(cluster)) |removed| {
            for (removed.value.named_metrics) |name| gpa.free(name);
            gpa.free(removed.value.named_metrics);
            gpa.free(removed.key);
        }
        if (cluster.len == 0) return;
        if (!propagation.cpu_utilization and !propagation.memory_utilization and !propagation.application_utilization and !propagation.named_metrics_all and propagation.named_metrics.len == 0) return;
        const key = gpa.dupe(u8, cluster) catch return;
        errdefer gpa.free(key);
        const names = gpa.alloc([]const u8, propagation.named_metrics.len) catch {
            gpa.free(key);
            return;
        };
        var initialized: usize = 0;
        errdefer {
            for (names[0..initialized]) |name| gpa.free(name);
            gpa.free(names);
        }
        for (propagation.named_metrics, names) |name, *copy| {
            copy.* = gpa.dupe(u8, name) catch {
                for (names[0..initialized]) |value| gpa.free(value);
                gpa.free(names);
                gpa.free(key);
                return;
            };
            initialized += 1;
        }
        const gop = self.propagation.getOrPut(gpa, key) catch {
            for (names) |name| gpa.free(name);
            gpa.free(names);
            gpa.free(key);
            return;
        };
        gop.key_ptr.* = key;
        gop.value_ptr.* = .{
            .cpu_utilization = propagation.cpu_utilization,
            .memory_utilization = propagation.memory_utilization,
            .application_utilization = propagation.application_utilization,
            .named_metrics_all = propagation.named_metrics_all,
            .named_metrics = names,
        };
    }

    fn accumulate(value: *Accum, sample: f64) void {
        if (sample == 0) return;
        value.sum += sample;
        value.count +%= 1;
    }

    fn takeSnapshot(self: *Stats, gpa: std.mem.Allocator, io: std.Io, comptime delta: bool) std.mem.Allocator.Error!Snapshot {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (delta) self.pruneReportedLocked();
        return @import("lrs_stats_snapshot.zig").takeLocked(self, gpa, delta);
    }

    /// Retired identities stay reportable through their last admitted call and
    /// final delta. Reclaim them only after a snapshot consumed that delta.
    fn pruneReportedLocked(self: *Stats) void {
        const selected = self.selection orelse return;
        const gpa = self.allocator orelse return;
        while (true) {
            var iterator = self.map.iterator();
            const removed = while (iterator.next()) |entry| {
                const value = entry.value_ptr.*;
                if (selected.find(value.cluster, value.service_name) != null or value.leases.load(.acquire) != 0 or value.in_progress != 0) continue;
                if (value.issued > value.reported_issued or value.successful > value.reported_successful or value.error_requests > value.reported_error_requests or value.dropped > value.reported_dropped) continue;
                if (value.cpu_utilization.count > value.cpu_utilization.reported_count or value.memory_utilization.count > value.memory_utilization.reported_count or value.application_utilization.count > value.application_utilization.reported_count) continue;
                var metrics = value.named_metrics.iterator();
                const pending = while (metrics.next()) |metric| {
                    if (metric.value_ptr.count > metric.value_ptr.reported_count) break true;
                } else false;
                if (pending) continue;
                break self.map.fetchRemove(entry.key_ptr.*).?;
            } else return;
            removed.value.deinit(gpa);
            gpa.destroy(removed.value);
            gpa.free(removed.key);
        }
    }

    /// Cumulative counters since channel creation.
    pub fn snapshot(self: *Stats, gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!Snapshot {
        return self.takeSnapshot(gpa, io, false);
    }

    /// Counters since the previous delta snapshot. `in_progress` remains a
    /// current gauge. This matches the LRS reporting interval contract.
    pub fn snapshotDelta(self: *Stats, gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!Snapshot {
        return self.takeSnapshot(gpa, io, true);
    }

    pub fn deinit(self: *Stats) void {
        if (self.selection) |value| value.release();
        const gpa = self.allocator orelse return;
        var iterator = self.map.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit(gpa);
            gpa.destroy(entry.value_ptr.*);
            gpa.free(entry.key_ptr.*);
        }
        self.map.deinit(gpa);
        var propagation_iterator = self.propagation.iterator();
        while (propagation_iterator.next()) |entry| {
            for (entry.value_ptr.named_metrics) |name| gpa.free(name);
            gpa.free(entry.value_ptr.named_metrics);
            gpa.free(entry.key_ptr.*);
        }
        self.propagation.deinit(gpa);
        self.* = undefined;
    }
};
