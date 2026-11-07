//! Per-cluster call counters for xDS Load Reporting Service.
const std = @import("std");
const orca = @import("../../orca.zig");
const selection = @import("lrs_stats_selection.zig");
const key_lookup = @import("lrs_stats_key.zig");
pub const Selection = selection.Selection;
pub const Identity = selection.Identity;
const MetricName = struct { prefix: []const u8, name: []const u8 };
const MetricContext = struct {
    pub fn hash(_: MetricContext, key: MetricName) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(key.prefix);
        hasher.update(key.name);
        return hasher.final();
    }
    pub fn eql(_: MetricContext, key: MetricName, stored: []const u8) bool {
        return std.mem.startsWith(u8, stored, key.prefix) and std.mem.eql(u8, stored[key.prefix.len..], key.name);
    }
};
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
/// Reported LRS names: CDS propagation adds named_metrics.; manual names stay raw.
pub const NamedMetric = struct { name: []const u8, sum: f64 = 0, count: u64 = 0 };

pub const Entry = struct {
    cluster: []const u8,
    service_name: []const u8 = "",
    source_key: []const u8 = "",
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

/// Keep the generated manager key intact for admission/service lookup.
pub fn clusterKey(endpoint: anytype) ?[]const u8 {
    for (endpoint.hierarchicalPath()) |part| {
        if (std.mem.startsWith(u8, part, "cluster:") and part.len > "cluster:".len) return part;
    }
    return null;
}

pub fn clusterName(endpoint: anytype) ?[]const u8 {
    return if (clusterKey(endpoint)) |key| stripCluster(key) else null;
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
    source_key: []const u8 = "",
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

    fn hasUnreported(self: *Counter) bool {
        if (self.issued > self.reported_issued or self.successful > self.reported_successful or self.error_requests > self.reported_error_requests or self.dropped > self.reported_dropped) return true;
        if (self.cpu_utilization.count > self.cpu_utilization.reported_count or self.memory_utilization.count > self.memory_utilization.reported_count or self.application_utilization.count > self.application_utilization.reported_count) return true;
        var metrics = self.named_metrics.iterator();
        while (metrics.next()) |metric| if (metric.value_ptr.count > metric.value_ptr.reported_count) return true;
        return false;
    }

    fn active(self: *Counter) bool {
        return self.leases.load(.acquire) != 0 or self.in_progress != 0 or self.hasUnreported();
    }

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
    /// Null until reporting is enabled, including disabled real channels.
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
        prefix_named_metrics: bool,
    };

    const Update = enum { issued_success, issued_error, started, aborted, issued, success, error_request, dropped };

    /// Enable collection at publication without replacing an existing allocator.
    pub fn enable(self: *Stats, allocator: std.mem.Allocator, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.allocator == null) self.allocator = allocator;
    }

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
        const source_key = if (self.selection) |selected| (selected.find(cluster, service_name) orelse return null).source_key else "";
        const borrowed: key_lookup.Borrowed = .{ .source_key = source_key, .cluster = cluster, .service_name = service_name };
        if (self.map.getAdapted(borrowed, key_lookup.Adapted{})) |value| return value;
        if (self.map.count() >= max_clusters) return null;
        const key = key_lookup.encode(gpa, borrowed) catch return null;
        const value = gpa.create(Counter) catch {
            gpa.free(key);
            return null;
        };
        value.* = .{ .source_key = key[16..][0..source_key.len], .cluster = key[16 + source_key.len ..][0..cluster.len], .service_name = key[16 + source_key.len + cluster.len ..] };
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
            if (self.selection) |selected| {
                const identity = selected.find(cluster, counter.service_name) orelse continue;
                if (!std.mem.eql(u8, identity.source_key, counter.source_key)) continue;
            } else if (counter.source_key.len != 0) continue;
            break counter;
        } else self.entryLocked(cluster, "") orelse return;
        self.metricsLocked(value, propagation, report);
    }

    pub fn recordRegisteredOrca(self: *Stats, io: std.Io, registration: Registration, report: orca.LoadReport) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const propagation = registration.propagation orelse blk: {
            const stored = self.propagation.get(registration.counter.cluster) orelse return;
            break :blk Propagation{ .cpu_utilization = stored.cpu_utilization, .memory_utilization = stored.memory_utilization, .application_utilization = stored.application_utilization, .named_metrics_all = stored.named_metrics_all, .named_metrics = stored.named_metrics, .prefix_named_metrics = stored.prefix_named_metrics };
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
            const prefix: []const u8 = if (propagation.prefix_named_metrics) "named_metrics." else "";
            const lookup: MetricName = .{ .prefix = prefix, .name = metric.name };
            if (value.named_metrics.getPtrAdapted(lookup, MetricContext{})) |existing| {
                accumulate(existing, metric.value);
                continue;
            }
            const length = std.math.add(usize, prefix.len, metric.name.len) catch return;
            const owned = gpa.alloc(u8, length) catch return;
            @memcpy(owned[0..prefix.len], prefix);
            @memcpy(owned[prefix.len..], metric.name);
            value.named_metrics.put(gpa, owned, .{ .sum = metric.value, .count = 1 }) catch {
                gpa.free(owned);
                return;
            };
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
            .prefix_named_metrics = propagation.prefix_named_metrics,
        };
    }

    fn accumulate(value: *Accum, sample: f64) void {
        if (sample == 0) return;
        value.sum += sample;
        value.count +%= 1;
    }

    fn takeSnapshot(self: *Stats, gpa: std.mem.Allocator, io: std.Io, comptime delta: bool, source_key: ?[]const u8) std.mem.Allocator.Error!Snapshot {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (delta) self.pruneReportedLocked();
        return @import("lrs_stats_snapshot.zig").takeLocked(self, gpa, delta, source_key);
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
                if (selected.find(value.cluster, value.service_name)) |identity| if (std.mem.eql(u8, identity.source_key, value.source_key)) continue;
                if (value.active()) continue;
                break self.map.fetchRemove(entry.key_ptr.*).?;
            } else return;
            removed.value.deinit(gpa);
            gpa.destroy(removed.value);
            gpa.free(removed.key);
        }
    }

    /// Cumulative counters since channel creation.
    pub fn snapshot(self: *Stats, gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!Snapshot {
        return self.takeSnapshot(gpa, io, false, null);
    }

    /// Counters since the previous delta snapshot. `in_progress` remains a
    /// current gauge. This matches the LRS reporting interval contract.
    pub fn snapshotDelta(self: *Stats, gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!Snapshot {
        return self.takeSnapshot(gpa, io, true, null);
    }

    /// Advance only this discovery source's interval baselines.
    pub fn snapshotDeltaForSource(self: *Stats, gpa: std.mem.Allocator, io: std.Io, source_key: []const u8) std.mem.Allocator.Error!Snapshot {
        return self.takeSnapshot(gpa, io, true, source_key);
    }

    /// Keep a retired source reportable until all admitted calls and deltas drain.
    pub fn sourceActive(self: *Stats, io: std.Io, source_key: []const u8) bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.selection) |selected| {
            for (selected.identities) |identity| if (std.mem.eql(u8, identity.source_key, source_key)) return true;
        }
        var iterator = self.map.valueIterator();
        while (iterator.next()) |value| if (std.mem.eql(u8, value.*.source_key, source_key) and value.*.active()) return true;
        return false;
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
