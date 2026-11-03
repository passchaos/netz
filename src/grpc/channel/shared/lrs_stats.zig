//! Per-cluster call counters for xDS Load Reporting Service.
const std = @import("std");
const orca = @import("../../orca.zig");
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
    categories: []CategoryCount = &.{},
    endpoints: []EndpointEntry = &.{},
};

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    entries: []Entry,
    categories: []CategoryCount,
    endpoints: []EndpointEntry,
    pub fn deinit(self: *Snapshot) void {
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
    service_name: []const u8 = "",
    issued: u64 = 0,
    successful: u64 = 0,
    error_requests: u64 = 0,
    dropped: u64 = 0,
    in_progress: u64 = 0,
    cpu_utilization: Accum = .{},
    memory_utilization: Accum = .{},
    application_utilization: Accum = .{},
    reported_issued: u64 = 0,
    reported_successful: u64 = 0,
    reported_error_requests: u64 = 0,
    reported_dropped: u64 = 0,
    dropped_categories: std.StringHashMapUnmanaged(CategoryCounter) = .empty,
    endpoints: std.StringHashMapUnmanaged(EndpointCounter) = .empty,

    fn deinit(self: *Counter, gpa: std.mem.Allocator) void {
        if (self.service_name.len != 0) gpa.free(self.service_name);
        var iterator = self.dropped_categories.iterator();
        while (iterator.next()) |entry| gpa.free(entry.key_ptr.*);
        self.dropped_categories.deinit(gpa);
        var endpoint_iterator = self.endpoints.iterator();
        while (endpoint_iterator.next()) |entry| gpa.free(entry.key_ptr.*);
        self.endpoints.deinit(gpa);
    }
};

pub const Stats = struct {
    /// Null in test-only State literals; real channels set it during init.
    allocator: ?std.mem.Allocator = null,
    mutex: std.Io.Mutex = .init,
    map: std.StringHashMapUnmanaged(Counter) = .empty,

    const Update = enum { issued_success, issued_error, started, aborted, issued, success, error_request, dropped };

    fn entryLocked(self: *Stats, cluster: []const u8, service_name: []const u8) ?*Counter {
        const gpa = self.allocator orelse return null;
        if (cluster.len == 0) return null;
        if (self.map.count() >= max_clusters) {
            if (self.map.get(cluster) == null) return null;
        }
        const gop = self.map.getOrPut(gpa, cluster) catch return null;
        if (!gop.found_existing) {
            const owned = gpa.dupe(u8, cluster) catch {
                _ = self.map.remove(cluster);
                return null;
            };
            const owned_service = if (service_name.len == 0) &.{} else gpa.dupe(u8, service_name) catch {
                gpa.free(owned);
                _ = self.map.remove(cluster);
                return null;
            };
            gop.key_ptr.* = owned;
            gop.value_ptr.* = .{ .service_name = owned_service };
        } else if (gop.value_ptr.service_name.len == 0 and service_name.len != 0) {
            gop.value_ptr.service_name = gpa.dupe(u8, service_name) catch return gop.value_ptr;
        }
        return gop.value_ptr;
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
        const key = std.fmt.allocPrint(gpa, "{f}", .{address}) catch return;
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
    pub fn recordStarted(self: *Stats, io: std.Io, cluster: []const u8, service_name: []const u8, endpoint: ?std.Io.net.IpAddress) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const value = self.entryLocked(cluster, service_name) orelse return;
        apply(value, .started);
        if (endpoint) |address| self.endpointUpdate(value, address, .started);
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
        const value = self.entryLocked(cluster, "") orelse return;
        accumulate(&value.cpu_utilization, report.cpu_utilization);
        accumulate(&value.memory_utilization, report.memory_utilization);
        accumulate(&value.application_utilization, report.application_utilization);
    }

    fn accumulate(value: *Accum, sample: f64) void {
        if (sample == 0) return;
        value.sum += sample;
        value.count +%= 1;
    }

    fn utilization(value: Accum, delta: bool) Utilization {
        if (!delta) return .{ .sum = value.sum, .count = value.count };
        return .{ .sum = value.sum - value.reported_sum, .count = value.count -| value.reported_count };
    }

    fn markReported(value: *Accum) void {
        value.reported_sum = value.sum;
        value.reported_count = value.count;
    }

    fn takeSnapshot(self: *Stats, gpa: std.mem.Allocator, io: std.Io, comptime delta: bool) std.mem.Allocator.Error!Snapshot {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        var storage_bytes: usize = 0;
        var category_count: usize = 0;
        var endpoint_count: usize = 0;
        var iterator = self.map.iterator();
        while (iterator.next()) |entry| {
            storage_bytes += entry.key_ptr.*.len + entry.value_ptr.service_name.len;
            category_count += entry.value_ptr.dropped_categories.count();
            endpoint_count += entry.value_ptr.endpoints.count();
            var categories = entry.value_ptr.dropped_categories.iterator();
            while (categories.next()) |category| storage_bytes += category.key_ptr.*.len;
            var endpoints = entry.value_ptr.endpoints.iterator();
            while (endpoints.next()) |endpoint| storage_bytes += endpoint.value_ptr.host.len;
        }
        const entries = try gpa.alloc(Entry, self.map.count());
        errdefer gpa.free(entries);
        const categories = try gpa.alloc(CategoryCount, category_count);
        errdefer gpa.free(categories);
        const endpoints = try gpa.alloc(EndpointEntry, endpoint_count);
        errdefer gpa.free(endpoints);
        const storage = try gpa.alloc(u8, storage_bytes);
        errdefer gpa.free(storage);
        var offset: usize = 0;
        var index: usize = 0;
        var category_index: usize = 0;
        var endpoint_index: usize = 0;
        iterator = self.map.iterator();
        while (iterator.next()) |entry| {
            const name = entry.key_ptr.*;
            const copy = storage[offset..][0..name.len];
            @memcpy(copy, name);
            offset += name.len;
            const service_name = entry.value_ptr.service_name;
            const service_copy = storage[offset..][0..service_name.len];
            @memcpy(service_copy, service_name);
            offset += service_name.len;
            const category_start = category_index;
            var category_iterator = entry.value_ptr.dropped_categories.iterator();
            while (category_iterator.next()) |category| {
                const category_name = category.key_ptr.*;
                const category_copy = storage[offset..][0..category_name.len];
                @memcpy(category_copy, category_name);
                offset += category_name.len;
                const count = if (delta) category.value_ptr.count -| category.value_ptr.reported else category.value_ptr.count;
                categories[category_index] = .{ .category = category_copy, .count = count };
                if (delta) category.value_ptr.reported = category.value_ptr.count;
                category_index += 1;
            }
            const endpoint_start = endpoint_index;
            var endpoint_iterator = entry.value_ptr.endpoints.iterator();
            while (endpoint_iterator.next()) |endpoint| {
                const host = endpoint.value_ptr.host;
                const host_copy = storage[offset..][0..host.len];
                @memcpy(host_copy, host);
                offset += host.len;
                const issued = if (delta) endpoint.value_ptr.issued -| endpoint.value_ptr.reported_issued else endpoint.value_ptr.issued;
                const successful = if (delta) endpoint.value_ptr.successful -| endpoint.value_ptr.reported_successful else endpoint.value_ptr.successful;
                const error_requests = if (delta) endpoint.value_ptr.error_requests -| endpoint.value_ptr.reported_error_requests else endpoint.value_ptr.error_requests;
                endpoints[endpoint_index] = .{
                    .host = host_copy,
                    .port = endpoint.value_ptr.port,
                    .ipv6 = endpoint.value_ptr.ipv6,
                    .issued = issued,
                    .successful = successful,
                    .error_requests = error_requests,
                    .in_progress = endpoint.value_ptr.in_progress,
                };
                if (delta) {
                    endpoint.value_ptr.reported_issued = endpoint.value_ptr.issued;
                    endpoint.value_ptr.reported_successful = endpoint.value_ptr.successful;
                    endpoint.value_ptr.reported_error_requests = endpoint.value_ptr.error_requests;
                }
                endpoint_index += 1;
            }
            const issued = if (delta) entry.value_ptr.issued -| entry.value_ptr.reported_issued else entry.value_ptr.issued;
            const successful = if (delta) entry.value_ptr.successful -| entry.value_ptr.reported_successful else entry.value_ptr.successful;
            const error_requests = if (delta) entry.value_ptr.error_requests -| entry.value_ptr.reported_error_requests else entry.value_ptr.error_requests;
            const dropped = if (delta) entry.value_ptr.dropped -| entry.value_ptr.reported_dropped else entry.value_ptr.dropped;
            const cpu = utilization(entry.value_ptr.cpu_utilization, delta);
            const memory = utilization(entry.value_ptr.memory_utilization, delta);
            const application = utilization(entry.value_ptr.application_utilization, delta);
            entries[index] = .{
                .cluster = copy,
                .service_name = service_copy,
                .issued = issued,
                .successful = successful,
                .error_requests = error_requests,
                .dropped = dropped,
                .in_progress = entry.value_ptr.in_progress,
                .cpu_utilization = cpu,
                .memory_utilization = memory,
                .application_utilization = application,
                .categories = categories[category_start..][0 .. category_index - category_start],
                .endpoints = endpoints[endpoint_start..][0 .. endpoint_index - endpoint_start],
            };
            if (delta) {
                entry.value_ptr.reported_issued = entry.value_ptr.issued;
                entry.value_ptr.reported_successful = entry.value_ptr.successful;
                entry.value_ptr.reported_error_requests = entry.value_ptr.error_requests;
                entry.value_ptr.reported_dropped = entry.value_ptr.dropped;
                markReported(&entry.value_ptr.cpu_utilization);
                markReported(&entry.value_ptr.memory_utilization);
                markReported(&entry.value_ptr.application_utilization);
            }
            index += 1;
        }
        return .{ .allocator = gpa, .storage = storage, .entries = entries, .categories = categories, .endpoints = endpoints };
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
        const gpa = self.allocator orelse return;
        var iterator = self.map.iterator();
        while (iterator.next()) |entry| {
            gpa.free(entry.key_ptr.*);
            entry.value_ptr.deinit(gpa);
        }
        self.map.deinit(gpa);
        self.* = undefined;
    }
};
