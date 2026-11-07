//! Own a counter image before advancing any LRS interval baselines.
const std = @import("std");
const stats = @import("lrs_stats.zig");
const Entry = stats.Entry;
const CategoryCount = stats.CategoryCount;
const EndpointEntry = stats.EndpointEntry;
const NamedMetric = stats.NamedMetric;

fn utilization(value: anytype, delta: bool) stats.Utilization {
    if (!delta) return .{ .sum = value.sum, .count = value.count };
    return .{ .sum = value.sum - value.reported_sum, .count = value.count -| value.reported_count };
}

fn markReported(value: anytype) void {
    value.reported_sum = value.sum;
    value.reported_count = value.count;
}

pub fn takeLocked(self: anytype, gpa: std.mem.Allocator, comptime delta: bool, source_key: ?[]const u8) std.mem.Allocator.Error!stats.Snapshot {
    var storage_bytes: usize = 0;
    var entry_count: usize = 0;
    var category_count: usize = 0;
    var endpoint_count: usize = 0;
    var metric_count: usize = 0;
    var iterator = self.map.iterator();
    while (iterator.next()) |entry| {
        if (source_key) |key| if (!std.mem.eql(u8, key, entry.value_ptr.*.source_key)) continue;
        entry_count += 1;
        storage_bytes += entry.value_ptr.*.source_key.len + entry.value_ptr.*.cluster.len + entry.value_ptr.*.service_name.len;
        category_count += entry.value_ptr.*.dropped_categories.count();
        endpoint_count += entry.value_ptr.*.endpoints.count();
        metric_count += entry.value_ptr.*.named_metrics.count();
        var categories = entry.value_ptr.*.dropped_categories.iterator();
        while (categories.next()) |category| storage_bytes += category.key_ptr.*.len;
        var endpoints = entry.value_ptr.*.endpoints.iterator();
        while (endpoints.next()) |endpoint| storage_bytes += endpoint.value_ptr.host.len;
        var metrics = entry.value_ptr.*.named_metrics.iterator();
        while (metrics.next()) |metric| storage_bytes += metric.key_ptr.*.len;
    }
    const entries = try gpa.alloc(Entry, entry_count);
    errdefer gpa.free(entries);
    const categories = try gpa.alloc(CategoryCount, category_count);
    errdefer gpa.free(categories);
    const endpoints = try gpa.alloc(EndpointEntry, endpoint_count);
    errdefer gpa.free(endpoints);
    const metrics = try gpa.alloc(NamedMetric, metric_count);
    errdefer gpa.free(metrics);
    const storage = try gpa.alloc(u8, storage_bytes);
    errdefer gpa.free(storage);
    var offset: usize = 0;
    var index: usize = 0;
    var category_index: usize = 0;
    var endpoint_index: usize = 0;
    var metric_index: usize = 0;
    iterator = self.map.iterator();
    while (iterator.next()) |entry| {
        if (source_key) |key| if (!std.mem.eql(u8, key, entry.value_ptr.*.source_key)) continue;
        const source = entry.value_ptr.*.source_key;
        const source_copy = storage[offset..][0..source.len];
        @memcpy(source_copy, source);
        offset += source.len;
        const name = entry.value_ptr.*.cluster;
        const copy = storage[offset..][0..name.len];
        @memcpy(copy, name);
        offset += name.len;
        const service_name = entry.value_ptr.*.service_name;
        const service_copy = storage[offset..][0..service_name.len];
        @memcpy(service_copy, service_name);
        offset += service_name.len;
        const category_start = category_index;
        var category_iterator = entry.value_ptr.*.dropped_categories.iterator();
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
        var endpoint_iterator = entry.value_ptr.*.endpoints.iterator();
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
        const metric_start = metric_index;
        var metric_iterator = entry.value_ptr.*.named_metrics.iterator();
        while (metric_iterator.next()) |metric| {
            const metric_name = metric.key_ptr.*;
            const metric_copy = storage[offset..][0..metric_name.len];
            @memcpy(metric_copy, metric_name);
            offset += metric_name.len;
            const output = utilization(metric.value_ptr.*, delta);
            metrics[metric_index] = .{ .name = metric_copy, .sum = output.sum, .count = output.count };
            if (delta) markReported(metric.value_ptr);
            metric_index += 1;
        }
        const issued = if (delta) entry.value_ptr.*.issued -| entry.value_ptr.*.reported_issued else entry.value_ptr.*.issued;
        const successful = if (delta) entry.value_ptr.*.successful -| entry.value_ptr.*.reported_successful else entry.value_ptr.*.successful;
        const error_requests = if (delta) entry.value_ptr.*.error_requests -| entry.value_ptr.*.reported_error_requests else entry.value_ptr.*.error_requests;
        const dropped = if (delta) entry.value_ptr.*.dropped -| entry.value_ptr.*.reported_dropped else entry.value_ptr.*.dropped;
        const cpu = utilization(entry.value_ptr.*.cpu_utilization, delta);
        const memory = utilization(entry.value_ptr.*.memory_utilization, delta);
        const application = utilization(entry.value_ptr.*.application_utilization, delta);
        entries[index] = .{
            .cluster = copy,
            .service_name = service_copy,
            .source_key = source_copy,
            .issued = issued,
            .successful = successful,
            .error_requests = error_requests,
            .dropped = dropped,
            .in_progress = entry.value_ptr.*.in_progress,
            .cpu_utilization = cpu,
            .memory_utilization = memory,
            .application_utilization = application,
            .load_metrics = metrics[metric_start..][0 .. metric_index - metric_start],
            .categories = categories[category_start..][0 .. category_index - category_start],
            .endpoints = endpoints[endpoint_start..][0 .. endpoint_index - endpoint_start],
        };
        if (delta) {
            entry.value_ptr.*.reported_issued = entry.value_ptr.*.issued;
            entry.value_ptr.*.reported_successful = entry.value_ptr.*.successful;
            entry.value_ptr.*.reported_error_requests = entry.value_ptr.*.error_requests;
            entry.value_ptr.*.reported_dropped = entry.value_ptr.*.dropped;
            markReported(&entry.value_ptr.*.cpu_utilization);
            markReported(&entry.value_ptr.*.memory_utilization);
            markReported(&entry.value_ptr.*.application_utilization);
        }
        index += 1;
    }
    return .{ .allocator = gpa, .storage = storage, .entries = entries, .categories = categories, .endpoints = endpoints, .metrics = metrics };
}
