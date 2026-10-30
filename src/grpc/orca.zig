//! Open Request Cost Aggregation (ORCA) per-RPC backend load reports.
//!
//! Servers carry one `xds.data.orca.v3.OrcaLoadReport` protobuf in the
//! `endpoint-load-metrics-bin` trailing metadata field. Payloads are encoded
//! directly so the transport does not require generated protobuf bindings.
const std = @import("std");
const http2 = @import("../http2/mod.zig");
const metadata = @import("metadata.zig");
const protobuf = @import("protobuf.zig");

pub const name = "endpoint-load-metrics-bin";
pub const Error = metadata.Error || protobuf.Error || error{
    DuplicateLoadReport,
    InvalidLoadReport,
};

pub const Metric = struct {
    name: []const u8,
    value: f64,
};

/// `xds.data.orca.v3.OrcaLoadReport` using protobuf's ordinary default-value
/// semantics. A missing metadata field remains distinct from a present report
/// whose scalar values are all zero.
pub const LoadReport = struct {
    cpu_utilization: f64 = 0,
    memory_utilization: f64 = 0,
    /// Deprecated integer RPS field retained for wire compatibility.
    rps: u64 = 0,
    request_cost: []const Metric = &.{},
    utilization: []const Metric = &.{},
    rps_fractional: f64 = 0,
    eps: f64 = 0,
    named_metrics: []const Metric = &.{},
    application_utilization: f64 = 0,
};

/// Owns the decoded protobuf image and metric-index arrays. Metric names in
/// `report` borrow from `bytes` and remain valid until `deinit`.
pub const OwnedLoadReport = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    request_cost: []Metric,
    utilization: []Metric,
    named_metrics: []Metric,
    report: LoadReport,

    pub fn deinit(self: *OwnedLoadReport) void {
        self.allocator.free(self.named_metrics);
        self.allocator.free(self.utilization);
        self.allocator.free(self.request_cost);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn clone(
        self: OwnedLoadReport,
        allocator: std.mem.Allocator,
    ) Error!OwnedLoadReport {
        return decodeAlloc(allocator, self.bytes);
    }
};

/// Encode a canonical ORCA report. Proto3 default scalar values are omitted;
/// map entries retain the caller's order while duplicate keys are rejected.
pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    report: LoadReport,
) Error![]u8 {
    try validate(report);
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    if (report.cpu_utilization != 0) {
        try appendDouble(&output, allocator, 1, report.cpu_utilization);
    }
    if (report.memory_utilization != 0) {
        try appendDouble(&output, allocator, 2, report.memory_utilization);
    }
    if (report.rps != 0) try appendVarint(&output, allocator, 3, report.rps);
    try appendMap(&output, allocator, 4, report.request_cost);
    try appendMap(&output, allocator, 5, report.utilization);
    if (report.rps_fractional != 0) {
        try appendDouble(&output, allocator, 6, report.rps_fractional);
    }
    if (report.eps != 0) {
        try appendDouble(&output, allocator, 7, report.eps);
    }
    try appendMap(&output, allocator, 8, report.named_metrics);
    if (report.application_utilization != 0) {
        try appendDouble(
            &output,
            allocator,
            9,
            report.application_utilization,
        );
    }
    return output.toOwnedSlice(allocator);
}

/// Decode and own one raw ORCA protobuf value. Unknown fields are skipped for
/// forward compatibility; repeated scalars and map keys follow protobuf's
/// last-value-wins rule.
pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error!OwnedLoadReport {
    const owned = try allocator.dupe(u8, bytes);
    errdefer allocator.free(owned);
    return parseOwned(allocator, owned);
}

/// Decode the single per-RPC report from response metadata. A normal response
/// carries it in trailers; a trailers-only HTTP/2 response may expose the same
/// field in its terminal header block. Repeated or comma-combined values are
/// rejected because ORCA metadata is non-repeatable.
pub fn fromMetadataAlloc(
    allocator: std.mem.Allocator,
    headers: []const http2.Hpack.HeaderField,
    trailers: []const http2.Hpack.HeaderField,
) Error!?OwnedLoadReport {
    var header_count: usize = 0;
    var trailer_count: usize = 0;
    for (headers) |field| if (std.mem.eql(u8, field.name, name)) {
        header_count += 1;
    };
    for (trailers) |field| if (std.mem.eql(u8, field.name, name)) {
        trailer_count += 1;
    };
    const count = std.math.add(usize, header_count, trailer_count) catch
        return error.InvalidLoadReport;
    if (count == 0) return null;
    if (count != 1) return error.DuplicateLoadReport;
    if (header_count != 0 and trailers.len != 0) {
        return error.InvalidLoadReport;
    }
    const fields = if (trailer_count != 0) trailers else headers;
    const size = try metadata.decodedFieldsUpperBound(fields, name);
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var values = try metadata.ValueIterator.init(fields, name, bytes);
    const first = (try values.next()) orelse return error.InvalidLoadReport;
    if (try values.next() != null) return error.DuplicateLoadReport;
    if (first.value.len != bytes.len) return error.InvalidLoadReport;
    return try parseOwned(allocator, bytes);
}

pub fn validate(report: LoadReport) Error!void {
    if (!validNonnegative(report.cpu_utilization) or
        !validFraction(report.memory_utilization) or
        !validNonnegative(report.rps_fractional) or
        !validNonnegative(report.eps) or
        !validNonnegative(report.application_utilization))
    {
        return error.InvalidLoadReport;
    }
    try validateMetrics(report.request_cost, false);
    try validateMetrics(report.utilization, true);
    try validateMetrics(report.named_metrics, false);
}

fn parseOwned(
    allocator: std.mem.Allocator,
    bytes: []u8,
) Error!OwnedLoadReport {
    var request_cost_list: std.ArrayList(Metric) = .empty;
    defer request_cost_list.deinit(allocator);
    var utilization_list: std.ArrayList(Metric) = .empty;
    defer utilization_list.deinit(allocator);
    var named_metrics_list: std.ArrayList(Metric) = .empty;
    defer named_metrics_list.deinit(allocator);

    var report: LoadReport = .{};
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 1) {
            report.cpu_utilization = @bitCast(try reader.fixed64());
        } else if (field.number == 2 and field.wire_type == 1) {
            report.memory_utilization = @bitCast(try reader.fixed64());
        } else if (field.number == 3 and field.wire_type == 0) {
            report.rps = try reader.varint();
        } else if (field.number == 4 and field.wire_type == 2) {
            const metric = try parseMetric(try reader.bytesValue());
            try putMetric(&request_cost_list, allocator, metric);
        } else if (field.number == 5 and field.wire_type == 2) {
            const metric = try parseMetric(try reader.bytesValue());
            try putMetric(&utilization_list, allocator, metric);
        } else if (field.number == 6 and field.wire_type == 1) {
            report.rps_fractional = @bitCast(try reader.fixed64());
        } else if (field.number == 7 and field.wire_type == 1) {
            report.eps = @bitCast(try reader.fixed64());
        } else if (field.number == 8 and field.wire_type == 2) {
            const metric = try parseMetric(try reader.bytesValue());
            try putMetric(&named_metrics_list, allocator, metric);
        } else if (field.number == 9 and field.wire_type == 1) {
            report.application_utilization = @bitCast(try reader.fixed64());
        } else try reader.skip(field);
    }

    const request_cost = try request_cost_list.toOwnedSlice(allocator);
    errdefer allocator.free(request_cost);
    const utilization = try utilization_list.toOwnedSlice(allocator);
    errdefer allocator.free(utilization);
    const named_metrics = try named_metrics_list.toOwnedSlice(allocator);
    errdefer allocator.free(named_metrics);
    report.request_cost = request_cost;
    report.utilization = utilization;
    report.named_metrics = named_metrics;
    try validate(report);
    return .{
        .allocator = allocator,
        .bytes = bytes,
        .request_cost = request_cost,
        .utilization = utilization,
        .named_metrics = named_metrics,
        .report = report,
    };
}

fn parseMetric(bytes: []const u8) Error!Metric {
    var reader: protobuf.Reader = .{ .bytes = bytes };
    var result: Metric = .{ .name = "", .value = 0 };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            result.name = try reader.string();
        } else if (field.number == 2 and field.wire_type == 1) {
            result.value = @bitCast(try reader.fixed64());
        } else try reader.skip(field);
    }
    return result;
}

fn putMetric(
    metrics: *std.ArrayList(Metric),
    allocator: std.mem.Allocator,
    metric: Metric,
) std.mem.Allocator.Error!void {
    for (metrics.items) |*existing| {
        if (std.mem.eql(u8, existing.name, metric.name)) {
            existing.* = metric;
            return;
        }
    }
    try metrics.append(allocator, metric);
}

fn appendMap(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    field_number: u8,
    metrics: []const Metric,
) Error!void {
    for (metrics) |metric| {
        var entry: std.ArrayList(u8) = .empty;
        defer entry.deinit(allocator);
        if (metric.name.len != 0) {
            try appendBytes(&entry, allocator, 1, metric.name);
        }
        if (metric.value != 0) {
            try appendDouble(&entry, allocator, 2, metric.value);
        }
        try appendBytes(output, allocator, field_number, entry.items);
    }
}

fn appendDouble(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    field_number: u8,
    value: f64,
) std.mem.Allocator.Error!void {
    try output.append(allocator, (field_number << 3) | 1);
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @bitCast(value), .little);
    try output.appendSlice(allocator, &encoded);
}

fn appendVarint(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    field_number: u8,
    value: u64,
) std.mem.Allocator.Error!void {
    try output.append(allocator, field_number << 3);
    try appendRawVarint(output, allocator, value);
}

fn appendBytes(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    field_number: u8,
    bytes: []const u8,
) std.mem.Allocator.Error!void {
    try output.append(allocator, (field_number << 3) | 2);
    try appendRawVarint(output, allocator, bytes.len);
    try output.appendSlice(allocator, bytes);
}

fn appendRawVarint(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    raw: anytype,
) std.mem.Allocator.Error!void {
    var value: u64 = @intCast(raw);
    while (value >= 128) : (value >>= 7) {
        try output.append(allocator, @as(u8, @truncate(value)) | 128);
    }
    try output.append(allocator, @intCast(value));
}

fn validateMetrics(metrics: []const Metric, fraction: bool) Error!void {
    for (metrics, 0..) |metric, index| {
        if (!std.unicode.utf8ValidateSlice(metric.name) or
            !std.math.isFinite(metric.value) or
            (fraction and (metric.value < 0 or metric.value > 1)))
        {
            return error.InvalidLoadReport;
        }
        for (metrics[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, metric.name)) {
                return error.InvalidLoadReport;
            }
        }
    }
}

fn validNonnegative(value: f64) bool {
    return std.math.isFinite(value) and value >= 0;
}

fn validFraction(value: f64) bool {
    return validNonnegative(value) and value <= 1;
}

test {
    _ = @import("orca/tests.zig");
}
