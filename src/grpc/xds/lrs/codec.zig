//! Envoy v3 Load Reporting Service envelopes.
const std = @import("std");
const protobuf = @import("../../protobuf.zig");
pub const Error = protobuf.Error || std.mem.Allocator.Error || error{ InvalidLoadReport, LoadReportLimitExceeded };

pub const Limits = struct {
    max_message_bytes: usize = 16 * 1024 * 1024,
    max_clusters: usize = 4096,
    max_localities: usize = 4096,
    max_dropped: usize = 256,
    max_endpoints: usize = 4096,
    max_text_bytes: usize = 4096,
};

pub const Locality = struct { region: []const u8 = "", zone: []const u8 = "", sub_zone: []const u8 = "" };
pub const EndpointStats = struct {
    host: []const u8,
    port: u16,
    ipv6: bool = false,
    successful: u64 = 0,
    in_progress: u64 = 0,
    error_requests: u64 = 0,
    issued: u64 = 0,
};
pub const MetricStats = struct {
    count: u64 = 0,
    value: f64 = 0,
};
pub const LocalityStats = struct {
    locality: Locality = .{},
    successful: u64 = 0,
    in_progress: u64 = 0,
    error_requests: u64 = 0,
    issued: u64 = 0,
    cpu_utilization: ?MetricStats = null,
    memory_utilization: ?MetricStats = null,
    application_utilization: ?MetricStats = null,
    endpoints: []const EndpointStats = &.{},
};
pub const Dropped = struct { category: []const u8, count: u64 = 0 };
pub const ClusterStats = struct {
    name: []const u8,
    service_name: []const u8 = "",
    localities: []const LocalityStats = &.{},
    total_dropped: u64 = 0,
    dropped: []const Dropped = &.{},
    interval_ns: u64 = 0,
};
pub const Request = struct { node: ?[]const u8 = null, clusters: []const ClusterStats = &.{} };
pub const Response = struct {
    clusters: []const []const u8 = &.{},
    interval_ns: ?u64 = null,
    report_endpoint_granularity: bool = false,
    send_all_clusters: bool = false,
};

pub const OwnedResponse = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    clusters: [][]const u8,
    value: Response,
    pub fn deinit(self: *OwnedResponse) void {
        self.allocator.free(self.clusters);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const OwnedCluster = struct {
    value: ClusterStats,
    localities: []LocalityStats,
    dropped: []Dropped,
};
pub const OwnedRequest = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    clusters: []OwnedCluster,
    stats: []ClusterStats,
    value: Request,
    pub fn deinit(self: *OwnedRequest) void {
        for (self.clusters) |cluster| {
            for (cluster.localities) |locality| self.allocator.free(locality.endpoints);
            self.allocator.free(cluster.localities);
            self.allocator.free(cluster.dropped);
        }
        self.allocator.free(self.clusters);
        self.allocator.free(self.stats);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn integer(out: *std.ArrayList(u8), gpa: std.mem.Allocator, raw: u64) Error!void {
    var value = raw;
    while (value >= 128) : (value >>= 7) try out.append(gpa, @as(u8, @truncate(value)) | 0x80);
    try out.append(gpa, @intCast(value));
}

fn bytesField(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, bytes: []const u8) Error!void {
    try integer(out, gpa, @as(u64, field) * 8 + 2);
    try integer(out, gpa, bytes.len);
    try out.appendSlice(gpa, bytes);
}

fn numberField(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, value: u64) Error!void {
    try integer(out, gpa, @as(u64, field) * 8);
    try integer(out, gpa, value);
}

fn doubleField(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, value: f64) Error!void {
    try integer(out, gpa, @as(u64, field) * 8 + 1);
    const bits: u64 = @bitCast(value);
    var index: usize = 0;
    while (index < 8) : (index += 1) try out.append(gpa, @truncate(bits >> @intCast(index * 8)));
}

fn encodeMetric(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, metric: MetricStats) Error!void {
    if (metric.count == 0 and metric.value == 0) return;
    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(gpa);
    if (metric.count != 0) try numberField(&nested, gpa, 1, metric.count);
    if (metric.value != 0) try doubleField(&nested, gpa, 2, metric.value);
    try bytesField(out, gpa, field, nested.items);
}

fn text(bytes: []const u8, limits: Limits, allow_empty: bool) Error!void {
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidLoadReport;
    if ((!allow_empty and bytes.len == 0) or bytes.len > limits.max_text_bytes) return error.InvalidLoadReport;
}

fn encodeDuration(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, nanoseconds: u64) Error!void {
    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(gpa);
    const seconds = nanoseconds / std.time.ns_per_s;
    const nanos: u32 = @intCast(nanoseconds % std.time.ns_per_s);
    if (seconds != 0) try numberField(&nested, gpa, 1, seconds);
    if (nanos != 0) try numberField(&nested, gpa, 2, nanos);
    try bytesField(out, gpa, field, nested.items);
}

fn encodeLocality(out: *std.ArrayList(u8), gpa: std.mem.Allocator, locality: Locality, limits: Limits) Error!void {
    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(gpa);
    try text(locality.region, limits, true);
    try text(locality.zone, limits, true);
    try text(locality.sub_zone, limits, true);
    if (locality.region.len != 0) try bytesField(&nested, gpa, 1, locality.region);
    if (locality.zone.len != 0) try bytesField(&nested, gpa, 2, locality.zone);
    if (locality.sub_zone.len != 0) try bytesField(&nested, gpa, 3, locality.sub_zone);
    try bytesField(out, gpa, 1, nested.items);
}

fn encodeEndpointStats(out: *std.ArrayList(u8), gpa: std.mem.Allocator, value: EndpointStats, limits: Limits) Error!void {
    try text(value.host, limits, false);
    if (value.port == 0) return error.InvalidLoadReport;
    var socket: std.ArrayList(u8) = .empty;
    defer socket.deinit(gpa);
    try numberField(&socket, gpa, 1, @intFromBool(value.ipv6));
    try bytesField(&socket, gpa, 2, value.host);
    try numberField(&socket, gpa, 3, value.port);
    var address: std.ArrayList(u8) = .empty;
    defer address.deinit(gpa);
    try bytesField(&address, gpa, 1, socket.items);
    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(gpa);
    try bytesField(&nested, gpa, 1, address.items);
    if (value.successful != 0) try numberField(&nested, gpa, 2, value.successful);
    if (value.in_progress != 0) try numberField(&nested, gpa, 3, value.in_progress);
    if (value.error_requests != 0) try numberField(&nested, gpa, 4, value.error_requests);
    if (value.issued != 0) try numberField(&nested, gpa, 7, value.issued);
    try bytesField(out, gpa, 7, nested.items);
}

fn encodeLocalityStats(out: *std.ArrayList(u8), gpa: std.mem.Allocator, value: LocalityStats, limits: Limits) Error!void {
    if (value.endpoints.len > limits.max_endpoints) return error.LoadReportLimitExceeded;
    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(gpa);
    try encodeLocality(&nested, gpa, value.locality, limits);
    if (value.successful != 0) try numberField(&nested, gpa, 2, value.successful);
    if (value.in_progress != 0) try numberField(&nested, gpa, 3, value.in_progress);
    if (value.error_requests != 0) try numberField(&nested, gpa, 4, value.error_requests);
    if (value.issued != 0) try numberField(&nested, gpa, 8, value.issued);
    if (value.cpu_utilization) |metric| try encodeMetric(&nested, gpa, 12, metric);
    if (value.memory_utilization) |metric| try encodeMetric(&nested, gpa, 13, metric);
    if (value.application_utilization) |metric| try encodeMetric(&nested, gpa, 14, metric);
    for (value.endpoints) |endpoint| try encodeEndpointStats(&nested, gpa, endpoint, limits);
    try bytesField(out, gpa, 2, nested.items);
}

fn encodeDropped(out: *std.ArrayList(u8), gpa: std.mem.Allocator, value: Dropped, limits: Limits) Error!void {
    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(gpa);
    try text(value.category, limits, false);
    try bytesField(&nested, gpa, 1, value.category);
    if (value.count != 0) try numberField(&nested, gpa, 2, value.count);
    try bytesField(out, gpa, 5, nested.items);
}

fn encodeCluster(out: *std.ArrayList(u8), gpa: std.mem.Allocator, value: ClusterStats, limits: Limits) Error!void {
    try text(value.name, limits, false);
    try text(value.service_name, limits, true);
    if (value.localities.len > limits.max_localities or value.dropped.len > limits.max_dropped) return error.LoadReportLimitExceeded;
    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(gpa);
    try bytesField(&nested, gpa, 1, value.name);
    for (value.localities) |locality| try encodeLocalityStats(&nested, gpa, locality, limits);
    if (value.total_dropped != 0) try numberField(&nested, gpa, 3, value.total_dropped);
    if (value.interval_ns != 0) try encodeDuration(&nested, gpa, 4, value.interval_ns);
    for (value.dropped) |dropped| try encodeDropped(&nested, gpa, dropped, limits);
    if (value.service_name.len != 0) try bytesField(&nested, gpa, 6, value.service_name);
    try bytesField(out, gpa, 2, nested.items);
}

pub fn encodeRequest(gpa: std.mem.Allocator, request: Request, limits: Limits) Error![]u8 {
    if (request.clusters.len > limits.max_clusters) return error.LoadReportLimitExceeded;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    if (request.node) |node| {
        if (node.len == 0) return error.InvalidLoadReport;
        var reader: protobuf.Reader = .{ .bytes = node };
        while (try reader.next()) |field| try reader.skip(field);
        try bytesField(&out, gpa, 1, node);
    }
    for (request.clusters) |cluster| try encodeCluster(&out, gpa, cluster, limits);
    if (out.items.len > limits.max_message_bytes) return error.LoadReportLimitExceeded;
    return out.toOwnedSlice(gpa);
}

pub fn encodeResponse(gpa: std.mem.Allocator, response: Response, limits: Limits) Error![]u8 {
    if (response.clusters.len > limits.max_clusters) return error.LoadReportLimitExceeded;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (response.clusters) |name| {
        try text(name, limits, false);
        try bytesField(&out, gpa, 1, name);
    }
    if (response.interval_ns) |nanoseconds| try encodeDuration(&out, gpa, 2, nanoseconds);
    if (response.report_endpoint_granularity) try numberField(&out, gpa, 3, 1);
    if (response.send_all_clusters) try numberField(&out, gpa, 4, 1);
    if (out.items.len > limits.max_message_bytes) return error.LoadReportLimitExceeded;
    return out.toOwnedSlice(gpa);
}

fn parseDuration(bytes: []const u8) Error!u64 {
    var seconds: u64 = 0;
    var nanos: u32 = 0;
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) {
            const raw = try reader.varint();
            if (raw > std.math.maxInt(i64)) return error.InvalidLoadReport;
            seconds = raw;
        } else if (field.number == 2 and field.wire_type == 0) {
            const raw = try reader.varint();
            if (raw > std.math.maxInt(i32) or raw >= std.time.ns_per_s) return error.InvalidLoadReport;
            nanos = @intCast(raw);
        } else try reader.skip(field);
    }
    const seconds_ns = std.math.mul(u64, seconds, std.time.ns_per_s) catch return error.InvalidLoadReport;
    return std.math.add(u64, seconds_ns, nanos) catch return error.InvalidLoadReport;
}

fn parseLocality(bytes: []const u8, limits: Limits) Error!Locality {
    var result: Locality = .{};
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) result.region = try reader.string() else if (field.number == 2 and field.wire_type == 2) result.zone = try reader.string() else if (field.number == 3 and field.wire_type == 2) result.sub_zone = try reader.string() else try reader.skip(field);
    }
    try text(result.region, limits, true);
    try text(result.zone, limits, true);
    try text(result.sub_zone, limits, true);
    return result;
}

fn parseEndpointStats(bytes: []const u8, limits: Limits) Error!EndpointStats {
    var result: EndpointStats = .{ .host = "", .port = 0 };
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            var address_reader: protobuf.Reader = .{ .bytes = try reader.bytesValue() };
            while (try address_reader.next()) |address_field| {
                if (address_field.number == 1 and address_field.wire_type == 2) {
                    var socket_reader: protobuf.Reader = .{ .bytes = try address_reader.bytesValue() };
                    while (try socket_reader.next()) |socket_field| {
                        if (socket_field.number == 1 and socket_field.wire_type == 0) {
                            const protocol = try socket_reader.varint();
                            if (protocol > 1) return error.InvalidLoadReport;
                            result.ipv6 = protocol == 1;
                        } else if (socket_field.number == 2 and socket_field.wire_type == 2) result.host = try socket_reader.string() else if (socket_field.number == 3 and socket_field.wire_type == 0) {
                            const port = try socket_reader.varint();
                            if (port == 0 or port > std.math.maxInt(u16)) return error.InvalidLoadReport;
                            result.port = @intCast(port);
                        } else try socket_reader.skip(socket_field);
                    }
                } else try address_reader.skip(address_field);
            }
        } else if (field.number == 2 and field.wire_type == 0) result.successful = try reader.varint() else if (field.number == 3 and field.wire_type == 0) result.in_progress = try reader.varint() else if (field.number == 4 and field.wire_type == 0) result.error_requests = try reader.varint() else if (field.number == 7 and field.wire_type == 0) result.issued = try reader.varint() else try reader.skip(field);
    }
    try text(result.host, limits, false);
    if (result.port == 0) return error.InvalidLoadReport;
    return result;
}

fn parseLocalityStats(gpa: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!LocalityStats {
    var endpoints: std.ArrayList(EndpointStats) = .empty;
    errdefer endpoints.deinit(gpa);
    var result: LocalityStats = .{};
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) result.locality = try parseLocality(try reader.bytesValue(), limits) else if (field.number == 2 and field.wire_type == 0) result.successful = try reader.varint() else if (field.number == 3 and field.wire_type == 0) result.in_progress = try reader.varint() else if (field.number == 4 and field.wire_type == 0) result.error_requests = try reader.varint() else if (field.number == 8 and field.wire_type == 0) result.issued = try reader.varint() else if (field.number == 7 and field.wire_type == 2) {
            if (endpoints.items.len >= limits.max_endpoints) return error.LoadReportLimitExceeded;
            try endpoints.append(gpa, try parseEndpointStats(try reader.bytesValue(), limits));
        } else try reader.skip(field);
    }
    result.endpoints = try endpoints.toOwnedSlice(gpa);
    return result;
}

fn parseDropped(bytes: []const u8, limits: Limits) Error!Dropped {
    var result: Dropped = .{ .category = "" };
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) result.category = try reader.string() else if (field.number == 2 and field.wire_type == 0) result.count = try reader.varint() else try reader.skip(field);
    }
    try text(result.category, limits, false);
    return result;
}

fn parseCluster(gpa: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!OwnedCluster {
    var localities: std.ArrayList(LocalityStats) = .empty;
    errdefer {
        for (localities.items) |locality| gpa.free(locality.endpoints);
        localities.deinit(gpa);
    }
    var dropped: std.ArrayList(Dropped) = .empty;
    errdefer dropped.deinit(gpa);
    var value: ClusterStats = .{ .name = "" };
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) value.name = try reader.string() else if (field.number == 2 and field.wire_type == 2) {
            if (localities.items.len >= limits.max_localities) return error.LoadReportLimitExceeded;
            try localities.append(gpa, try parseLocalityStats(gpa, try reader.bytesValue(), limits));
        } else if (field.number == 3 and field.wire_type == 0) value.total_dropped = try reader.varint() else if (field.number == 4 and field.wire_type == 2) value.interval_ns = try parseDuration(try reader.bytesValue()) else if (field.number == 5 and field.wire_type == 2) {
            if (dropped.items.len >= limits.max_dropped) return error.LoadReportLimitExceeded;
            try dropped.append(gpa, try parseDropped(try reader.bytesValue(), limits));
        } else if (field.number == 6 and field.wire_type == 2) value.service_name = try reader.string() else try reader.skip(field);
    }
    try text(value.name, limits, false);
    try text(value.service_name, limits, true);
    const locality_values = try localities.toOwnedSlice(gpa);
    errdefer gpa.free(locality_values);
    const dropped_values = try dropped.toOwnedSlice(gpa);
    value.localities = locality_values;
    value.dropped = dropped_values;
    return .{ .value = value, .localities = locality_values, .dropped = dropped_values };
}

pub fn decodeResponse(gpa: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!OwnedResponse {
    if (bytes.len > limits.max_message_bytes) return error.LoadReportLimitExceeded;
    const owned = try gpa.dupe(u8, bytes);
    errdefer gpa.free(owned);
    var clusters: std.ArrayList([]const u8) = .empty;
    errdefer clusters.deinit(gpa);
    var response: Response = .{};
    var reader: protobuf.Reader = .{ .bytes = owned };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            if (clusters.items.len >= limits.max_clusters) return error.LoadReportLimitExceeded;
            try clusters.append(gpa, try reader.string());
        } else if (field.number == 2 and field.wire_type == 2) response.interval_ns = try parseDuration(try reader.bytesValue()) else if (field.number == 3 and field.wire_type == 0) response.report_endpoint_granularity = try reader.varint() != 0 else if (field.number == 4 and field.wire_type == 0) response.send_all_clusters = try reader.varint() != 0 else try reader.skip(field);
    }
    for (clusters.items, 0..) |name, index| {
        try text(name, limits, false);
        if (index != 0) for (clusters.items[0..index]) |previous| if (std.mem.eql(u8, previous, name)) return error.InvalidLoadReport;
    }
    const values = try clusters.toOwnedSlice(gpa);
    response.clusters = values;
    return .{ .allocator = gpa, .bytes = owned, .clusters = values, .value = response };
}

pub fn decodeRequest(gpa: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!OwnedRequest {
    if (bytes.len > limits.max_message_bytes) return error.LoadReportLimitExceeded;
    const owned = try gpa.dupe(u8, bytes);
    errdefer gpa.free(owned);
    var clusters: std.ArrayList(OwnedCluster) = .empty;
    errdefer {
        for (clusters.items) |cluster| {
            for (cluster.localities) |locality| gpa.free(locality.endpoints);
            gpa.free(cluster.localities);
            gpa.free(cluster.dropped);
        }
        clusters.deinit(gpa);
    }
    var request: Request = .{};
    var reader: protobuf.Reader = .{ .bytes = owned };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) request.node = try reader.bytesValue() else if (field.number == 2 and field.wire_type == 2) {
            if (clusters.items.len >= limits.max_clusters) return error.LoadReportLimitExceeded;
            try clusters.append(gpa, try parseCluster(gpa, try reader.bytesValue(), limits));
        } else try reader.skip(field);
    }
    for (clusters.items, 0..) |cluster, index| {
        if (index != 0) for (clusters.items[0..index]) |previous| if (std.mem.eql(u8, previous.value.name, cluster.value.name)) return error.InvalidLoadReport;
    }
    const values = try clusters.toOwnedSlice(gpa);
    const stats = try gpa.alloc(ClusterStats, values.len);
    errdefer gpa.free(stats);
    for (values, stats) |cluster, *stat| stat.* = cluster.value;
    request.clusters = stats;
    return .{ .allocator = gpa, .bytes = owned, .clusters = values, .stats = stats, .value = request };
}
