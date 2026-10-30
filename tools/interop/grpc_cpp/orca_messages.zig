//! Bounded codec for `grpc.testing.TestOrcaReport` in the official
//! `orca_per_rpc` fixture. The standard ORCA metadata payload uses the public
//! `netz.grpc.orca` codec instead.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    DuplicateField,
    InvalidArgument,
    InvalidFieldNumber,
    InvalidUtf8,
    MalformedVarint,
    MessageTooLarge,
    MissingPayload,
    NonCanonicalVarint,
    TruncatedMessage,
    UnsupportedField,
    UnsupportedWireType,
};

pub const Metric = struct {
    name: []const u8,
    value: f64,
};

pub const Report = struct {
    cpu_utilization: f64,
    memory_utilization: f64,
    request_cost: []const Metric,
    utilization: []const Metric,
};

/// Encode the official request: a `grpc.testing.SimpleRequest` containing
/// only field 11 `orca_per_query_report`.
pub fn encodePerQueryRequestAlloc(
    allocator: std.mem.Allocator,
    report: Report,
) Error![]u8 {
    try validate(report);
    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(allocator);
    try appendFixed64(
        &nested,
        allocator,
        1,
        @bitCast(report.cpu_utilization),
    );
    try appendFixed64(
        &nested,
        allocator,
        2,
        @bitCast(report.memory_utilization),
    );
    try appendMap(&nested, allocator, 3, report.request_cost);
    try appendMap(&nested, allocator, 4, report.utilization);

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try appendBytes(&output, allocator, 11, nested.items);
    return output.toOwnedSlice(allocator);
}

/// Strictly decode the same request. Metric names borrow from `input`; the
/// caller owns the bounded entry arrays.
pub fn decodePerQueryRequest(
    input: []const u8,
    request_cost_out: []Metric,
    utilization_out: []Metric,
) Error!Report {
    var reader = Reader{ .input = input };
    const tag = try reader.readTag();
    if (tag.number != 11 or tag.wire_type != .length_delimited) {
        return error.UnsupportedField;
    }
    const bytes = try reader.readBytes(1024);
    if (!reader.finished()) return error.UnsupportedField;

    var report_reader = Reader{ .input = bytes };
    var cpu_seen = false;
    var memory_seen = false;
    var request_cost_len: usize = 0;
    var utilization_len: usize = 0;
    var result = Report{
        .cpu_utilization = 0,
        .memory_utilization = 0,
        .request_cost = request_cost_out[0..0],
        .utilization = utilization_out[0..0],
    };
    while (!report_reader.finished()) {
        const field = try report_reader.readTag();
        switch (field.number) {
            1 => {
                if (field.wire_type != .fixed64) {
                    return error.UnsupportedWireType;
                }
                if (cpu_seen) return error.DuplicateField;
                cpu_seen = true;
                result.cpu_utilization = @bitCast(
                    try report_reader.readFixed64(),
                );
            },
            2 => {
                if (field.wire_type != .fixed64) {
                    return error.UnsupportedWireType;
                }
                if (memory_seen) return error.DuplicateField;
                memory_seen = true;
                result.memory_utilization = @bitCast(
                    try report_reader.readFixed64(),
                );
            },
            3 => {
                if (field.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (request_cost_len == request_cost_out.len) {
                    return error.MessageTooLarge;
                }
                request_cost_out[request_cost_len] = try decodeMetric(
                    try report_reader.readBytes(256),
                );
                request_cost_len += 1;
            },
            4 => {
                if (field.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (utilization_len == utilization_out.len) {
                    return error.MessageTooLarge;
                }
                utilization_out[utilization_len] = try decodeMetric(
                    try report_reader.readBytes(256),
                );
                utilization_len += 1;
            },
            else => return error.UnsupportedField,
        }
    }
    if (!cpu_seen or !memory_seen) return error.MissingPayload;
    result.request_cost = request_cost_out[0..request_cost_len];
    result.utilization = utilization_out[0..utilization_len];
    try validate(result);
    return result;
}

fn decodeMetric(input: []const u8) Error!Metric {
    var reader = Reader{ .input = input };
    var name_seen = false;
    var value_seen = false;
    var result = Metric{ .name = "", .value = 0 };
    while (!reader.finished()) {
        const field = try reader.readTag();
        switch (field.number) {
            1 => {
                if (field.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (name_seen) return error.DuplicateField;
                name_seen = true;
                result.name = try reader.readBytes(128);
                if (!std.unicode.utf8ValidateSlice(result.name)) {
                    return error.InvalidUtf8;
                }
            },
            2 => {
                if (field.wire_type != .fixed64) {
                    return error.UnsupportedWireType;
                }
                if (value_seen) return error.DuplicateField;
                value_seen = true;
                result.value = @bitCast(try reader.readFixed64());
            },
            else => return error.UnsupportedField,
        }
    }
    if (!name_seen or !value_seen) return error.MissingPayload;
    return result;
}

fn validate(report: Report) Error!void {
    if (!std.math.isFinite(report.cpu_utilization) or
        report.cpu_utilization < 0 or
        !std.math.isFinite(report.memory_utilization) or
        report.memory_utilization < 0 or
        report.memory_utilization > 1)
    {
        return error.InvalidArgument;
    }
    try validateMetrics(report.request_cost, false);
    try validateMetrics(report.utilization, true);
}

fn validateMetrics(metrics: []const Metric, fraction: bool) Error!void {
    for (metrics, 0..) |metric, index| {
        if (metric.name.len > 128 or
            !std.unicode.utf8ValidateSlice(metric.name) or
            !std.math.isFinite(metric.value) or
            (fraction and (metric.value < 0 or metric.value > 1)))
        {
            return error.InvalidArgument;
        }
        for (metrics[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, metric.name)) {
                return error.DuplicateField;
            }
        }
    }
}

fn appendMap(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    field_number: u5,
    metrics: []const Metric,
) Error!void {
    for (metrics) |metric| {
        var entry: std.ArrayList(u8) = .empty;
        defer entry.deinit(allocator);
        try appendBytes(&entry, allocator, 1, metric.name);
        try appendFixed64(
            &entry,
            allocator,
            2,
            @bitCast(metric.value),
        );
        try appendBytes(output, allocator, field_number, entry.items);
    }
}

fn appendFixed64(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    number: u5,
    value: u64,
) std.mem.Allocator.Error!void {
    try output.append(allocator, fieldKey(number, .fixed64));
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, value, .little);
    try output.appendSlice(allocator, &encoded);
}

fn appendBytes(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    number: u5,
    bytes: []const u8,
) std.mem.Allocator.Error!void {
    try output.append(allocator, fieldKey(number, .length_delimited));
    var length = bytes.len;
    while (length >= 128) : (length >>= 7) {
        try output.append(allocator, @as(u8, @truncate(length)) | 128);
    }
    try output.append(allocator, @intCast(length));
    try output.appendSlice(allocator, bytes);
}

const WireType = enum(u3) {
    fixed64 = 1,
    length_delimited = 2,
};

const Tag = struct {
    number: u29,
    wire_type: WireType,
};

fn fieldKey(number: u5, wire_type: WireType) u8 {
    return (@as(u8, number) << 3) | @intFromEnum(wire_type);
}

const Reader = struct {
    input: []const u8,
    cursor: usize = 0,

    fn finished(self: Reader) bool {
        return self.cursor == self.input.len;
    }

    fn readTag(self: *Reader) Error!Tag {
        const raw = try self.readVarint();
        const number = raw >> 3;
        if (number == 0 or number > 0x1fff_ffff) {
            return error.InvalidFieldNumber;
        }
        const wire_type: WireType = switch (@as(u3, @truncate(raw & 7))) {
            1 => .fixed64,
            2 => .length_delimited,
            else => return error.UnsupportedWireType,
        };
        return .{ .number = @intCast(number), .wire_type = wire_type };
    }

    fn readBytes(self: *Reader, limit: usize) Error![]const u8 {
        const raw_len = try self.readVarint();
        if (raw_len > limit or raw_len > std.math.maxInt(usize)) {
            return error.MessageTooLarge;
        }
        const len: usize = @intCast(raw_len);
        const end = std.math.add(usize, self.cursor, len) catch
            return error.MessageTooLarge;
        if (end > self.input.len) return error.TruncatedMessage;
        defer self.cursor = end;
        return self.input[self.cursor..end];
    }

    fn readFixed64(self: *Reader) Error!u64 {
        if (8 > self.input.len - self.cursor) return error.TruncatedMessage;
        const value = std.mem.readInt(
            u64,
            self.input[self.cursor..][0..8],
            .little,
        );
        self.cursor += 8;
        return value;
    }

    fn readVarint(self: *Reader) Error!u64 {
        const start = self.cursor;
        var value: u64 = 0;
        var shift: u6 = 0;
        for (0..10) |index| {
            if (self.cursor == self.input.len) return error.TruncatedMessage;
            const byte = self.input[self.cursor];
            self.cursor += 1;
            if (index == 9 and byte > 1) return error.MalformedVarint;
            value |= @as(u64, byte & 0x7f) << shift;
            if (byte & 0x80 == 0) {
                if (self.cursor - start != varintLen(value)) {
                    return error.NonCanonicalVarint;
                }
                return value;
            }
            if (index != 9) shift += 7;
        }
        return error.MalformedVarint;
    }
};

fn varintLen(raw: anytype) usize {
    var value: u64 = @intCast(raw);
    var len: usize = 1;
    while (value >= 128) : (len += 1) value >>= 7;
    return len;
}

test "canonical ORCA per-query fixture round trips" {
    const expected = Report{
        .cpu_utilization = 0.8210,
        .memory_utilization = 0.5847,
        .request_cost = &.{.{ .name = "cost", .value = 3456.32 }},
        .utilization = &.{.{ .name = "util", .value = 0.30499 }},
    };
    const encoded = try encodePerQueryRequestAlloc(
        std.testing.allocator,
        expected,
    );
    defer std.testing.allocator.free(encoded);
    var request_cost: [1]Metric = undefined;
    var utilization: [1]Metric = undefined;
    const actual = try decodePerQueryRequest(
        encoded,
        &request_cost,
        &utilization,
    );
    try std.testing.expectEqual(expected.cpu_utilization, actual.cpu_utilization);
    try std.testing.expectEqual(expected.memory_utilization, actual.memory_utilization);
    try std.testing.expectEqualDeep(expected.request_cost, actual.request_cost);
    try std.testing.expectEqualDeep(expected.utilization, actual.utilization);
    try std.testing.expectError(
        error.TruncatedMessage,
        decodePerQueryRequest(
            "\x5a\x02\x09\x00",
            &request_cost,
            &utilization,
        ),
    );
}
