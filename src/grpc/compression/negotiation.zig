//! gRPC accepted-encoding values, field selection, and canonical output.
const std = @import("std");
const algorithm_types = @import("algorithm.zig");
const Algorithm = algorithm_types.Algorithm;
const AlgorithmSet = algorithm_types.AlgorithmSet;

/// Parses `grpc-accept-encoding`, ignoring extensions unknown to netz.
///
/// Unknown entries cannot be selected by this implementation but must not
/// hide known entries in the same comma-separated field.
pub fn parseValue(value: ?[]const u8) AlgorithmSet {
    var result: AlgorithmSet = .{};
    var tokens = std.mem.splitScalar(u8, value orelse "", ',');
    while (tokens.next()) |token| {
        if (Algorithm.parse(std.mem.trim(u8, token, " \t"))) |algorithm| {
            result.insert(algorithm);
        }
    }
    return result;
}

/// gRPC compression policy follows the last non-repeatable advertisement.
/// HTTP/1 adapters can supply their original field-name spelling.
pub fn parseFields(headers: anytype) AlgorithmSet {
    var latest: ?[]const u8 = null;
    for (headers) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, "grpc-accept-encoding")) latest = field.value;
    }
    return parseValue(latest);
}

pub fn formatInto(
    out: []u8,
    algorithms: AlgorithmSet,
) error{BufferTooSmall}![]u8 {
    var used: usize = 0;
    for ([_]Algorithm{
        .identity,
        .deflate,
        .gzip,
    }) |algorithm| {
        if (!algorithms.contains(algorithm)) continue;
        const delimiter: []const u8 = if (used == 0) "" else ",";
        const required = delimiter.len + algorithm.name().len;
        if (out.len -| used < required) return error.BufferTooSmall;
        @memcpy(out[used..][0..delimiter.len], delimiter);
        used += delimiter.len;
        @memcpy(out[used..][0..algorithm.name().len], algorithm.name());
        used += algorithm.name().len;
    }
    return out[0..used];
}
