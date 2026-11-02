//! RDS retry_on/status conversion and grpc-core defaults, clamped to 5 attempts.
const std = @import("std");
const pb = @import("protobuf.zig");
const call = @import("../../call.zig");
const Status = @import("../../wire.zig").Status;
pub fn parse(gpa: std.mem.Allocator, bytes: []const u8, text_limit: usize) pb.Error!?call.RetryPolicy {
    var reader = pb.Reader{ .bytes = bytes };
    var names: []const u8 = "";
    var retries: u64 = 1;
    var backoff: ?[]const u8 = null;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) names = try pb.text(&reader, text_limit) else if (field.number == 2 and field.wire_type == 2) retries = try pb.wrapper(try reader.bytesValue()) else if (field.number == 8 and field.wire_type == 2) backoff = try reader.bytesValue() else try reader.skip(field);
    }
    if (retries == 0 or retries > std.math.maxInt(u32)) return error.InvalidRdsResource;
    var initial: std.Io.Duration = .fromMilliseconds(25);
    var maximum: std.Io.Duration = .fromMilliseconds(250);
    if (backoff) |raw| {
        var nested = pb.Reader{ .bytes = raw };
        var base: ?std.Io.Duration = null;
        var max: ?std.Io.Duration = null;
        while (try nested.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) base = try pb.duration(try nested.bytesValue()) else if (field.number == 2 and field.wire_type == 2) max = try pb.duration(try nested.bytesValue()) else try nested.skip(field);
        }
        initial = base orelse return error.InvalidRdsResource;
        maximum = max orelse .fromNanoseconds(initial.nanoseconds * 10);
        if (initial.nanoseconds <= 0 or maximum.nanoseconds < initial.nanoseconds) return error.InvalidRdsResource;
    }
    var codes: std.ArrayList(Status) = .empty;
    defer codes.deinit(gpa);
    var parts = std.mem.splitScalar(u8, names, ',');
    while (parts.next()) |name| {
        const status: Status = if (std.mem.eql(u8, name, "cancelled")) .cancelled else if (std.mem.eql(u8, name, "deadline-exceeded")) .deadline_exceeded else if (std.mem.eql(u8, name, "internal")) .internal else if (std.mem.eql(u8, name, "resource-exhausted")) .resource_exhausted else if (std.mem.eql(u8, name, "unavailable")) .unavailable else continue;
        for (codes.items) |previous| if (previous == status) break else {} else try codes.append(gpa, status);
    }
    if (codes.items.len == 0) return null;
    return .{ .max_attempts = @intCast(@min(retries + 1, 5)), .initial_backoff = initial, .max_backoff = maximum, .backoff_multiplier = 2, .retryable_status_codes = try codes.toOwnedSlice(gpa) };
}
