//! Validate complete logical fields before allocating their unfolded values.
const std = @import("std");
const http1 = @import("../mod.zig");
const wire = @import("../../internal/wire.zig");
const Lines = http1.LineIterator;

pub fn Parser(comptime Context: type) type {
    return struct {
        pub fn parse(allocator: std.mem.Allocator, lines: *Lines, options: http1.ParseOptions, policy: Context.PolicyType) http1.Error!Context.ResultType {
            var headers: std.ArrayList(http1.Header) = .empty;
            var values: std.ArrayList([]u8) = .empty;
            errdefer {
                for (values.items) |value| allocator.free(value);
                values.deinit(allocator);
                headers.deinit(allocator);
            }
            while (lines.next()) |line| {
                if (line.len == 0) continue;
                if (continuation(line)) {
                    // An orphan continuation can be ignored only if its
                    // bytes cannot alter another parser's line boundaries.
                    if (!policy.ignore_invalid or Context.fatal(line)) return error.MalformedHeader;
                    continue;
                }
                var header = Context.parseLine(line, policy.allow_spaces_before_colon) catch |err| {
                    if (!policy.ignore_invalid or Context.fatal(line)) return err;
                    try skipIgnoredGroup(lines);
                    continue;
                };
                if (headers.items.len >= options.max_headers) return error.TooManyHeaders;
                const first_continuation = lines.*;
                const group = try scanGroup(lines, header.value.len, policy.ignore_invalid);
                if (!group.valid) continue;
                if (group.count != 0) {
                    var owned: ?[]u8 = try allocator.alloc(u8, group.value_len);
                    defer if (owned) |value| allocator.free(value);
                    copyValue(owned.?, header.value, first_continuation, group.count);
                    try values.append(allocator, owned.?);
                    header.value = owned.?;
                    owned = null;
                }
                try headers.append(allocator, header);
            }
            const owned_headers = try headers.toOwnedSlice(allocator);
            errdefer allocator.free(owned_headers);
            return .{ .headers = owned_headers, .value_storage = try values.toOwnedSlice(allocator) };
        }

        const Group = struct { count: usize = 0, value_len: usize, valid: bool = true };

        fn scanGroup(lines: *Lines, initial_len: usize, ignore_invalid: bool) http1.Error!Group {
            var group: Group = .{ .value_len = initial_len };
            while (true) {
                var next = lines.*;
                const line = next.next() orelse break;
                if (!continuation(line)) break;
                // Keep checking after any earlier malformed continuation:
                // discarding a field never authorizes skipping fatal bytes.
                if (Context.fatal(line)) return error.MalformedHeader;
                const value = wire.trimOws(line);
                Context.validateValue(value) catch |err| {
                    if (!ignore_invalid) return err;
                    group.valid = false;
                };
                group.value_len = std.math.add(usize, group.value_len, 1) catch return error.MalformedHeader;
                group.value_len = std.math.add(usize, group.value_len, value.len) catch return error.MalformedHeader;
                group.count += 1;
                lines.* = next;
            }
            return group;
        }

        fn skipIgnoredGroup(lines: *Lines) http1.Error!void {
            while (true) {
                var next = lines.*;
                const line = next.next() orelse return;
                if (!continuation(line)) return;
                if (Context.fatal(line)) return error.MalformedHeader;
                lines.* = next;
            }
        }

        fn copyValue(destination: []u8, initial: []const u8, lines_value: Lines, count: usize) void {
            @memcpy(destination[0..initial.len], initial);
            var offset = initial.len;
            var lines = lines_value;
            for (0..count) |_| {
                const value = wire.trimOws(lines.next().?);
                // RFC 9112 replaces every obs-fold with at least one SP,
                // including an otherwise empty whitespace-only line.
                destination[offset] = ' ';
                offset += 1;
                @memcpy(destination[offset..][0..value.len], value);
                offset += value.len;
            }
            std.debug.assert(offset == destination.len);
        }

        fn continuation(line: []const u8) bool {
            return line.len != 0 and (line[0] == ' ' or line[0] == '\t');
        }
    };
}
