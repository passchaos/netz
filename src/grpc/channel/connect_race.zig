//! Plan a gRPC connection pass without changing public endpoint indices.
const std = @import("std");
const competition = @import("../../internal/connection_race.zig");
const Family = std.meta.Tag(std.Io.net.IpAddress);
const stack_capacity = 8;

/// A result is an original endpoint index. The caller's stable endpoint slot
/// owns the HTTP/2 connection, so selector storage never copies large values.
pub fn connect(comptime Error: type, allocator: std.mem.Allocator, io: std.Io, context: anytype, start: usize, delay: std.Io.Duration, deadline: ?std.Io.Clock.Timestamp, canceled: *std.Io.Event) (Error || competition.Error)!?usize {
    const count = context.count();
    var input_stack: [stack_capacity]usize = undefined;
    const input_heap = if (count > input_stack.len) try allocator.alloc(usize, count) else null;
    defer if (input_heap) |storage| allocator.free(storage);
    const input = input_heap orelse input_stack[0..count];
    var eligible: usize = 0;
    for (0..count) |offset| {
        const index = (start + offset) % count;
        if (!context.eligible(index)) continue;
        input[eligible] = index;
        eligible += 1;
    }
    if (eligible == 0) return null;
    var ordered_stack: [stack_capacity]usize = undefined;
    const ordered_heap = if (eligible > ordered_stack.len) try allocator.alloc(usize, eligible) else null;
    defer if (ordered_heap) |storage| allocator.free(storage);
    const ordered = ordered_heap orelse ordered_stack[0..eligible];
    interleave(context, ordered, input[0..eligible]);
    const Context = @TypeOf(context);
    context.start();
    return try competition.race(Error, usize, allocator, io, ordered, .{
        .attempt_delay = delay,
        // Every configured endpoint can make progress even when all earlier
        // addresses remain blackholed. Launches are staggered, not capped at
        // two permanently occupied sockets.
        .max_in_flight = eligible,
        .cancel_event = canceled,
    }, deadline, if (deadline != null) @as(?Error, error.Timeout) else null, context, Context.connect, Context.deinitConnected, Context.tryNext);
}

fn interleave(context: anytype, output: []usize, input: []const usize) void {
    const preferred = context.family(input[0]) orelse {
        @memcpy(output, input);
        return;
    };
    for (input) |index| if (context.family(index) == null) {
        @memcpy(output, input);
        return;
    };
    const alternate: Family = if (preferred == .ip4) .ip6 else .ip4;
    var preferred_cursor: usize = 0;
    var alternate_cursor: usize = 0;
    var want_preferred = true;
    for (output) |*index| {
        if (want_preferred) {
            if (next(context, input, preferred, &preferred_cursor)) |found| {
                index.* = found;
                want_preferred = false;
                continue;
            }
        } else if (next(context, input, alternate, &alternate_cursor)) |found| {
            index.* = found;
            want_preferred = true;
            continue;
        }
        index.* = next(context, input, if (want_preferred) alternate else preferred, if (want_preferred) &alternate_cursor else &preferred_cursor).?;
    }
}

fn next(context: anytype, input: []const usize, family: Family, cursor: *usize) ?usize {
    while (cursor.* < input.len) : (cursor.* += 1) {
        const index = input[cursor.*];
        if (context.family(index) != family) continue;
        cursor.* += 1;
        return index;
    }
    return null;
}

test "gRPC connection competition preserves indices and stable family order" {
    const families = [_]?Family{ .ip6, .ip6, .ip4, .ip4, .ip6 };
    const Context = struct {
        families: []const ?Family,
        fn family(self: @This(), index: usize) ?Family {
            return self.families[index];
        }
    };
    var out: [5]usize = undefined;
    interleave(Context{ .families = &families }, &out, &.{ 0, 1, 2, 3, 4 });
    try std.testing.expectEqualSlices(usize, &.{ 0, 2, 1, 3, 4 }, &out);
    const mixed = [_]?Family{ .ip6, null, .ip4 };
    interleave(Context{ .families = &mixed }, out[0..3], &.{ 0, 1, 2 });
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 2 }, out[0..3]);
}
