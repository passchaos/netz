const std = @import("std");
const grpc = @import("../../../mod.zig");
const stream = @import("../stream.zig");
const allocator = std.testing.allocator;

pub fn readReply(reader: stream.Reader, expected: []const u8) !void {
    var count: usize = 0;
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(5));
        defer event.deinit(allocator);
        switch (event) {
            .message => |message| {
                try std.testing.expectEqualStrings(expected, message.payload);
                count += 1;
            },
            .terminal => |response| {
                try std.testing.expectEqual(grpc.Status.ok, response.status);
                try std.testing.expectEqual(@as(usize, 1), count);
                return;
            },
            else => {},
        }
    }
}

pub fn readOne(reader: stream.Reader, expected: []const u8, compressed: bool) !void {
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(5));
        defer event.deinit(allocator);
        if (event == .message) {
            try std.testing.expectEqualStrings(expected, event.message.payload);
            try std.testing.expectEqual(compressed, event.message.was_compressed);
            return;
        }
        if (event == .terminal) return error.EarlyTerminal;
    }
}

pub fn wait(event: *std.Io.Event, io: std.Io) !void {
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    while (true) {
        event.waitTimeout(io, .{ .deadline = until }) catch |err| {
            if (err == error.Timeout and until.durationFromNow(io).raw.nanoseconds > 0) continue;
            return err;
        };
        return;
    }
}
