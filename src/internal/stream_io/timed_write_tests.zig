const std = @import("std");
const writer = @import("timed_write.zig");

const Observer = struct {
    var active: *Observer = undefined;
    delegate: std.Io,
    limit: usize = 3,
    fail_after: usize = std.math.maxInt(usize),
    race_timeout: bool = false,
    calls: usize = 0,
    bytes: [128]u8 = undefined,
    written: usize = 0,

    fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active;
        std.debug.assert(splat == 0 and data.len != 0 and data[data.len - 1].len == 0);
        if (self.calls == self.fail_after) return error.NetworkDown;
        self.calls += 1;
        var count: usize = 0;
        for (0..data.len) |index| {
            const part = if (index == 0) header else data[index - 1];
            const len = @min(part.len, self.limit - count);
            @memcpy(self.bytes[self.written + count ..][0..len], part[0..len]);
            count += len;
            if (count == self.limit) break;
        }
        self.written += count;
        if (self.race_timeout) std.Io.sleep(self.delegate, .fromMilliseconds(20), .awake) catch {};
        return count;
    }

    fn io(self: *Observer, vtable: *std.Io.VTable) std.Io {
        active = self;
        vtable.* = self.delegate.vtable.*;
        vtable.netWrite = write;
        return .{ .userdata = self.delegate.userdata, .vtable = vtable };
    }
};

fn socket() std.Io.net.Stream {
    return .{ .socket = .{ .handle = 0, .address = .{ .ip4 = .loopback(0) } } };
}

test "stream timed scatter writer advances within and across empty slice boundaries" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var observer = Observer{ .delegate = threaded.io(), .fail_after = 3 };
    var vtable: std.Io.VTable = undefined;
    const io = observer.io(&vtable);
    var committed: usize = 99;
    const parts: []const []const u8 = &.{ "", "ab", "", "cdef", "ghijk", "", "lm" };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try std.testing.expectError(error.NetworkDown, writer.writeAllSlicesTrackedWithDeadline(io, socket(), parts, &committed, deadline));
    try std.testing.expectEqual(@as(usize, 9), committed);
    try std.testing.expectEqualStrings("abcdefghi", observer.bytes[0..observer.written]);
}

test "stream timed scatter writer handles more slices than the native vector limit" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var observer = Observer{ .delegate = threaded.io(), .limit = 128 };
    var vtable: std.Io.VTable = undefined;
    const io = observer.io(&vtable);
    var bytes: [37]u8 = undefined;
    var parts: [37][]const u8 = undefined;
    for (&bytes, &parts, 0..) |*byte, *part, index| {
        byte.* = @intCast(index);
        part.* = bytes[index..][0..1];
    }
    var committed: usize = 99;
    try writer.writeAllSlicesTrackedWithDeadline(io, socket(), &parts, &committed, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(bytes.len, committed);
    try std.testing.expectEqualSlices(u8, &bytes, observer.bytes[0..observer.written]);
    try std.testing.expectEqual(@as(usize, 3), observer.calls);
}

test "stream timed scatter writer retains a multi-slice prefix racing timeout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var observer = Observer{ .delegate = threaded.io(), .limit = 5, .race_timeout = true };
    var vtable: std.Io.VTable = undefined;
    const io = observer.io(&vtable);
    var committed: usize = 99;
    try std.testing.expectError(error.Timeout, writer.writeAllSlicesTrackedWithDeadline(io, socket(), &.{ "ab", "cdef", "ghi" }, &committed, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(5) })));
    try std.testing.expectEqual(@as(usize, 5), committed);
    try std.testing.expectEqualStrings("abcde", observer.bytes[0..observer.written]);
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
}

test "stream timed scatter writer validates deadlines before socket output" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var observer = Observer{ .delegate = threaded.io() };
    var vtable: std.Io.VTable = undefined;
    const io = observer.io(&vtable);
    var committed: usize = 99;
    try std.testing.expectError(error.Timeout, writer.writeAllSlicesTrackedWithDeadline(io, socket(), &.{ "a", "b" }, &committed, .{ .clock = .awake, .raw = .zero }));
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(usize, 0), observer.calls);
    try writer.writeAllSlicesTrackedWithDeadline(io, socket(), &.{ "", "" }, &committed, .{ .clock = .awake, .raw = .zero });
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(usize, 0), observer.calls);
}
