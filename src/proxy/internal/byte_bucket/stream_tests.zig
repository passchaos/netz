const std = @import("std");
const ByteBucket = @import("../byte_bucket.zig").ByteBucket;
const output = @import("stream.zig");

const Script = struct {
    calls: usize = 0,
    fail_at: ?usize = null,
    chunk: usize,
    sink: [32]u8 = undefined,
    used: usize = 0,

    fn send(_: std.Io, self: *Script, bytes: []const u8, _: ?std.Io.Clock.Timestamp) output.Error!usize {
        const call = self.calls;
        self.calls += 1;
        if (self.fail_at == call) return error.Timeout;
        const count = @min(bytes.len, self.chunk);
        @memcpy(self.sink[self.used..][0..count], bytes[0..count]);
        self.used += count;
        return count;
    }
};

test "proxy rate write charges only committed partial TCP bytes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var bucket = ByteBucket.initWithBurst(1, 16, std.math.maxInt(i64));
    var script = Script{ .chunk = 3, .fail_at = 1 };
    var committed: usize = 99;
    try std.testing.expectError(error.Timeout, output.writeUsing(&bucket, threaded.io(), &script, Script.send, "abcdefgh", &committed, null));
    try std.testing.expectEqual(@as(usize, 3), committed);
    try std.testing.expectEqual(@as(u64, 13), bucket.tokens);
    script.fail_at = null;
    try output.writeUsing(&bucket, threaded.io(), &script, Script.send, "defgh", &committed, null);
    try std.testing.expectEqualStrings("abcdefgh", script.sink[0..script.used]);
    try std.testing.expectEqual(@as(u64, 8), bucket.tokens);
}

test "proxy rate write preserves committed credit on later rate timeout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var bucket = ByteBucket.initWithBurst(1, 4, std.math.maxInt(i64));
    var script = Script{ .chunk = 32 };
    var committed: usize = 99;
    try std.testing.expectError(error.Timeout, output.writeUsing(&bucket, io, &script, Script.send, "abcdefgh", &committed, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2) })));
    try std.testing.expectEqualStrings("abcd", script.sink[0..script.used]);
    try std.testing.expectEqual(@as(usize, 4), committed);
    try std.testing.expectEqual(@as(u64, 0), bucket.tokens);
}
