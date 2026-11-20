//! Partial output retains source order across interrupted pump calls.
const std = @import("std");
const Pump = @import("reader_upload.zig").Pump;
const allocator = std.testing.allocator;

test "unified HTTP Reader upload preserves the unwritten suffix and source identity" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const Progress = struct { accepted_bytes: usize = 0 };
    const Target = struct {
        output: std.ArrayList(u8) = .empty,
        allowance: usize = 5,
        fn write(self: *@This(), bytes: []const u8, progress: *Progress, _: ?std.Io.Clock.Timestamp) !void {
            const count = @min(bytes.len, self.allowance);
            try self.output.appendSlice(allocator, bytes[0..count]);
            progress.accepted_bytes = count;
            if (count != bytes.len) return error.Timeout;
        }
    };
    var target: Target = .{};
    defer target.output.deinit(allocator);
    var reader = std.Io.Reader.fixed("reader contribution");
    var other = std.Io.Reader.fixed("wrong source");
    var pump: Pump = .{};
    defer pump.deinit(allocator);
    var progress: Progress = .{};
    try std.testing.expectError(error.Timeout, pump.run(allocator, threaded.io(), &reader, &target, Target.write, &progress, null));
    try std.testing.expectEqual(@as(usize, 5), progress.accepted_bytes);
    try std.testing.expectError(error.RequestBodyPending, pump.ensureDrained());
    try std.testing.expectError(error.RequestBodySourceChanged, pump.run(allocator, threaded.io(), &other, &target, Target.write, &progress, null));
    try std.testing.expectEqual(@as(usize, 0), other.seek);
    progress = .{};
    target.allowance = 100;
    try pump.run(allocator, threaded.io(), &reader, &target, Target.write, &progress, null);
    try pump.ensureDrained();
    try std.testing.expectEqual("reader contribution".len - 5, progress.accepted_bytes);
    try std.testing.expectEqualStrings("reader contribution", target.output.items);
}
