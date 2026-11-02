//! Cancellation must interrupt evaluation, including large overlapping programs.
const std = @import("std");
const regex = @import("../regex.zig");
const gpa = std.testing.allocator;
test "gRPC xDS safe regex evaluation respects expired and interrupted request budgets" {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var value = try regex.Regex.init(gpa, "(?:a|aa)*b", .{});
    defer value.deinit();
    var workspace = try regex.Workspace.init(gpa, value.program);
    defer workspace.deinit();
    try std.testing.expectError(error.Timeout, workspace.matchesWithBudget(value.program, "aab", .{ .io = base, .deadline = .fromNow(base, .{ .clock = .awake, .raw = .fromNanoseconds(-1) }) }));
    const Probe = struct {
        calls: usize = 0,
        var active: ?*@This() = null;
        fn check(_: ?*anyopaque) std.Io.Cancelable!void {
            const self = active.?;
            self.calls += 1;
            if (self.calls == 3) return error.Canceled;
        }
    };
    var probe: Probe = .{};
    var table = base.vtable.*;
    table.checkCancel = Probe.check;
    const io = std.Io{ .userdata = base.userdata, .vtable = &table };
    Probe.active = &probe;
    defer Probe.active = null;
    const input = try gpa.alloc(u8, 32768);
    defer gpa.free(input);
    @memset(input, 'a');
    try std.testing.expectError(error.Canceled, workspace.matchesWithBudget(value.program, input, .{ .io = io }));
    try std.testing.expectEqual(@as(usize, 3), probe.calls);
    try std.testing.expect(workspace.stats.states_visited > 0 and workspace.stats.states_visited < value.program.instructions.len * input.len);
    input[input.len - 1] = 'b';
    try std.testing.expect(workspace.matches(value.program, input));
}
