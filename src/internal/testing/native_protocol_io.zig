//! Exercise native protocol behavior on each supported test I/O backend.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");

pub fn run(comptime test_case: anytype) anyerror!void {
    // Threaded's native Windows datagram deadline path reports unavailable
    // concurrency. Preserve Threaded coverage where it supports this scope.
    return runImpl(test_case, builtin.os.tag != .windows);
}

/// Stream and futex tests retain Threaded TCP coverage on Windows as well.
/// They do not rely on Threaded's unsupported timed datagram receive path.
pub fn runStream(comptime test_case: anytype) anyerror!void {
    return runImpl(test_case, true);
}

fn runImpl(comptime test_case: anytype, comptime include_threaded: bool) anyerror!void {
    if (include_threaded) {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
        defer threaded.deinit();
        try test_case(threaded.io());
    }
    // The application backend is exercised on every native platform.
    var backend = try runtime.Backend.initWithExecutors(std.testing.allocator, 1);
    defer backend.deinit();
    try test_case(backend.io());
}
