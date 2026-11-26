const std = @import("std");
const client_jobs = @import("../endpoint_client/job.zig");
const server_jobs = @import("../endpoint_server/job.zig");
const client_endpoint = @import("../endpoint_client.zig");
const server_endpoint = @import("../endpoint_server.zig");
const Fixture = @import("../../../http2/runtime/duplex/testing.zig").Fixture;
const Faults = @import("../endpoint_client/testing/drop_faults.zig").Faults;
const allocator = std.testing.allocator;

const Parent = struct {
    allocator: std.mem.Allocator,
    refs: usize = 1,
    pub fn retain(self: *@This()) void {
        self.refs += 1;
    }
    pub fn release(self: *@This()) void {
        self.refs -= 1;
    }
};

fn before(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
}

test "WebTransport HTTP2 sliced jobs own caller payload across abandonment" {
    inline for (.{ client_jobs.Job(Parent), server_jobs.Job(Parent) }) |Job| {
        var parent: Parent = .{ .allocator = allocator };
        var first = "abc".*;
        var second = "def".*;
        var slices = [_][]const u8{ &first, "", &second };
        const job = try Job.createStreamSlices(&parent, .{ .index = 7, .generation = 9 }, 12, &slices, true, .{ .clock = .awake, .raw = .{ .nanoseconds = 0 } });
        var retained = true;
        defer if (retained) job.release();
        @memset(&first, 'x');
        @memset(&second, 'y');
        @memset(&slices, "changed");
        // The queued owner keeps the command alive after caller abandonment.
        job.retain();
        try std.testing.expect(job.abandon());
        job.release();
        try std.testing.expectEqualStrings("abcdef", job.command.send_stream.data);
        try std.testing.expect(job.command.send_stream.fin);
        try std.testing.expectEqual(@as(u62, 12), job.command.send_stream.id);
        try std.testing.expectEqual(@as(u32, 7), job.command.send_stream.handle.index);
        try std.testing.expectEqual(@as(u64, 9), job.command.send_stream.handle.generation);
        try std.testing.expectEqual(@as(usize, 2), parent.refs);
        job.release();
        retained = false;
        try std.testing.expectEqual(@as(usize, 1), parent.refs);
    }
}

fn allocationFailure(alloc: std.mem.Allocator, comptime Job: type) !void {
    var parent: Parent = .{ .allocator = alloc };
    defer std.testing.expectEqual(@as(usize, 1), parent.refs) catch @panic("parent reference leaked");
    const job = try Job.createStreamSlices(&parent, .{ .index = 0, .generation = 1 }, 0, &.{ "owned", "-payload" }, true, .{ .clock = .awake, .raw = .{ .nanoseconds = 0 } });
    defer job.release();
    try std.testing.expectEqualStrings("owned-payload", job.command.send_stream.data);
}

test "WebTransport HTTP2 sliced jobs release all allocations on staging failure" {
    inline for (.{ client_jobs.Job(Parent), server_jobs.Job(Parent) }) |Job| {
        const Check = struct {
            fn run(alloc: std.mem.Allocator) !void {
                return allocationFailure(alloc, Job);
            }
        };
        try std.testing.checkAllAllocationFailures(allocator, Check.run, .{});
    }
}

fn allocationProbe(comptime Endpoint: type) !void {
    var backend = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing });
    defer backend.deinit();
    const io = backend.io();
    var fixture = try Fixture.init(io);
    if (Endpoint == server_endpoint.EndpointServer) fixture.connection.role = .server;
    defer {
        fixture.peer.close(io);
        fixture.listener.deinit(io);
    }
    var faults: Faults = .{ .caller = std.Thread.getCurrentId(), .base = io };
    var endpoint = try Endpoint.init(faults.allocator(), fixture.connection, .{});
    defer endpoint.deinit();
    const handle: client_jobs.Handle = .{ .index = 0, .generation = 1 };
    const refs = endpoint.state.refs.load(.acquire);
    faults.tracking.store(true, .release);
    defer faults.tracking.store(false, .release);
    faults.deny.store(true, .release);
    try std.testing.expectError(error.Timeout, endpoint.sendStreamSlicesWithDeadline(handle, 0, &.{ "abc", "def" }, true, .fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) })));
    try std.testing.expectError(error.Timeout, endpoint.sendStreamSlicesWithDeadline(handle, 0, &.{ "abc", "def" }, true, .{ .clock = .real, .raw = .{ .nanoseconds = 0 } }));
    try std.testing.expectEqual(@as(usize, 0), faults.attempts.load(.acquire));
    faults.deny.store(false, .release);
    try std.testing.expectError(error.StaleSession, endpoint.sendStreamWithDeadline(handle, 0, "abcdef", true, before(io)));
    const contiguous = faults.attempts.swap(0, .acq_rel);
    try std.testing.expectError(error.StaleSession, endpoint.sendStreamSlicesWithDeadline(handle, 0, &.{ "abc", "", "def" }, true, before(io)));
    const sliced = faults.attempts.load(.acquire);
    // Count the real public admission, owning job and sole worker path. There
    // must be no additional caller allocation to stage a sliced payload.
    try std.testing.expect(contiguous > 0);
    try std.testing.expectEqual(contiguous, sliced);
    std.debug.print("{s} caller staging allocations: contiguous={d} sliced={d}\n", .{ @typeName(Endpoint), contiguous, sliced });
    endpoint.state.mutex.lockUncancelable(io);
    defer endpoint.state.mutex.unlock(io);
    try std.testing.expectEqual(refs, endpoint.state.refs.load(.acquire));
}

test "WebTransport HTTP2 sliced EndpointClient admission copies once and skips expired staging" {
    try allocationProbe(client_endpoint.EndpointClient);
}

test "WebTransport HTTP2 sliced EndpointServer admission copies once and skips expired staging" {
    try allocationProbe(server_endpoint.EndpointServer);
}
