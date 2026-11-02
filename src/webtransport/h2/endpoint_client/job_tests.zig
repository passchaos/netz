const std = @import("std");
const endpoint = @import("../endpoint_client.zig");
const Fixture = @import("../../../http2/runtime/duplex/testing.zig").Fixture;
const allocator = std.testing.allocator;

test "WebTransport HTTP2 EndpointClient owner rejects expired commands before Session lookup" {
    for ([_]bool{ false, true }) |abandoned| {
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var fixture = try Fixture.init(io);
        defer {
            fixture.peer.close(io);
            fixture.listener.deinit(io);
        }
        var client = try endpoint.EndpointClient.init(allocator, fixture.connection, .{});
        defer client.deinit();
        const State = @TypeOf(client.state.*);
        const command: @import("job.zig").Command = .{ .open_stream = .{ .handle = endpoint.Handle{ .index = 0, .generation = 1 }, .direction = .bidirectional } };
        const job = try State.Job.create(client.state, command, .fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) }));
        defer job.release();
        if (abandoned) try std.testing.expect(job.abandon());
        // Delay queue admission independently of the waiting caller. Before
        // the fix the owner would look up this handle and return StaleSession.
        client.state.mutex.lockUncancelable(io);
        job.retain();
        client.state.head = job;
        client.state.tail = job;
        client.state.queued = 1;
        client.state.wake.set(io);
        client.state.mutex.unlock(io);
        if (abandoned) {
            // Abandoned completion is not delivered to the caller. Wait on a
            // later command's completion to prove the owner has drained it.
            try std.testing.expectError(error.StaleSession, client.openStreamWithTimeout(.{ .index = 0, .generation = 1 }, .bidirectional, .fromSeconds(1)));
            try std.testing.expectEqual(@as(?anyerror, error.Canceled), job.err);
        } else {
            try job.done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
            try std.testing.expectEqual(@as(?anyerror, error.Timeout), job.err);
            try std.testing.expect(!job.abandon());
        }
        client.state.mutex.lockUncancelable(io);
        defer client.state.mutex.unlock(io);
        try std.testing.expect(client.state.head == null and client.state.tail == null);
        try std.testing.expectEqual(@as(usize, 0), client.state.queued);
        try std.testing.expectEqual(@as(usize, 0), client.state.active_sessions);
        try std.testing.expectEqual(@as(u31, 1), client.state.connection.next_client_stream_id);
        try std.testing.expectEqual(@as(usize, 1), job.refs.load(.acquire));
    }
}

test "WebTransport HTTP2 EndpointClient completed job wins later abandonment and retains its owned event" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer {
        fixture.peer.close(io);
        fixture.listener.deinit(io);
    }
    var client = try endpoint.EndpointClient.init(allocator, fixture.connection, .{});
    defer client.deinit();
    const State = @TypeOf(client.state.*);
    const parent_refs = client.state.refs.load(.acquire);
    const job = try State.Job.create(client.state, .{ .receive = .{ .index = 0, .generation = 1 } }, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    var owned = true;
    defer if (owned) job.release();
    job.event = .{ .allocator = allocator, .value = .{ .datagram = try allocator.dupe(u8, "owned-after-completion") } };
    job.retain();
    try std.testing.expect(client.state.finish(job, null));
    try std.testing.expect(!job.abandon());
    var event = job.takeEvent();
    defer event.deinit();
    job.release();
    owned = false;
    try std.testing.expectEqualStrings("owned-after-completion", event.value.datagram);
    try std.testing.expectEqual(parent_refs, client.state.refs.load(.acquire));
}
