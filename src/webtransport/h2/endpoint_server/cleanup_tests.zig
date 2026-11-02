const std = @import("std");
const endpoint = @import("../endpoint_server.zig");
const Fixture = @import("../../../http2/runtime/duplex/testing.zig").Fixture;
const Faults = @import("../endpoint_client/testing/drop_faults.zig").Faults;
const allocator = std.testing.allocator;

test "WebTransport HTTP2 pending request drop bypasses a held mutex and full queue without allocation" {
    for ([_]bool{ false, true }) |deny| try exerciseDrop(deny, false);
}

test "WebTransport HTTP2 pending request drop remains safe after server owner shutdown" {
    try exerciseDrop(true, true);
}

fn exerciseDrop(deny: bool, shut_down: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var faults = Faults{ .caller = std.Thread.getCurrentId(), .base = base };
    Faults.active = &faults;
    defer Faults.active = null;
    var fixture = try Fixture.init(base);
    defer {
        fixture.peer.close(base);
        fixture.listener.deinit(base);
    }
    fixture.connection.role = .server;
    var client = try endpoint.EndpointServer.init(faults.allocator(), fixture.connection, .{ .max_sessions = 1, .max_pending_sessions = 1, .max_queued_commands = 1 });
    var owned = true;
    defer if (owned) client.deinit();
    const State = @TypeOf(client.state.*);
    const state = client.state;
    var state_alive = true;
    state.mutex.lockUncancelable(base);
    var locked = true;
    defer {
        faults.tracking.store(false, .release);
        if (state_alive) {
            state.io = base;
            if (locked and !faults.released) state.mutex.unlock(base);
        }
    }
    // A request whose transport admission was already retired can still be
    // kept in the pending table until its owning handle is removed.
    state.pending[0].request = .{ .request = undefined, .receive_settings = .{}, .active = false };
    state.pending[0].claimed = true;
    state.pending[0].cleanup.publish(1);
    state.pending_count = 1;
    state.retain();
    var attempt = endpoint.PendingRequest{ .state = state, .data = .{
        .allocator = faults.allocator(),
        .handle = .{ .index = 0, .generation = 1 },
        .path = try faults.allocator().dupe(u8, "/owned"),
        .authority = null,
        .origin = null,
        .headers = try faults.allocator().alloc(@import("../../../http2/mod.zig").Hpack.HeaderField, 0),
    } };
    var attempt_owned = true;
    defer if (attempt_owned) attempt.deinit();
    faults.mutex = &state.mutex;
    var table = base.vtable.*;
    table.futexWaitUncancelable = Faults.waitUncancelable;
    state.io = .{ .userdata = base.userdata, .vtable = &table };
    if (shut_down) {
        state.io = base;
        state.mutex.unlock(base);
        locked = false;
        client.deinit();
        owned = false;
        // The accepted result retains State and its fixed slots until drop.
        try std.testing.expectEqual(@as(u64, 0), state.pending[0].cleanup.generation.load(.acquire));
        faults.tracking.store(true, .release);
        faults.deny.store(deny, .release);
        attempt.deinit();
        attempt_owned = false;
        state_alive = false;
        // State was released by the drop; do not access it in cleanup.
        try std.testing.expectEqual(@as(usize, 0), faults.attempts.load(.acquire));
        return;
    }
    const job = try State.Job.create(state, .{ .accept = .{ .handle = .{ .index = 0, .generation = 1 }, .options = .{} } }, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    defer job.release();
    job.retain();
    state.head = job;
    state.tail = job;
    state.queued = 1;
    const refs = state.refs.load(.acquire);
    faults.tracking.store(true, .release);
    faults.deny.store(deny, .release);
    attempt.deinit();
    attempt_owned = false;
    try std.testing.expectEqual(@as(usize, 0), faults.attempts.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), faults.unbounded);
    try std.testing.expectEqual(refs - 1, state.refs.load(.acquire));
    try std.testing.expect(state.head == job and state.tail == job and state.queued == 1);
    try std.testing.expectEqual(@as(u64, 1), state.pending[0].cleanup.pending.load(.acquire));
    faults.tracking.store(false, .release);
    state.io = base;
    state.mutex.unlock(base);
    locked = false;
    try job.done.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    try std.testing.expectEqual(@as(?anyerror, error.StalePendingSession), job.err);
    state.mutex.lockUncancelable(base);
    locked = true;
    try std.testing.expectEqual(@as(usize, 0), state.pending_count);
    try std.testing.expectEqual(@as(usize, 0), state.queued);
    try std.testing.expectEqual(@as(u64, 2), state.pending[0].generation);
    try std.testing.expectEqual(@as(u64, 0), state.pending[0].cleanup.generation.load(.acquire));
    try std.testing.expect(!state.cleanup_pending.load(.acquire));
}
