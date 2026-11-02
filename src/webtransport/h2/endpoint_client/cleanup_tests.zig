const std = @import("std");
const cleanup = @import("cleanup.zig");
const endpoint = @import("../endpoint_client.zig");
const Fixture = @import("../../../http2/runtime/duplex/testing.zig").Fixture;
const Faults = @import("testing/drop_faults.zig").Faults;
const allocator = std.testing.allocator;

test "WebTransport HTTP2 cleanup requests coalesce and preserve the current Session generation" {
    var request: cleanup.Request = .{};
    request.publish(1);
    try std.testing.expect(request.request(1));
    try std.testing.expect(request.request(1));
    try std.testing.expectEqual(@as(u64, 1), request.take());
    try std.testing.expectEqual(@as(u64, 0), request.take());
    request.retire();
    request.publish(2);
    // A stale request already in flight can land after a slot is reused.
    // The valid new request replaces it, and later stale requests cannot
    // overwrite the new generation's request.
    request.pending.store(1, .release);
    try std.testing.expect(request.request(2));
    try std.testing.expect(!request.request(1));
    try std.testing.expectEqual(@as(u64, 2), request.take());
    request.retire();
    try std.testing.expect(!request.request(2));
    try std.testing.expect(!request.request(0));
}

test "WebTransport HTTP2 dropped result cleanup bypasses a held mutex and full queue without allocation" {
    for ([_]bool{ false, true }) |deny| try exerciseDrop(deny, false);
}

test "WebTransport HTTP2 dropped result remains safe after endpoint owner shutdown" {
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
    var client = try endpoint.EndpointClient.init(faults.allocator(), fixture.connection, .{ .max_sessions = 1, .max_queued_commands = 1 });
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
    // A failed Session still occupies its endpoint slot until removal. Use
    // this valid lifecycle state to isolate cleanup from Capsule I/O.
    state.slots[0].failure = error.SessionClosed;
    state.slots[0].cleanup.publish(1);
    state.active_sessions = 1;
    state.retain();
    var attempt = endpoint.ConnectAttempt{ .state = state, .accepted_session = .{
        .allocator = faults.allocator(),
        .handle = .{ .index = 0, .generation = 1 },
        .status = 200,
        .headers = try faults.allocator().alloc(@import("../../../http2/mod.zig").Hpack.HeaderField, 0),
        .selected_protocol = try faults.allocator().dupe(u8, "owned"),
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
        try std.testing.expectEqual(@as(u64, 0), state.slots[0].cleanup.generation.load(.acquire));
        faults.tracking.store(true, .release);
        faults.deny.store(deny, .release);
        attempt.deinit();
        attempt_owned = false;
        state_alive = false;
        // State was released by the drop; do not access it in cleanup.
        try std.testing.expectEqual(@as(usize, 0), faults.attempts.load(.acquire));
        return;
    }
    const job = try State.Job.create(state, .{ .open_stream = .{ .handle = .{ .index = 0, .generation = 1 }, .direction = .bidirectional } }, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
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
    try std.testing.expectEqual(@as(u64, 1), state.slots[0].cleanup.pending.load(.acquire));
    faults.tracking.store(false, .release);
    state.io = base;
    state.mutex.unlock(base);
    locked = false;
    try job.done.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    try std.testing.expectEqual(@as(?anyerror, error.StaleSession), job.err);
    state.mutex.lockUncancelable(base);
    locked = true;
    try std.testing.expectEqual(@as(usize, 0), state.active_sessions);
    try std.testing.expectEqual(@as(usize, 0), state.queued);
    try std.testing.expectEqual(@as(u64, 2), state.slots[0].generation);
    try std.testing.expectEqual(@as(u64, 0), state.slots[0].cleanup.generation.load(.acquire));
    try std.testing.expect(!cleanup.pending(state));
}
