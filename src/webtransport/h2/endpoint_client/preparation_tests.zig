const std = @import("std");
const endpoint = @import("../endpoint_client.zig");
const Fixture = @import("../../../http2/runtime/duplex/testing.zig").Fixture;
const allocator = std.testing.allocator;

test "WebTransport HTTP2 EndpointClient command preparation uses the original deadline before queue commit" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const ClockAfterCopy = struct {
        base: std.Io,
        armed: std.atomic.Value(bool) = .init(false),
        shifted: std.atomic.Value(bool) = .init(false),
        var active: ?*@This() = null;
        fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            const self = active.?;
            const original = self.base.vtable.now(userdata, clock);
            return if (self.shifted.load(.acquire)) original.addDuration(.fromMilliseconds(100)) else original;
        }
        fn allocator(self: *@This()) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
        }
        fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            const bytes = std.testing.allocator.rawAlloc(len, alignment, ra);
            // The command's payload copy uses its arena allocation. Advance
            // the operation clock after this preparation, before queue commit.
            if (bytes != null and len >= 1024 and self.armed.load(.acquire)) self.shifted.store(true, .release);
            return bytes;
        }
        fn resize(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
            return std.testing.allocator.rawResize(bytes, alignment, len, ra);
        }
        fn remap(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
            return std.testing.allocator.rawRemap(bytes, alignment, len, ra);
        }
        fn free(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
            std.testing.allocator.rawFree(bytes, alignment, ra);
        }
    };
    var clock = ClockAfterCopy{ .base = base };
    ClockAfterCopy.active = &clock;
    defer ClockAfterCopy.active = null;
    var table = base.vtable.*;
    table.now = ClockAfterCopy.now;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    var fixture = try Fixture.init(io);
    defer {
        fixture.peer.close(io);
        fixture.listener.deinit(io);
    }
    var client = try endpoint.EndpointClient.init(clock.allocator(), fixture.connection, .{});
    defer client.deinit();
    client.state.mutex.lockUncancelable(base);
    defer client.state.mutex.unlock(base);
    const refs = client.state.refs.load(.acquire);
    const payload = [_]u8{'x'} ** 1024;
    clock.armed.store(true, .release);
    try std.testing.expectError(error.Timeout, client.sendDatagramWithDeadline(.{ .index = 0, .generation = 1 }, &payload, .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(50) })));
    try std.testing.expect(clock.shifted.load(.acquire));
    try std.testing.expectEqual(refs, client.state.refs.load(.acquire));
    try std.testing.expect(client.state.head == null and client.state.tail == null and client.state.queued == 0);
}

test "WebTransport HTTP2 EndpointClient initWithTimeout closes the transport on a zero budget" {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer {
        fixture.peer.close(io);
        fixture.listener.deinit(io);
    }
    try std.testing.expectError(
        error.Timeout,
        endpoint.EndpointClient.initWithTimeout(
            allocator,
            fixture.connection,
            .{},
            .fromNanoseconds(0),
        ),
    );
    var byte: [1]u8 = undefined;
    const count = try @import("../../../internal/stream_io.zig").readSomeWithDeadline(
        io,
        fixture.peer,
        &byte,
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }),
    );
    try std.testing.expectEqual(@as(usize, 0), count);
}
