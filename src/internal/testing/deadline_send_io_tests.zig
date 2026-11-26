const std = @import("std");
const Native = @import("deadline_send_io.zig").Native;
const native_protocol_io = @import("native_protocol_io.zig");
const quic = @import("../../quic/mod.zig");
const allocator = std.testing.allocator;

const Probe = struct {
    observer: Native,
    await_callback: @FieldType(std.Io.VTable, "batchAwaitConcurrent") = undefined,
    entered: std.Io.Event = .unset,
    last_timeout: ?std.Io.Timeout = null,

    fn io(self: *Probe) std.Io {
        const wrapped = self.observer.io();
        self.await_callback = wrapped.vtable.batchAwaitConcurrent;
        self.observer.table.batchAwaitConcurrent = awaitBatch;
        return wrapped;
    }

    fn awaitBatch(userdata: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        const observer: *Native = @fieldParentPtr("backend", backend);
        const self: *Probe = @alignCast(@fieldParentPtr("observer", observer));
        self.last_timeout = timeout;
        self.entered.set(observer.baseIo());
        return self.await_callback(userdata, batch, timeout);
    }
};

test "Native protocol observer forwards entered UDP read cancellation and preserves the socket" {
    try native_protocol_io.run(cancelRead);
}

fn cancelRead(io: std.Io) !void {
    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer endpoint.deinit();
    var peer = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer peer.deinit();
    var probe: Probe = .{ .observer = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = io,
        .fixed_clock = false,
    } };
    defer probe.observer.backend.deinit();
    const wrapped = probe.io();
    endpoint.io = wrapped;
    defer endpoint.io = io;
    const Worker = struct {
        fn run(receiver: *quic.runtime.Endpoint) !void {
            var bytes = try receiver.receiveBytesWithTimeout(.fromSeconds(2));
            defer bytes.deinit(allocator);
            return error.TestUnexpectedResult;
        }
    };
    var pending = try std.Io.concurrent(wrapped, Worker.run, .{&endpoint});
    defer pending.cancel(wrapped) catch {};
    try probe.entered.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } });
    try std.testing.expectError(error.Canceled, pending.cancel(wrapped));
    try peer.sendBytes(endpoint.address(), "after-joined-cancel");
    var bytes = try endpoint.receiveBytesWithTimeout(.fromSeconds(1));
    defer bytes.deinit(allocator);
    try std.testing.expectEqualStrings("after-joined-cancel", bytes.bytes);
    try std.testing.expectEqual(peer.address().getPort(), bytes.from.getPort());
}

test "Native protocol observer translates synthetic absolute UDP deadlines at the actual backend" {
    try native_protocol_io.run(syntheticDeadline);
}

fn syntheticDeadline(io: std.Io) !void {
    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer endpoint.deinit();
    // The inner observer records the timeout that reaches the actual backend.
    var actual: Probe = .{ .observer = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = io,
        .fixed_clock = false,
    } };
    defer actual.observer.backend.deinit();
    var clock: Native = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = actual.io(),
        .now_ns = .init(1_000_000),
    };
    defer clock.backend.deinit();
    endpoint.io = clock.io();
    defer endpoint.io = io;
    const start = std.Io.Clock.awake.now(io);
    try std.testing.expectError(error.Timeout, endpoint.receiveBytesWithDeadline(.{
        .clock = .awake,
        .raw = .fromNanoseconds(clock.now_ns.load(.acquire) + 20 * std.time.ns_per_ms),
    }));
    const submitted = actual.last_timeout.?;
    try std.testing.expect(submitted == .duration);
    try std.testing.expectEqual(@as(i96, 20 * std.time.ns_per_ms), submitted.duration.raw.nanoseconds);
    try std.testing.expect(start.durationTo(std.Io.Clock.awake.now(io)).nanoseconds < 2 * std.time.ns_per_s);
}
