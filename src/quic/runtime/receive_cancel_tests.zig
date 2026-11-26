const std = @import("std");
const Endpoint = @import("../runtime.zig").Endpoint;
const forwarded_io = @import("../../internal/testing/forwarded_io.zig");
const native_protocol_io = @import("../../internal/testing/native_protocol_io.zig");

test "QUIC UDP batch preserves received prefix and rearms cancellation" {
    try native_protocol_io.run(exercise);
}

fn exercise(delegate: std.Io) !void {
    const allocator = std.testing.allocator;
    const PrefixIo = struct {
        delegate: std.Io,
        inject: bool = true,
        cancelled: bool = false,

        fn from(userdata: ?*anyopaque) *@This() {
            return @ptrCast(@alignCast(userdata.?));
        }

        fn base(self: *@This()) std.Io {
            return self.delegate;
        }

        fn mapTimeout(_: *@This(), value: std.Io.Timeout) std.Io.Timeout {
            return value;
        }

        fn awaitConcurrent(userdata: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
            const self = from(userdata);
            if (self.cancelled) return error.Canceled;
            try self.delegate.vtable.batchAwaitConcurrent(self.delegate.userdata, batch, timeout);
            if (self.inject) {
                const result = &batch.storage[0].completion.result.net_receive;
                if (result.*[1] != 0) {
                    result.*[0] = error.Canceled;
                    self.inject = false;
                }
            }
        }

        fn recancel(userdata: ?*anyopaque) void {
            const self = from(userdata);
            self.cancelled = true;
        }
    };
    var receiver = try Endpoint.bind(allocator, delegate, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer receiver.deinit();
    var sender = try Endpoint.bind(allocator, delegate, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer sender.deinit();
    try sender.sendBytes(receiver.address(), "first");
    try sender.sendBytes(receiver.address(), "second");
    var wrapper = PrefixIo{ .delegate = delegate };
    var vtable = forwarded_io.table(PrefixIo.from, PrefixIo.base, PrefixIo.mapTimeout);
    vtable.batchAwaitConcurrent = PrefixIo.awaitConcurrent;
    vtable.recancel = PrefixIo.recancel;
    receiver.io = .{ .userdata = &wrapper, .vtable = &vtable };
    defer receiver.io = delegate;
    const Worker = struct {
        ready: std.Io.Event = .unset,
        never: std.Io.Event = .unset,

        fn run(self: *@This(), io: std.Io) std.Io.Cancelable!void {
            self.ready.set(io);
            try self.never.wait(io);
        }
    };
    var worker = Worker{};
    var future = try receiver.io.concurrent(Worker.run, .{ &worker, receiver.io });
    defer future.cancel(receiver.io) catch {};
    try worker.ready.wait(delegate);
    try std.testing.expectError(error.Canceled, future.cancel(receiver.io));
    var storage: [3 * 128]u8 = undefined;
    var views: [3]@import("../runtime.zig").ReceivedBytesView = undefined;
    const count = try receiver.receiveManyBytesIntoWithTimeout(&storage, &views, .fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("first", views[0].bytes);
    try std.testing.expectEqualStrings("second", views[1].bytes);
    try std.testing.expectError(error.Canceled, receiver.receiveManyBytesIntoWithTimeout(&storage, &views, .fromMilliseconds(20)));
}
