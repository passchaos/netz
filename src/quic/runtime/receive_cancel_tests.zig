const std = @import("std");
const Endpoint = @import("../runtime.zig").Endpoint;

test "QUIC UDP batch preserves received prefix and rearms cancellation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const delegate = threaded.io();
    const PrefixIo = struct {
        delegate: std.Io,
        inject: bool = true,
        cancelled: bool = false,

        fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            return self.delegate.vtable.now(self.delegate.userdata, clock);
        }

        fn awaitConcurrent(userdata: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
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
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
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
    var vtable = delegate.vtable.*;
    vtable.now = PrefixIo.now;
    vtable.batchAwaitConcurrent = PrefixIo.awaitConcurrent;
    vtable.recancel = PrefixIo.recancel;
    receiver.io = .{ .userdata = &wrapper, .vtable = &vtable };
    defer receiver.io = delegate;
    var storage: [3 * 128]u8 = undefined;
    var views: [3]@import("../runtime.zig").ReceivedBytesView = undefined;
    const count = try receiver.receiveManyBytesIntoWithTimeout(&storage, &views, .fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("first", views[0].bytes);
    try std.testing.expectEqualStrings("second", views[1].bytes);
    try std.testing.expectError(error.Canceled, receiver.receiveManyBytesIntoWithTimeout(&storage, &views, .fromMilliseconds(20)));
}
