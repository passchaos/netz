const std = @import("std");
const fixture = @import("testing/record_fixture.zig");
const terminal = @import("../../http2/runtime/control/tls_close.zig");

test "HTTP/2 terminal TLS close deadline includes writer mutex admission" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    inline for (.{ false, true }) |old| {
        const Record = if (old) @import("tls12_record_stream.zig") else @import("record_stream.zig");
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{});
        defer listener.deinit(base);
        const peer = try listener.socket.address.connect(base, .{ .mode = .stream });
        defer peer.close(base);
        const stream = try listener.accept(base);
        defer stream.close(base);
        const Connection = struct {
            io: std.Io,
            stream: std.Io.net.Stream,
            records: union(enum) { value: Record.Stream },
            pub fn sendCloseNotify(self: *@This()) Record.Error!void {
                try self.records.value.sendCloseNotify(self.io, self.stream);
            }
            pub fn sendCloseNotifyWithDeadline(self: *@This(), deadline: std.Io.Clock.Timestamp) Record.Error!void {
                try self.records.value.sendCloseNotifyWithDeadline(self.io, self.stream, deadline);
            }
        };
        const Transport = union(enum) { tcp: void, tls_client: *Connection, tls_server: *Connection };
        var connection = Connection{ .io = base, .stream = stream, .records = .{ .value = try fixture.stream(old, 0x22, 0x11) } };
        defer connection.records.value.deinit();
        const Probe = struct {
            base: std.Io,
            mutex: *std.Io.Mutex,
            unbounded_waits: usize = 0,
            var active: ?*@This() = null;
            fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
                const self = active.?;
                const target: *const u32 = @ptrCast(&self.mutex.state.raw);
                if (pointer == target) {
                    self.unbounded_waits += 1;
                    self.mutex.state.store(.unlocked, .release);
                } else self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
            }
        };
        const mutex = &connection.records.value.write_mutex;
        mutex.lockUncancelable(base);
        defer {
            _ = mutex.tryLock();
            mutex.unlock(base);
        }
        var probe = Probe{ .base = base, .mutex = mutex };
        var table = base.vtable.*;
        table.futexWaitUncancelable = Probe.wait;
        Probe.active = &probe;
        defer Probe.active = null;
        connection.io = .{ .userdata = base.userdata, .vtable = &table };
        terminal.closeNotify(Transport{ .tls_client = &connection }, .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(10) }));
        try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
        try std.testing.expect(!mutex.tryLock());
        try std.testing.expect(connection.records.value.failed);
        try std.testing.expect(!connection.records.value.close_notify_sent);
    }
}
