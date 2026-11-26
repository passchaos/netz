//! Native experiment for Threaded receive completion racing cancellation.
//! Keep this separate from protocol behavior until Windows establishes the
//! primitive's result. No socket modes or production I/O paths are changed.
const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const net = std.Io.net;

const Cancellation = struct {
    ready: std.Io.Event = .unset,
    never: std.Io.Event = .unset,

    fn wait(self: *Cancellation, io: std.Io) std.Io.Cancelable!void {
        self.ready.set(io);
        try self.never.wait(io);
    }
};

const Pair = struct {
    sender: net.Stream,
    receiver: net.Stream,

    fn init(io: std.Io) !Pair {
        var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
        defer listener.deinit(io);
        const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer sender.close(io);
        return .{ .sender = sender, .receiver = try listener.accept(io) };
    }

    fn deinit(self: Pair, io: std.Io) void {
        self.receiver.close(io);
        self.sender.close(io);
    }

    fn send(self: Pair, io: std.Io, bytes: []const u8) !void {
        var writer = self.sender.writer(io, &.{});
        try writer.interface.writeAll(bytes);
    }
};

/// The buffers, request and operation storage remain at stable addresses from
/// submission until cancel/await has joined the native completion APC.
const Receive = struct {
    buffers: [1]windows.AFD.WSABUF(.@"var"),
    info: windows.AFD.RECV_INFO,
    storage: [1]std.Io.Operation.Storage,
    batch: std.Io.Batch,

    fn init(self: *Receive, stream: net.Stream, bytes: []u8, peek: bool) void {
        self.buffers = .{.{ .len = @intCast(bytes.len), .buf = bytes.ptr }};
        self.info = .{
            .BufferArray = &self.buffers,
            .BufferCount = 1,
            // These are the ordinary Threaded netRead flags.
            .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
            .TdiFlags = .{ .NORMAL = true, .PEEK = peek },
        };
        self.batch = .init(&self.storage);
        _ = self.batch.add(.{ .device_io_control = .{
            .file = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = true } },
            .code = windows.IOCTL.AFD.RECEIVE,
            .in = std.mem.asBytes(&self.info),
        } });
    }

    fn count(completion: std.Io.Batch.Completion) !usize {
        const iosb = completion.result.device_io_control;
        if (iosb.u.Status != .SUCCESS) return windows.unexpectedStatus(iosb.u.Status);
        return iosb.Information;
    }

    fn cancel(self: *Receive, io: std.Io) void {
        if (self.batch.pending.head != .none) {
            // Threaded batchCancel first waits indefinitely for an APC or
            // alert, before issuing NtCancelIoFileEx. An idle receive need
            // not have an APC queued. Arm one alert on this native owner so
            // that initial wait can advance to cancellation and join.
            const status = windows.ntdll.NtAlertThread(windows.GetCurrentThread());
            std.debug.assert(status == .SUCCESS);
        }
        self.batch.cancel(io);
    }

    fn wait(self: *Receive, io: std.Io) !usize {
        defer self.cancel(io);
        const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(2),
        });
        while (true) {
            self.batch.awaitConcurrent(io, .{ .deadline = deadline }) catch |err| {
                self.cancel(io);
                if (self.batch.next()) |completion| {
                    const received = try count(completion);
                    if (err == error.Canceled) std.Io.recancel(io);
                    return received;
                }
                return err;
            };
            if (self.batch.next()) |completion| return count(completion);
        }
    }
};

fn read(io: std.Io, stream: net.Stream, bytes: []u8, peek: bool) !usize {
    var operation: Receive = undefined;
    operation.init(stream, bytes, peek);
    return operation.wait(io);
}

const Observation = struct {
    bytes: [5]u8 = @splat(0xcc),
    received: usize = 0,
    read_error: ?anyerror = null,
    cancellation_pending: bool = false,
    cancellation: Cancellation = .{},

    fn run(self: *Observation, io: std.Io, stream: net.Stream, batch: bool) void {
        // An early read failure must also release the parent's handshake wait;
        // assertions will distinguish it from the intended canceled boundary.
        defer self.cancellation.ready.set(io);
        // The parent cancels this actual Future at the announced point.
        // Only a cancellation already observed at a real wait can be rearmed.
        // The raw case then targets submission with readable data; the Batch
        // case announces cancellation after native completion, before dequeue.
        if (!batch) {
            self.cancellation.wait(io) catch |err| {
                std.debug.assert(err == error.Canceled);
                std.Io.recancel(io);
            };
        }
        const result = if (batch) read(io, stream, &self.bytes, false) else raw: {
            var buffers = [_][]u8{&self.bytes};
            break :raw io.vtable.netRead(io.userdata, stream.socket.handle, &buffers);
        };
        self.received = result catch |err| failed: {
            self.read_error = err;
            break :failed 0;
        };
        std.Io.checkCancel(io) catch {
            self.cancellation_pending = true;
        };
    }
};

const CompletedAwait = struct {
    var delegate: std.Io = undefined;
    var cancellation: *Cancellation = undefined;

    fn awaitConcurrent(userdata: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        try delegate.vtable.batchAwaitConcurrent(userdata, batch, timeout);
        if (batch.completed.head != .none) {
            // The real Future.cancel request reaches this wait after the
            // receive completed. Propagate its actual Canceled result with
            // the native completion still available for the candidate.
            try cancellation.wait(delegate);
        }
    }
};

test "TCP completion probe consumes and rearms real task cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    const Caller = struct {
        cancellation: Cancellation = .{},
        observed: usize = 0,

        fn run(self: *@This(), task_io: std.Io) void {
            self.cancellation.wait(task_io) catch |err| {
                std.debug.assert(err == error.Canceled);
                self.observed += 1;
                std.Io.recancel(task_io);
                std.Io.checkCancel(task_io) catch |next| {
                    std.debug.assert(next == error.Canceled);
                    self.observed += 1;
                };
            };
        }
    };
    var caller = Caller{};
    var worker = try io.concurrent(Caller.run, .{ &caller, io });
    defer worker.cancel(io);
    try caller.cancellation.ready.wait(io);
    worker.cancel(io);
    try std.testing.expectEqual(@as(usize, 2), caller.observed);
}

test "Windows Threaded TCP completion probe compares ordinary receive with joined Batch" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    CompletedAwait.delegate = io;
    var vtable = io.vtable.*;
    vtable.batchAwaitConcurrent = CompletedAwait.awaitConcurrent;
    const interrupted = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var observations: [2]Observation = @splat(.{});
    for (&observations, 0..) |*observation, index| {
        const pair = try Pair.init(io);
        defer pair.deinit(io);
        try pair.send(io, "ABCDE");
        var peek: [5]u8 = undefined;
        const ready = try read(io, pair.receiver, &peek, true);
        try std.testing.expectEqual(@as(usize, 5), ready);
        try std.testing.expectEqualStrings("ABCDE", &peek);

        const worker_io = if (index == 1) interrupted else io;
        CompletedAwait.cancellation = &observation.cancellation;
        var worker = try io.concurrent(Observation.run, .{ observation, worker_io, pair.receiver, index == 1 });
        defer worker.cancel(io);
        try observation.cancellation.ready.wait(io);
        worker.cancel(io);
        if (observation.read_error) |err| try std.testing.expectEqual(error.Canceled, err);
        if (index == 0 and observation.read_error == null) {
            try std.testing.expectEqual(@as(usize, 5), observation.received);
            try std.testing.expectEqualStrings("ABCDE", &observation.bytes);
        }
        if (index == 1) {
            try std.testing.expect(observation.read_error == null);
            try std.testing.expectEqual(@as(usize, 5), observation.received);
            try std.testing.expectEqualStrings("ABCDE", &observation.bytes);
            try std.testing.expect(observation.cancellation_pending);
            try pair.send(io, "FGHIJ");
            var suffix: [5]u8 = undefined;
            try std.testing.expectEqual(@as(usize, 5), try read(io, pair.receiver, &suffix, false));
            try std.testing.expectEqualStrings("FGHIJ", &suffix);
        }
    }
    const raw = observations[0];
    const joined = observations[1];
    var raw_changed_bytes: usize = 0;
    for (raw.bytes) |byte| {
        if (byte != 0xcc) raw_changed_bytes += 1;
    }
    // A bounded notice exposes the primitive result in public CI annotations,
    // including successful runs whose raw log may not be publicly available.
    std.debug.print("\n::notice title=Windows TCP completion probe::{{\"raw_error\":\"{s}\",\"raw_count\":{d},\"raw_changed_bytes\":{d},\"raw_payload_in_buffer\":{any},\"batch_count\":{d},\"batch_cancel_pending\":{any},\"batch_cancel_after_native_completion\":true,\"exact_suffix\":true}}\n", .{
        if (raw.read_error) |err| @errorName(err) else "none",
        raw.received,
        raw_changed_bytes,
        std.mem.eql(u8, &raw.bytes, "ABCDE"),
        joined.received,
        joined.cancellation_pending,
    });
}

test "Windows Threaded TCP completion probe cancels pending receive and reuses its socket" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    const pair = try Pair.init(io);
    defer pair.deinit(io);
    var bytes: [5]u8 = @splat(0xcc);
    var operation: Receive = undefined;
    operation.init(pair.receiver, &bytes, false);
    defer operation.cancel(io);
    try std.testing.expectError(error.Timeout, operation.batch.awaitConcurrent(io, .{
        .duration = .{ .clock = .awake, .raw = .zero },
    }));
    try std.testing.expect(operation.batch.pending.head != .none);
    operation.cancel(io);
    try std.testing.expect(operation.batch.next() == null);
    try std.testing.expectEqualSlices(u8, &@as([5]u8, @splat(0xcc)), &bytes);

    try pair.send(io, "reuse");
    try std.testing.expectEqual(@as(usize, 5), try read(io, pair.receiver, &bytes, false));
    try std.testing.expectEqualStrings("reuse", &bytes);
    std.debug.print("\n::notice title=Windows TCP pending receive probe::one native self-alert before cancel; entered receive canceled and joined; buffer untouched; exact same-socket reuse passed\n", .{});
}
