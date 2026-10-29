const std = @import("std");
const shared = @import("../../../shared.zig");
const stream = @import("../../stream.zig");
const call_module = @import("../call.zig");
const Wake = @import("../../wake.zig").Wake;

const Operation = enum { read, write };

fn retire(state: anytype, call: anytype) void {
    call.requestCancel();
    state.lock();
    call.retireLocked(error.Canceled);
    state.unlock();
    call.release(); // Synthetic endpoint ownership.
    call.release(); // Caller capability ownership.
}

fn exerciseAdmission(operation: Operation, canceled: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var channel = try shared.SharedChannel.init(std.testing.allocator, base, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = channel.sender();
    defer sender.deinit();
    channel.deinit();
    const state = sender.state;
    const State = @TypeOf(state.*);
    state.closed = false;
    defer state.closed = true;
    const references = state.refs.load(.acquire);
    const call = try State.StreamCall.create(state, .{ .path = "/svc/Bidi" }, null);
    call.retain();
    const wake = try Wake.create(std.testing.allocator);
    call.setOwnerWake(wake);
    wake.release();

    const Probe = struct {
        base: std.Io,
        mutex: *std.Io.Mutex,
        canceled: bool,
        unbounded_waits: usize = 0,
        var active: ?*@This() = null;
        fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            const mutex: *const u32 = @ptrCast(&self.mutex.state.raw);
            if (self.canceled and pointer == mutex) return error.Canceled;
            return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
        }
        fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
            const self = active.?;
            const mutex: *const u32 = @ptrCast(&self.mutex.state.raw);
            if (pointer == mutex) {
                self.unbounded_waits += 1;
                self.mutex.state.store(.unlocked, .release);
            } else self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
        }
    };
    var probe = Probe{ .base = base, .mutex = &state.mutex, .canceled = canceled };
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    table.futexWaitUncancelable = Probe.waitUncancelable;
    Probe.active = &probe;
    state.io = .{ .userdata = base.userdata, .vtable = &table };
    state.mutex.lockUncancelable(base);

    const expected = if (canceled) error.Canceled else error.Timeout;
    switch (operation) {
        .write => {
            const writer = stream.Writer{ .call = call };
            if (canceled) {
                try std.testing.expectError(expected, writer.writeMessage("body"));
            } else try std.testing.expectError(expected, writer.writeMessageWithTimeout("body", .fromMilliseconds(1)));
            try std.testing.expectEqual(@as(?anyerror, null), call.failureValue());
            try std.testing.expect(!call.cancel_requested.load(.acquire));
            try std.testing.expect(call.write == null);
        },
        .read => {
            const reader = stream.Reader{ .call = call };
            if (canceled) {
                try std.testing.expectError(expected, reader.next());
            } else {
                try std.testing.expectError(expected, reader.nextWithTimeout(.fromMilliseconds(1)));
            }
            try std.testing.expectEqual(@as(?anyerror, null), call.failureValue());
            try std.testing.expect(!call.cancel_requested.load(.acquire));
            try std.testing.expect(!call.read_busy.load(.acquire));
        },
    }
    try std.testing.expect(!wake.event.isSet());
    try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
    try std.testing.expect(!state.mutex.tryLock());

    state.io = base;
    Probe.active = null;
    state.mutex.unlock(base);
    retire(state, call);
    try std.testing.expectEqual(references, state.refs.load(.acquire));
}

test "gRPC shared stream operation admission obeys deadline and cancellation" {
    for ([_]Operation{ .read, .write }) |operation| {
        for ([_]bool{ false, true }) |canceled| try exerciseAdmission(operation, canceled);
    }
}

fn exerciseInterrupted(operation: Operation) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var channel = try shared.SharedChannel.init(std.testing.allocator, base, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = channel.sender();
    defer sender.deinit();
    channel.deinit();
    const state = sender.state;
    const State = @TypeOf(state.*);
    state.closed = false;
    defer state.closed = true;
    const references = state.refs.load(.acquire);
    const call = try State.StreamCall.create(state, .{ .path = "/svc/Bidi" }, null);
    call.retain();
    const wake = try Wake.create(std.testing.allocator);
    call.setOwnerWake(wake);
    wake.release();

    const Probe = struct {
        base: std.Io,
        mutex: *std.Io.Mutex,
        retired: *std.Io.Event,
        entered: bool = false,
        unbounded_waits: usize = 0,
        var active: ?*@This() = null;
        fn wait(_: ?*anyopaque, _: *const u32, _: u32, _: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (!self.entered) {
                self.mutex.lockUncancelable(self.base);
                self.entered = true;
            }
            return error.Canceled;
        }
        fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
            const self = active.?;
            self.unbounded_waits += 1;
            const mutex: *const u32 = @ptrCast(&self.mutex.state.raw);
            const retired: *const u32 = @ptrCast(self.retired);
            if (pointer == mutex) {
                self.mutex.state.store(.unlocked, .release);
            } else if (pointer == retired) {
                self.retired.set(self.base);
            } else self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
        }
    };
    var probe = Probe{ .base = base, .mutex = &state.mutex, .retired = &call.retired_event };
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    table.futexWaitUncancelable = Probe.waitUncancelable;
    Probe.active = &probe;
    state.io = .{ .userdata = base.userdata, .vtable = &table };

    switch (operation) {
        .write => {
            var payload: [8]u8 = "original".*;
            const writer = stream.Writer{ .call = call };
            try std.testing.expectError(error.Canceled, writer.writeMessage(&payload));
            try std.testing.expect(probe.entered);
            try std.testing.expect(call.write != null);
            @memset(&payload, 'x');
            try std.testing.expectEqualStrings(
                "original",
                call.write.?.payload(),
            );
        },
        .read => {
            const reader = stream.Reader{ .call = call };
            try std.testing.expectError(error.Canceled, reader.next());
            try std.testing.expect(probe.entered);
            try std.testing.expect(!call.read_busy.load(.acquire));
        },
    }
    try std.testing.expectEqual(@as(?anyerror, error.Canceled), call.failureValue());
    try std.testing.expect(call.cancel_requested.load(.acquire));
    try std.testing.expect(wake.event.isSet());
    try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
    try std.testing.expect(!state.mutex.tryLock());

    state.io = base;
    Probe.active = null;
    state.mutex.unlock(base);
    retire(state, call);
    try std.testing.expectEqual(references, state.refs.load(.acquire));
}

test "gRPC shared stream interruption returns before operation retirement" {
    for ([_]Operation{ .read, .write }) |operation| try exerciseInterrupted(operation);
}

test "gRPC shared write command allocation failures release partial ownership" {
    const Scenario = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const command = try call_module.Write.create(allocator, .{ .payload = "owned-payload" });
            try std.testing.expectEqualStrings("owned-payload", command.payload());
            command.release();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Scenario.run, .{});
}

test "gRPC shared write command transfers prefix-reserved storage exactly once" {
    const allocator = std.testing.allocator;
    const command = try call_module.Write.create(allocator, .{
        .payload = "transfer-payload",
    });
    const storage = command.messageStorage();
    try std.testing.expectEqual(@as(usize, 5 + "transfer-payload".len), storage.len);
    try std.testing.expectEqualStrings("transfer-payload", command.payload());
    const transferred = command.transferPayload();
    try std.testing.expectEqual(storage.ptr, transferred.ptr);
    command.release();
    allocator.free(transferred);
}
