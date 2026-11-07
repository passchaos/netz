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

fn exerciseInterrupted(operation: Operation, preserve_read: bool) !void {
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
    var call_retired = false;
    defer if (!call_retired) retire(state, call);
    const wake = try Wake.create(std.testing.allocator);
    call.setOwnerWake(wake);
    wake.release();

    const Probe = struct {
        base: std.Io,
        mutex: *std.Io.Mutex,
        retired: *std.Io.Event,
        entered: bool = false,
        mutex_held: bool = false,
        unbounded_waits: usize = 0,
        var active: ?*@This() = null;
        fn wait(_: ?*anyopaque, _: *const u32, _: u32, _: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (!self.entered) {
                self.mutex.lockUncancelable(self.base);
                self.entered = true;
                self.mutex_held = true;
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
                self.mutex_held = false;
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
    defer {
        state.io = base;
        Probe.active = null;
        if (probe.mutex_held) {
            state.mutex.unlock(base);
            probe.mutex_held = false;
        }
    }

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
            const reader = stream.Reader{ .call = call, .cancel_call_on_interrupt = !preserve_read };
            try std.testing.expectError(error.Canceled, reader.next());
            try std.testing.expect(probe.entered);
            try std.testing.expect(!call.read_busy.load(.acquire));
        },
    }
    if (operation == .read and preserve_read) {
        try std.testing.expectEqual(@as(?anyerror, null), call.failureValue());
        try std.testing.expect(!call.cancel_requested.load(.acquire));
        try std.testing.expect(!wake.event.isSet());
    } else {
        try std.testing.expectEqual(@as(?anyerror, error.Canceled), call.failureValue());
        try std.testing.expect(call.cancel_requested.load(.acquire));
        try std.testing.expect(wake.event.isSet());
    }
    try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
    const unexpected_admission = state.mutex.tryLock();
    if (unexpected_admission) {
        state.mutex.unlock(base);
        probe.mutex_held = false;
    }
    try std.testing.expect(!unexpected_admission);
    try std.testing.expect(!call.retired and !call.retired_event.isSet());

    state.io = base;
    Probe.active = null;
    state.mutex.unlock(base);
    probe.mutex_held = false;
    if (operation == .read and preserve_read) {
        // A later authority update must still be consumable after a losing
        // local read is canceled, without a new RPC or decoder reset.
        call.decoder = try @import("../../../../stream/codec.zig").Decoder.init(state.allocator, call.options.responseMessageLimit(), null, call.options.accepted_encodings);
        const wire = [_]u8{ 0, 0, 0, 0, 4, 'k', 'e', 'p', 't' };
        try call.reserveReceiveBuffer(wire.len);
        {
            state.lock();
            defer state.unlock();
            try call.appendLocked(&wire);
        }
        const reader = stream.Reader{ .call = call, .cancel_call_on_interrupt = false };
        var message = blk: {
            var resumed = reader.clone();
            defer resumed.deinit();
            try std.testing.expect(!resumed.cancel_call_on_interrupt);
            break :blk try resumed.nextWithTimeout(.fromMilliseconds(10));
        };
        defer message.deinit(state.allocator);
        try std.testing.expect(message == .message);
        try std.testing.expectEqualStrings("kept", message.message.payload);
        try std.testing.expectEqual(@as(usize, 0), call.len);
        try std.testing.expect(!call.read_busy.load(.acquire));
        try std.testing.expectEqual(@as(?anyerror, null), call.failureValue());
        try std.testing.expect(!call.cancel_requested.load(.acquire));
        try std.testing.expect(!call.retired and !call.retired_event.isSet());
    }
    retire(state, call);
    call_retired = true;
    try std.testing.expectEqual(references, state.refs.load(.acquire));
}

test "gRPC shared stream interruption returns before operation retirement" {
    for ([_]Operation{ .read, .write }) |operation| try exerciseInterrupted(operation, false);
}

test "gRPC shared stream resumable read cancellation preserves buffered message delivery" {
    try exerciseInterrupted(.read, true);
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

test "gRPC shared write command takes owned message storage without copying" {
    const allocator = std.testing.allocator;
    var message = try call_module.OwnedWriteMessage.init(
        allocator,
        "owned-command".len,
    );
    defer message.deinit();
    @memcpy(message.payload(), "owned-command");
    const storage = message.storage.?;
    const command = try call_module.Write.createOwned(
        allocator,
        &message,
        .{},
    );
    try std.testing.expect(!message.hasValue());
    try std.testing.expectEqual(storage.ptr, command.messageStorage().ptr);
    try std.testing.expectEqualStrings("owned-command", command.payload());
    command.release();
}

test "gRPC shared write command rejects foreign owned storage transactionally" {
    var backing: [64]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&backing);
    var message = try call_module.OwnedWriteMessage.init(
        fixed.allocator(),
        8,
    );
    defer message.deinit();
    try std.testing.expectError(
        error.InvalidStreamState,
        call_module.Write.createOwned(
            std.testing.allocator,
            &message,
            .{},
        ),
    );
    try std.testing.expect(message.hasValue());
}

test "gRPC shared owned write command releases every allocation failure" {
    const Scenario = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var message = try call_module.OwnedWriteMessage.init(
                allocator,
                64,
            );
            defer message.deinit();
            const command = try call_module.Write.createOwned(
                allocator,
                &message,
                .{},
            );
            defer command.release();
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Scenario.run,
        .{},
    );
}

test "gRPC shared owned write removes the serialized-payload clone" {
    const backing = std.testing.allocator;
    const payload = "caller-serialized-payload";

    var owned_counting = std.testing.FailingAllocator.init(backing, .{});
    var message = try call_module.OwnedWriteMessage.init(
        owned_counting.allocator(),
        payload.len,
    );
    @memcpy(message.payload(), payload);
    const owned_command = try call_module.Write.createOwned(
        owned_counting.allocator(),
        &message,
        .{},
    );
    owned_command.release();
    try std.testing.expectEqual(@as(usize, 2), owned_counting.allocations);

    var borrowed_counting = std.testing.FailingAllocator.init(backing, .{});
    const caller_payload = try borrowed_counting.allocator().dupe(u8, payload);
    defer borrowed_counting.allocator().free(caller_payload);
    const borrowed_command = try call_module.Write.create(
        borrowed_counting.allocator(),
        .{ .payload = caller_payload },
    );
    borrowed_command.release();
    try std.testing.expectEqual(@as(usize, 3), borrowed_counting.allocations);
    try std.testing.expectEqual(
        owned_counting.allocated_bytes + payload.len,
        borrowed_counting.allocated_bytes,
    );
}
