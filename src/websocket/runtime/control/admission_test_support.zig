const std = @import("std");
const runtime = @import("../../runtime.zig");
const websocket = @import("../../mod.zig");
const allocator = std.testing.allocator;

pub const Read = enum { frame, allocating, into };

pub fn Receiver(comptime Connection: type) type {
    return struct {
        connection: *Connection,
        io: std.Io,
        read: Read,
        started: std.Io.Event = .unset,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,
        timeout: std.Io.Duration = .fromMilliseconds(10),
        out: [32]u8 = undefined,
        result: [125]u8 = undefined,
        result_len: usize = 0,
        opcode: websocket.Opcode = .continuation,
        pub fn receive(self: *@This(), deadline: std.Io.Clock.Timestamp) !void {
            switch (self.read) {
                .frame => {
                    var frame = if (comptime @hasDecl(@TypeOf(self.connection.*), "receiveFrameAutoWithDeadline"))
                        try self.connection.receiveFrameAutoWithDeadline(deadline)
                    else
                        try self.connection.receiveFrameWithDeadline(deadline);
                    defer frame.deinit(allocator);
                    self.opcode = frame.header.opcode;
                    self.result_len = frame.payload.len;
                    @memcpy(self.result[0..frame.payload.len], frame.payload);
                },
                .allocating => {
                    var message = try self.connection.receiveMessageWithDeadline(deadline);
                    defer message.deinit(allocator);
                    self.opcode = message.opcode;
                    self.result_len = message.payload.len;
                    @memcpy(self.result[0..message.payload.len], message.payload);
                },
                .into => {
                    const message = try self.connection.receiveMessageIntoWithDeadline(&self.out, deadline);
                    self.opcode = message.opcode;
                    self.result_len = message.payload.len;
                    @memcpy(self.result[0..message.payload.len], message.payload);
                },
            }
        }
        pub fn run(self: *@This()) void {
            self.started.set(self.io);
            self.receive(.fromNow(self.io, .{ .clock = .awake, .raw = self.timeout })) catch |err| {
                self.err = err;
            };
            self.done.set(self.io);
        }
    };
}

pub fn held(task: anytype, canceled: bool) !void {
    const io = task.io;
    const connection = task.connection;
    connection.send_mutex.lockUncancelable(io);
    var locked = true;
    defer if (locked) connection.send_mutex.unlock(io);
    var future = try io.concurrent(@TypeOf(task.*).run, .{task});
    defer _ = future.cancel(io);
    try task.started.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    if (canceled) _ = future.cancel(io);
    const observed = if (task.done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(100) } })) |_| true else |err| switch (err) {
        error.Timeout => false,
        else => return err,
    };
    connection.send_mutex.unlock(io);
    locked = false;
    future.await(io);
    try std.testing.expect(observed);
    try std.testing.expectEqual(@as(?anyerror, if (canceled) error.Canceled else error.Timeout), task.err);
}

const AllocationGate = struct {
    io: std.Io,
    encountered: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    armed: bool = true,
    var active: ?*AllocationGate = null;

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, return_address: usize) ?[*]u8 {
        if (active) |gate| {
            if (gate.armed) {
                gate.armed = false;
                gate.encountered.set(gate.io);
                gate.release.waitUncancelable(gate.io);
            }
        }
        return allocator.vtable.alloc(context, len, alignment, return_address);
    }
};

/// Start the writer after the receive guard passed, while frame allocation is
/// paused. This exercises an actual admission race rather than bypassing the
/// read API's rejection of an already-retained application transaction.
pub fn heldWithPartialWriter(task: anytype, payload: []const u8) !void {
    const connection = task.connection;
    const io = task.io;
    try connection.inbuf.ensureTotalCapacityPrecise(allocator, 256);
    var gate = AllocationGate{ .io = io };
    AllocationGate.active = &gate;
    defer AllocationGate.active = null;
    var table = allocator.vtable.*;
    table.alloc = AllocationGate.alloc;
    connection.allocator = .{ .ptr = allocator.ptr, .vtable = &table };
    defer connection.allocator = allocator;
    connection.send_mutex.lockUncancelable(io);
    var locked = true;
    defer if (locked) connection.send_mutex.unlock(io);
    var future = try io.concurrent(@TypeOf(task.*).run, .{task});
    defer _ = future.cancel(io);
    defer gate.release.set(io);
    try gate.encountered.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    try runtime.testing.beginPendingMessage(connection, .binary, payload);
    var storage: [8]u8 = undefined;
    const prefix = try runtime.testing.copyPendingMessageChunk(connection, payload, 0, &storage);
    var writer = connection.stream.writer(io, &.{});
    try writer.interface.writeAll(prefix);
    runtime.testing.markPendingMessageCommitted(connection, prefix.len);
    gate.release.set(io);
    const observed = if (task.done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(100) } })) |_| true else |err| switch (err) {
        error.Timeout => false,
        else => return err,
    };
    connection.send_mutex.unlock(io);
    locked = false;
    future.await(io);
    try std.testing.expect(observed);
    try std.testing.expectEqual(@as(?anyerror, error.Timeout), task.err);
}
