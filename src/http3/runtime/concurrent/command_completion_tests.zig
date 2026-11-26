//! Drive the public owner loop at the command wait boundary, with no sleeps.
const std = @import("std");
const http3 = @import("../../mod.zig");
const concurrent = @import("../concurrent.zig");
const RequestEvent = @import("../stream/events.zig").Request;
const BodyProgress = @import("body_write.zig").Progress;
const net = std.Io.net;
const allocator = std.testing.allocator;
const actual_completion = @import("actual_completion_tests.zig");
const native_io = @import("../../../internal/testing/native_protocol_io.zig");

const Session = struct { writes: usize = 0 };
const Adapter = struct {
    pub fn maxStreams(_: *Session) usize {
        return 1;
    }
    pub fn maxBodyBuffer(_: *Session) usize {
        return 1;
    }
    pub fn peerSettings(_: *Session) http3.Settings {
        return .{};
    }
    pub fn receive(_: *Session, _: ?std.Io.Clock.Timestamp) !RequestEvent {
        return error.Timeout;
    }
    pub fn availableBody(_: *Session, _: net.IpAddress, _: u62) !usize {
        return 0;
    }
    pub fn readBody(_: *Session, _: net.IpAddress, _: u62, _: []u8) !usize {
        return 0;
    }
    pub fn startResponse(session: *Session, _: net.IpAddress, _: u62, _: http3.Response, _: ?usize, _: ?std.Io.Clock.Timestamp) !void {
        session.writes += 1;
    }
    pub fn sendInformational(_: *Session, _: net.IpAddress, _: u62, _: http3.InformationalResponse, _: ?std.Io.Clock.Timestamp) !void {}
    pub fn sendBody(_: *Session, _: net.IpAddress, _: u62, data: []const u8, fin: bool, progress: *BodyProgress, _: ?std.Io.Clock.Timestamp) !void {
        progress.committed_bytes = data.len;
        progress.fin_committed = fin;
    }
    pub fn sendCompleteResponse(_: *Session, _: net.IpAddress, _: u62, _: http3.Response, _: ?usize, _: []const u8, _: ?[]const u8, _: ?std.Io.Clock.Timestamp) !void {}
    pub fn sendCompleteResponseWithInformational(_: *Session, _: net.IpAddress, _: u62, _: []const http3.InformationalResponse, _: http3.Response, _: ?usize, _: []const u8, _: ?[]const u8, _: ?std.Io.Clock.Timestamp) !void {}
    pub fn finishTrailers(_: *Session, _: net.IpAddress, _: u62, _: []const http3.Qpack.HeaderField, _: ?std.Io.Clock.Timestamp) !void {}
    pub fn cancel(_: *Session, _: net.IpAddress, _: u62, _: u64, _: ?std.Io.Clock.Timestamp) !void {}
    pub fn goaway(_: *Session, _: u64) !void {}
};

const Engine = concurrent.Engine(Session, Adapter);
const Outcome = enum { skipped, completed };

const Probe = struct {
    backend: std.Io.Threaded,
    table: std.Io.VTable = undefined,
    engine: ?*Engine = null,
    shutdown: std.Io.Event = .unset,
    outcome: Outcome,
    expired: bool = false,
    driving: bool = false,
    owner_driven: bool = false,
    owner_error: ?anyerror = null,
    cancelable_waits: usize = 0,
    uncancelable_joins: usize = 0,

    fn io(self: *Probe) std.Io {
        const base = self.backend.io();
        self.table = base.vtable.*;
        self.table.futexWait = wait;
        self.table.futexWaitUncancelable = waitUncancelable;
        self.table.now = now;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }
    fn from(userdata: ?*anyopaque) *Probe {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        return @fieldParentPtr("backend", backend);
    }
    fn isCommand(self: *Probe, pointer: *const u32) bool {
        const engine = self.engine orelse return false;
        for (engine.commands.slice()) |command| {
            if (pointer == @as(*const u32, @ptrCast(&command.done))) return true;
        }
        return false;
    }
    fn driveOwner(self: *Probe) void {
        self.driving = true;
        defer self.driving = false;
        self.owner_driven = true;
        const engine = self.engine.?;
        self.shutdown.set(engine.io);
        const Handler = struct {
            fn run(_: *void, _: *Engine.Stream) anyerror!void {
                return error.UnexpectedHandler;
            }
        };
        var context: void = {};
        _ = engine.serve(void, &context, Handler.run) catch |err| {
            self.owner_error = err;
        };
    }
    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = from(userdata);
        if (!self.isCommand(pointer)) {
            const base = self.backend.io();
            return base.vtable.futexWait(base.userdata, pointer, expected, timeout);
        }
        self.cancelable_waits += 1;
        // Keep a legacy second cancelable cleanup observable without
        // fabricating a cancellation notification for a real backend.
        if (self.cancelable_waits > 1) {
            self.driveOwner();
            return;
        }
        self.expired = true;
    }
    fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = from(userdata);
        if (self.isCommand(pointer)) {
            self.uncancelable_joins += 1;
            self.driveOwner();
            return;
        }
        const base = self.backend.io();
        base.vtable.futexWaitUncancelable(base.userdata, pointer, expected);
    }
    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = from(userdata);
        const base = self.backend.io();
        if (clock == .awake and self.expired and !self.driving) {
            // Complete after the event's spurious wake, before the caller
            // observes expiry. Admission in that owner turn still has budget.
            if (self.outcome == .completed and !self.owner_driven) self.driveOwner();
            return base.vtable.now(base.userdata, clock).addDuration(.fromSeconds(10));
        }
        return base.vtable.now(base.userdata, clock);
    }
};

fn completion(outcome: Outcome) !void {
    var probe: Probe = .{ .backend = .init(allocator, .{}), .outcome = outcome };
    defer probe.backend.deinit();
    const base = probe.backend.io();
    const io = probe.io();
    var session: Session = .{};
    var engine = Engine.init(&session, allocator, io, .{ .shutdown = &probe.shutdown });
    defer engine.deinit();
    // A failing legacy run can leave a dangling queue pointer. Discard the
    // pointer without dereferencing it before fixture teardown.
    defer engine.commands.clearRetainingCapacity();
    probe.engine = &engine;
    const Slot = @typeInfo(@FieldType(Engine.Stream, "slot")).pointer.child;
    var slot: Slot = .{ .engine = &engine, .stream = undefined, .from = .{ .ip4 = .loopback(0) }, .stream_id = 1, .head = undefined };
    slot.head.method = @constCast("GET");
    slot.stream = .{ .engine = &engine, .slot = &slot };
    const deadline = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(5) });
    const result = slot.stream.startResponseWithDeadline(.{ .status = 200 }, 0, deadline);
    if (outcome == .completed) {
        try result;
        try std.testing.expectEqual(@as(usize, 1), session.writes);
        try std.testing.expect(slot.response_started and slot.response_finished);
    } else {
        try std.testing.expectError(error.Timeout, result);
        try std.testing.expectEqual(@as(usize, 0), session.writes);
        try std.testing.expect(!slot.response_started and !slot.response_finished);
        try std.testing.expectEqual(@as(usize, 1), probe.uncancelable_joins);
    }
    try std.testing.expect(probe.owner_driven);
    try std.testing.expectEqual(@as(usize, 1), probe.cancelable_waits);
    try std.testing.expect(engine.commands.isEmpty());
    if (probe.owner_error) |err| return err;
}

test "HTTP/3 concurrent command timeout joins skipped stack command before return" {
    try native_io.run(actual_completion.timeoutSkipped);
}
test "HTTP/3 concurrent command cancellation joins skipped stack command before return" {
    try native_io.run(actual_completion.canceledSkipped);
}
test "HTTP/3 concurrent command timeout reports racing complete response success" {
    try completion(.completed);
}
test "HTTP/3 concurrent command cancellation reports racing complete response success" {
    try native_io.run(actual_completion.canceledCompleted);
}
