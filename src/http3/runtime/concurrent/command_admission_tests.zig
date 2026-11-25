//! Public Stream operations keep one deadline through owner admission.
const std = @import("std");
const http3 = @import("../../mod.zig");
const concurrent = @import("../concurrent.zig");
const BodyProgress = @import("body_write.zig").Progress;
const net = std.Io.net;
const allocator = std.testing.allocator;

const Session = struct {
    writes: usize = 0,
    seen: u8 = 0,
    last_deadline: ?std.Io.Clock.Timestamp = null,
    body_failure: ?anyerror = null,
    body_prefix: usize = 0,
    body_bytes: [32]u8 = undefined,
    body_used: usize = 0,
};
const Adapter = struct {
    pub const bounded_complete = true;
    pub fn maxBodyBuffer(_: *Session) usize {
        return 1;
    }
    pub fn peerSettings(_: *Session) http3.Settings {
        return .{};
    }
    pub fn startResponse(session: *Session, _: net.IpAddress, _: u62, _: http3.Response, _: ?usize, deadline: ?std.Io.Clock.Timestamp) !void {
        session.writes += 1;
        session.seen |= 1;
        session.last_deadline = deadline;
    }
    pub fn sendInformational(session: *Session, _: net.IpAddress, _: u62, _: http3.InformationalResponse, deadline: ?std.Io.Clock.Timestamp) !void {
        session.writes += 1;
        session.seen |= 2;
        session.last_deadline = deadline;
    }
    pub fn sendBody(session: *Session, _: net.IpAddress, _: u62, data: []const u8, fin: bool, progress: *BodyProgress, deadline: ?std.Io.Clock.Timestamp) !void {
        session.writes += 1;
        session.seen |= 4;
        session.last_deadline = deadline;
        const count = if (session.body_failure != null) @min(session.body_prefix, data.len) else data.len;
        @memcpy(session.body_bytes[session.body_used..][0..count], data[0..count]);
        session.body_used += count;
        progress.committed_bytes = count;
        progress.fin_committed = fin and count == data.len;
        if (session.body_failure) |err| return err;
    }
    pub fn sendCompleteResponse(session: *Session, _: net.IpAddress, _: u62, _: http3.Response, _: ?usize, _: []const u8, _: ?[]const u8, deadline: ?std.Io.Clock.Timestamp) !void {
        session.writes += 1;
        session.seen |= 8;
        session.last_deadline = deadline;
    }
    pub fn sendCompleteResponseWithInformational(session: *Session, _: net.IpAddress, _: u62, _: []const http3.InformationalResponse, _: http3.Response, _: ?usize, _: []const u8, _: ?[]const u8, deadline: ?std.Io.Clock.Timestamp) !void {
        session.writes += 1;
        session.seen |= 16;
        session.last_deadline = deadline;
    }
    pub fn finishTrailers(session: *Session, _: net.IpAddress, _: u62, _: []const http3.Qpack.HeaderField, deadline: ?std.Io.Clock.Timestamp) !void {
        session.writes += 1;
        session.seen |= 32;
        session.last_deadline = deadline;
    }
    pub fn cancel(session: *Session, _: net.IpAddress, _: u62, _: u64, deadline: ?std.Io.Clock.Timestamp) !void {
        session.writes += 1;
        session.seen |= 64;
        session.last_deadline = deadline;
    }
};

test "HTTP/3 concurrent command rechecks original deadline before inline mutation" {
    const Probe = struct {
        backend: std.Io.Threaded,
        table: std.Io.VTable = undefined,
        reads: usize = 0,
        shift: bool = true,
        fn io(self: *@This()) std.Io {
            const base = self.backend.io();
            self.table = base.vtable.*;
            self.table.now = now;
            return .{ .userdata = base.userdata, .vtable = &self.table };
        }
        fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
            const self: *@This() = @fieldParentPtr("backend", backend);
            const base = self.backend.io();
            const value = base.vtable.now(base.userdata, clock);
            if (clock != .awake or !self.shift) return value;
            self.reads += 1;
            return if (self.reads > 1) value.addDuration(.fromSeconds(2)) else value;
        }
    };
    var probe: Probe = .{ .backend = .init(allocator, .{}) };
    defer probe.backend.deinit();
    const base = probe.backend.io();
    const io = probe.io();
    var session: Session = .{};
    const Engine = concurrent.Engine(Session, Adapter);
    var engine = Engine.init(&session, allocator, io, .{});
    defer engine.deinit();
    const Slot = @typeInfo(@FieldType(Engine.Stream, "slot")).pointer.child;
    var slot: Slot = .{ .engine = &engine, .stream = undefined, .from = .{ .ip4 = .loopback(0) }, .stream_id = 1, .head = undefined, .handler_inline = true };
    slot.head.method = @constCast("GET");
    slot.stream = .{ .engine = &engine, .slot = &slot };
    engine.inline_active = true;
    engine.inline_slot = &slot;
    const deadline = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(500) });
    try std.testing.expectError(error.Timeout, slot.stream.startResponseWithDeadline(.{ .status = 200 }, 0, deadline));
    try std.testing.expect(probe.reads >= 2);
    try std.testing.expectEqual(@as(usize, 0), session.writes);
    try std.testing.expect(!slot.response_started and !slot.response_finished);
    probe.shift = false;
    try slot.stream.startResponseWithDeadline(.{ .status = 200 }, 0, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(@as(usize, 1), session.writes);
    try std.testing.expect(slot.response_started and slot.response_finished);
}

test "HTTP/3 concurrent command adapters retain one deadline across every mutation" {
    var backend = std.Io.Threaded.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var session: Session = .{};
    const Engine = concurrent.Engine(Session, Adapter);
    var engine = Engine.init(&session, allocator, io, .{});
    defer engine.deinit();
    const Slot = @typeInfo(@FieldType(Engine.Stream, "slot")).pointer.child;
    var slot: Slot = .{ .engine = &engine, .stream = undefined, .from = .{ .ip4 = .loopback(0) }, .stream_id = 1, .head = undefined, .handler_inline = true };
    slot.head.method = @constCast("GET");
    slot.stream = .{ .engine = &engine, .slot = &slot };
    engine.inline_active = true;
    engine.inline_slot = &slot;
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    try slot.stream.startResponseWithDeadline(.{ .status = 200 }, null, deadline);
    try std.testing.expectEqualDeep(deadline, session.last_deadline.?);
    try slot.stream.writeDataWithDeadline("x", false, deadline);
    try std.testing.expectEqualDeep(deadline, session.last_deadline.?);
    try slot.stream.finishWithTrailersWithDeadline(&.{}, deadline);
    try std.testing.expectEqualDeep(deadline, session.last_deadline.?);
    try slot.stream.resetWithDeadline(0, deadline);
    try std.testing.expectEqualDeep(deadline, session.last_deadline.?);
    slot.response_started = false;
    slot.response_finished = false;
    try slot.stream.startResponseWithBodyAndInformationalWithDeadline(.{ .status = 200 }, null, "x", false, &.{.{ .status = 103 }}, deadline);
    try std.testing.expectEqualDeep(deadline, session.last_deadline.?);
    slot.response_started = false;
    slot.response_finished = false;
    try slot.stream.startResponseWithBodyAndInformationalWithDeadline(.{ .status = 200 }, 1, "x", true, &.{.{ .status = 103 }}, deadline);
    try std.testing.expectEqualDeep(deadline, session.last_deadline.?);
    slot.response_started = false;
    slot.response_finished = false;
    try slot.stream.startResponseWithBodyWithDeadline(.{ .status = 200 }, 1, "x", true, deadline);
    try std.testing.expectEqualDeep(deadline, session.last_deadline.?);
    try std.testing.expectEqual(@as(u8, 127), session.seen);
}

test "HTTP/3 concurrent DATA public progress survives partial timeout and suffix retry" {
    var backend = std.Io.Threaded.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var session: Session = .{ .body_failure = error.Timeout, .body_prefix = 2 };
    const Engine = concurrent.Engine(Session, Adapter);
    var engine = Engine.init(&session, allocator, io, .{});
    defer engine.deinit();
    const Slot = @typeInfo(@FieldType(Engine.Stream, "slot")).pointer.child;
    var slot: Slot = .{ .engine = &engine, .stream = undefined, .from = .{ .ip4 = .loopback(0) }, .stream_id = 1, .head = undefined, .handler_inline = true, .response_started = true };
    slot.head.method = @constCast("GET");
    slot.stream = .{ .engine = &engine, .slot = &slot };
    engine.inline_active = true;
    engine.inline_slot = &slot;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    var progress: Engine.Stream.DataWriteProgress = .{};
    try std.testing.expectError(error.Timeout, slot.stream.writeDataWithProgressAndDeadline("abcdef", true, &progress, deadline));
    try std.testing.expectEqual(@as(usize, 2), progress.committed_bytes);
    try std.testing.expect(progress.retryable and !progress.fin_committed);
    try std.testing.expect(!slot.response_finished);
    session.body_failure = null;
    try slot.stream.writeDataWithProgressAndDeadline("abcdef"[progress.committed_bytes..], true, &progress, deadline);
    try std.testing.expectEqual(@as(usize, 4), progress.committed_bytes);
    try std.testing.expect(progress.fin_committed and slot.response_finished);
    try std.testing.expectEqualStrings("abcdef", session.body_bytes[0..session.body_used]);
    try std.testing.expectEqualDeep(deadline, session.last_deadline.?);
    const writes = session.writes;
    progress = .{ .committed_bytes = 99, .fin_committed = true, .retryable = false };
    try std.testing.expectError(error.Timeout, slot.stream.writeDataWithProgressAndTimeout("x", false, &progress, .zero));
    try std.testing.expectEqualDeep(Engine.Stream.DataWriteProgress{}, progress);
    try std.testing.expectEqual(writes, session.writes);
}
