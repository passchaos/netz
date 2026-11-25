//! Public Stream operations keep one deadline through owner admission.
const std = @import("std");
const http3 = @import("../../mod.zig");
const concurrent = @import("../concurrent.zig");
const net = std.Io.net;
const allocator = std.testing.allocator;

const Session = struct { writes: usize = 0 };
const Adapter = struct {
    pub fn maxBodyBuffer(_: *Session) usize {
        return 1;
    }
    pub fn peerSettings(_: *Session) http3.Settings {
        return .{};
    }
    pub fn startResponse(session: *Session, _: net.IpAddress, _: u62, _: http3.Response, _: ?usize) !void {
        session.writes += 1;
    }
    pub fn sendInformational(session: *Session, _: net.IpAddress, _: u62, _: http3.InformationalResponse, _: ?std.Io.Clock.Timestamp) !void {
        session.writes += 1;
    }
    pub fn sendBody(session: *Session, _: net.IpAddress, _: u62, _: []const u8, _: bool) !void {
        session.writes += 1;
    }
    pub fn sendCompleteResponse(session: *Session, _: net.IpAddress, _: u62, _: http3.Response, _: ?usize, _: []const u8, _: ?[]const u8) !void {
        session.writes += 1;
    }
    pub fn sendCompleteResponseWithInformational(session: *Session, _: net.IpAddress, _: u62, _: []const http3.InformationalResponse, _: http3.Response, _: ?usize, _: []const u8, _: ?[]const u8) !void {
        session.writes += 1;
    }
    pub fn finishTrailers(session: *Session, _: net.IpAddress, _: u62, _: []const http3.Qpack.HeaderField) !void {
        session.writes += 1;
    }
    pub fn cancel(session: *Session, _: net.IpAddress, _: u62, _: u64) !void {
        session.writes += 1;
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
