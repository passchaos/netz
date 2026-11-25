//! The public owner retry loop must never resend a committed DATA prefix.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const h3 = @import("../../mod.zig");
const concurrent = @import("../concurrent.zig");
const Progress = @import("body_write.zig").Progress;
const tracked = @hasDecl(runtime.HandshakeServerSession.ConcurrentStream, "DataWriteProgress");
const Address = std.Io.net.IpAddress;
const Session = struct { blocked: bool = true, bytes: [16]u8 = undefined, used: usize = 0, fins: usize = 0, attempts: usize = 0 };
const Adapter = struct {
    pub fn maxBodyBuffer(_: *Session) usize {
        return 1;
    }
    pub fn peerSettings(_: *Session) h3.Settings {
        return .{};
    }
    pub fn startResponse(_: *Session, _: Address, _: u62, _: h3.Response, _: ?usize, _: ?std.Io.Clock.Timestamp) !void {}
    pub fn sendInformational(_: *Session, _: Address, _: u62, _: h3.InformationalResponse, _: ?std.Io.Clock.Timestamp) !void {}
    pub fn sendCompleteResponse(_: *Session, _: Address, _: u62, _: h3.Response, _: ?usize, _: []const u8, _: ?[]const u8, _: ?std.Io.Clock.Timestamp) !void {}
    pub fn sendCompleteResponseWithInformational(_: *Session, _: Address, _: u62, _: []const h3.InformationalResponse, _: h3.Response, _: ?usize, _: []const u8, _: ?[]const u8, _: ?std.Io.Clock.Timestamp) !void {}
    pub fn finishTrailers(_: *Session, _: Address, _: u62, _: []const h3.Qpack.HeaderField, _: ?std.Io.Clock.Timestamp) !void {}
    pub fn cancel(_: *Session, _: Address, _: u62, _: u64, _: ?std.Io.Clock.Timestamp) !void {}
    pub const sendBody = if (tracked) sendTracked else sendLegacy;
    fn sendLegacy(session: *Session, _: Address, _: u62, data: []const u8, fin: bool, _: ?std.Io.Clock.Timestamp) !void {
        var progress: Progress = .{};
        return send(session, data, fin, &progress);
    }
    fn sendTracked(session: *Session, _: Address, _: u62, data: []const u8, fin: bool, progress: *Progress, _: ?std.Io.Clock.Timestamp) !void {
        return send(session, data, fin, progress);
    }
    fn send(session: *Session, data: []const u8, fin: bool, progress: *Progress) !void {
        session.attempts += 1;
        const count = if (session.blocked) @min(2, data.len) else data.len;
        @memcpy(session.bytes[session.used..][0..count], data[0..count]);
        session.used += count;
        progress.committed_bytes = count;
        progress.fin_committed = fin and count == data.len;
        if (progress.fin_committed) session.fins += 1;
        if (session.blocked) return error.CongestionLimited;
    }
};
const Engine = concurrent.Engine(Session, Adapter);
test "HTTP/3 concurrent DATA public owner retry preserves its committed prefix" {
    const allocator = std.testing.allocator;
    var backend = std.Io.Threaded.init(allocator, .{});
    defer backend.deinit();
    var session: Session = .{};
    var engine = Engine.init(&session, allocator, backend.io(), .{});
    defer engine.deinit();
    const Slot = @typeInfo(@FieldType(Engine.Stream, "slot")).pointer.child;
    var slot: Slot = .{ .engine = &engine, .stream = undefined, .from = .{ .ip4 = .loopback(0) }, .stream_id = 1, .head = undefined, .response_started = true, .handler_inline = true };
    slot.head.method = @constCast("GET");
    slot.stream = .{ .engine = &engine, .slot = &slot };
    engine.inline_active = true;
    engine.inline_slot = &slot;
    const Pump = struct {
        fn run(_: *Engine, raw: *anyopaque) !void {
            const sender: *Session = @ptrCast(@alignCast(raw));
            sender.blocked = false;
        }
    };
    engine.inline_pump = Pump.run;
    engine.inline_pump_state = &session;
    try slot.stream.writeDataWithDeadline("abcdef", true, .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(5) }));
    try std.testing.expectEqualStrings("abcdef", session.bytes[0..session.used]);
    try std.testing.expectEqual(@as(usize, 2), session.attempts);
    try std.testing.expectEqual(@as(usize, 1), session.fins);
    try std.testing.expect(slot.response_finished);
}
