//! Real protected traffic leaves an automatic receiver grant pending.
const std = @import("std");
const webtransport = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
pub const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;
pub const Role = @import("../../session_control/test_support/handshake_pair.zig").Role;

pub fn pending(pair: *Pair, io: std.Io, comptime role: Role) !u62 {
    return pendingWithCredit(pair, io, role, 6);
}

pub fn pendingWithCredit(pair: *Pair, io: std.Io, comptime role: Role, credit: u64) !u62 {
    var settings = webtransport.defaultSettings(.{});
    settings.webtransport_initial_max_data = credit;
    try pair.initWithSettings(io, settings, settings);
    errdefer pair.deinit();
    const id = try pair.client.openBidirectionalStream();
    try pair.client.sendStream(id, if (role == .server) "123456" else "x", false);
    var buffer: [16]u8 = undefined;
    if (role == .client) {
        _ = try pair.server.readStreamWithTimeout(&buffer, .fromSeconds(1));
        try pair.server.sendStream(id, "123456", false);
    }
    const session = if (role == .client) &pair.client else &pair.server;
    pace(pair.connection(role), io, 1);
    const data = try session.readStreamWithTimeout(&buffer, .fromSeconds(1));
    try std.testing.expect(data == .data and data.data.bytes == 6);
    try std.testing.expectEqual(@as(?u64, credit + 6), session.streams.flow.?.automaticDataGrant());
    return id;
}

pub fn pace(connection: *quic.one_rtt.Connection, io: std.Io, rate: u64) void {
    connection.pacer.enabled = true;
    connection.setMaxPacingRateBytesPerSecond(rate);
    quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(io).nanoseconds));
}

pub fn withinBudget(io: std.Io, comptime function: anytype, args: anytype) !void {
    return withinBudgetFor(io, .fromSeconds(1), function, args);
}

pub fn withinBudgetFor(
    io: std.Io,
    budget: std.Io.Duration,
    comptime function: anytype,
    args: anytype,
) !void {
    const Wake = union(enum) { done: anyerror!void, expired: std.Io.Cancelable!void };
    var storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &storage);
    defer select.cancelDiscard();
    try select.concurrent(.done, function, args);
    try select.concurrent(.expired, std.Io.sleep, .{ io, budget, std.Io.Clock.awake });
    switch (try select.await()) {
        .done => |result| try result,
        .expired => |result| {
            try result;
            return error.TestUnexpectedResult;
        },
    }
}
