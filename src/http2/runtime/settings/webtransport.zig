//! Lazy acknowledged WebTransport SETTINGS snapshots for HTTP/2 connections.
const std = @import("std");
const http2 = @import("../../mod.zig");

const Settings = http2.WebTransportSettings;

const State = struct {
    peer_current: Settings = .{},
    peer_acknowledged: Settings = .{},
    local_sent: Settings = .{},
    local_acknowledged: Settings = .{},
    local_initialized: bool = false,
};

/// Ordinary HTTP/2 connections pay one nullable pointer instead of carrying
/// four WebTransport credit snapshots. State is allocated only after the peer
/// advertises a WebTransport setting or the application updates local credit.
pub const LazyState = struct {
    state: ?*State = null,

    pub fn deinit(self: *LazyState, allocator: std.mem.Allocator) void {
        if (self.state) |state| allocator.destroy(state);
        self.* = undefined;
    }

    pub fn applyPeer(
        self: *LazyState,
        allocator: std.mem.Allocator,
        setting: http2.Setting,
    ) (http2.Error || std.mem.Allocator.Error)!void {
        if (!isWebTransport(setting.id)) return;
        var next = if (self.state) |state| state.peer_current else Settings{};
        try next.apply(setting);
        const state = try self.ensure(allocator);
        state.peer_current = next;
    }

    pub fn acknowledgePeer(self: *LazyState) void {
        const state = self.state orelse return;
        state.peer_acknowledged = state.peer_current;
    }

    pub fn peerAcknowledged(self: *const LazyState) Settings {
        const state = self.state orelse return .{};
        return state.peer_acknowledged;
    }

    pub fn prepareLocal(
        self: *LazyState,
        allocator: std.mem.Allocator,
        initial: Settings,
    ) std.mem.Allocator.Error!void {
        const state = try self.ensure(allocator);
        if (state.local_initialized) return;
        state.local_sent = initial;
        state.local_acknowledged = initial;
        state.local_initialized = true;
    }

    pub fn setLocalSent(self: *LazyState, settings: Settings) void {
        const state = self.state.?;
        std.debug.assert(state.local_initialized);
        state.local_sent = settings;
    }

    pub fn acknowledgeLocal(self: *LazyState) void {
        const state = self.state orelse return;
        if (!state.local_initialized) return;
        state.local_acknowledged = state.local_sent;
    }

    pub fn localAcknowledged(
        self: *const LazyState,
        initial: Settings,
    ) Settings {
        const state = self.state orelse return initial;
        return if (state.local_initialized)
            state.local_acknowledged
        else
            initial;
    }

    pub fn localSent(
        self: *const LazyState,
        initial: Settings,
    ) Settings {
        const state = self.state orelse return initial;
        return if (state.local_initialized) state.local_sent else initial;
    }

    fn ensure(
        self: *LazyState,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!*State {
        if (self.state) |state| return state;
        const state = try allocator.create(State);
        state.* = .{};
        self.state = state;
        return state;
    }
};

fn isWebTransport(id: http2.SettingId) bool {
    return switch (id) {
        .webtransport_enabled,
        .webtransport_initial_max_data,
        .webtransport_initial_max_stream_data_uni,
        .webtransport_initial_max_stream_data_bidi_local,
        .webtransport_initial_max_stream_data_bidi_remote,
        .webtransport_initial_max_streams_uni,
        .webtransport_initial_max_streams_bidi,
        => true,
        else => false,
    };
}

test "HTTP/2 WebTransport settings state stays lazy and preserves snapshots" {
    const allocator = std.testing.allocator;
    var lazy: LazyState = .{};
    defer lazy.deinit(allocator);
    try std.testing.expect(lazy.state == null);
    try lazy.applyPeer(allocator, .{
        .id = .initial_window_size,
        .value = 1,
    });
    try std.testing.expect(lazy.state == null);
    try lazy.applyPeer(allocator, .{
        .id = .webtransport_initial_max_data,
        .value = 10,
    });
    try std.testing.expect(lazy.state != null);
    try std.testing.expectEqual(@as(u32, 0), lazy.peerAcknowledged().max_data);
    lazy.acknowledgePeer();
    try std.testing.expectEqual(@as(u32, 10), lazy.peerAcknowledged().max_data);

    const initial = Settings{ .enabled = true, .max_data = 20 };
    try lazy.prepareLocal(allocator, initial);
    try std.testing.expectEqualDeep(initial, lazy.localAcknowledged(.{}));
    lazy.setLocalSent(.{ .enabled = true, .max_data = 30 });
    try std.testing.expectEqualDeep(initial, lazy.localAcknowledged(.{}));
    lazy.acknowledgeLocal();
    try std.testing.expectEqual(@as(u32, 30), lazy.localAcknowledged(.{}).max_data);
}
