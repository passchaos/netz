//! Prepare local QoS ownership before replacing a reconnect Client's identity.
const std = @import("std");
const mqtt = @import("../mod.zig");
const session = @import("../session/mod.zig");

pub fn options() session.Options {
    return .{
        .max_sessions = 1,
        .max_queued_per_session = std.math.maxInt(u16),
        .max_inflight_per_session = std.math.maxInt(u16),
    };
}

pub const FreshSession = struct {
    store: session.Store,
    handle: session.Handle,

    pub fn init(allocator: std.mem.Allocator, client_id: []const u8, now: std.Io.Timestamp) session.Error!FreshSession {
        var store = session.Store.init(allocator, options());
        errdefer store.deinit();
        // An empty identity is replaced after server assignment and never
        // reaches a persistent image.
        const opened = try store.open(client_id, client_id.len == 0, std.math.maxInt(u32), now);
        return .{ .store = store, .handle = opened.handle };
    }

    pub fn deinit(self: *FreshSession) void {
        self.store.deinit();
        self.* = undefined;
    }

    pub fn install(self: *FreshSession, client: anytype) void {
        client.outgoing.swap(&self.store);
        client.outgoing_handle = self.handle;
        client.outgoing_open = true;
        client.outgoing_session_lost = false;
    }
};

/// Own an assigned identity independently of the transient CONNACK/Connection.
/// This also validates identities learned from a reconnect snapshot.
pub fn clone(allocator: std.mem.Allocator, client_id: []const u8) mqtt.Error![]u8 {
    if (client_id.len == 0 or client_id.len > std.math.maxInt(u16)) return error.InvalidClientId;
    try mqtt.validateUtf8String(client_id);
    return allocator.dupe(u8, client_id);
}

/// Take ownership after all fallible preparation has finished.
pub fn install(client: anytype, owned_id: []u8) void {
    client.allocator.free(client.options.client_id);
    client.options.client_id = owned_id;
    client.options.value.client_id = owned_id;
}

pub fn adopt(client: anytype, client_id: []const u8) session.Error!void {
    std.debug.assert(client.options.value.client_id.len == 0);
    const owned = try clone(client.allocator, client_id);
    errdefer client.allocator.free(owned);
    var fresh = try FreshSession.init(client.allocator, client_id, std.Io.Clock.awake.now(client.io));
    defer fresh.deinit();
    fresh.install(client);
    install(client, owned);
    client.subscription_replay_index = 0;
}
