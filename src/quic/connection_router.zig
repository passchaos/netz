const std = @import("std");

pub const max_connection_id_len = 20;

pub const Error = error{
    InvalidConnectionId,
    DuplicateConnectionId,
} || std.mem.Allocator.Error;

pub const Route = struct {
    connection_index: usize,
    sequence_number: u64 = 0,
};

/// Fixed-size key used for routing QUIC datagrams by Destination Connection ID.
///
/// Mature QUIC endpoints (for example the implementations in `~/Work/quic-zig`
/// and `~/Work/s2n-quic`) keep an endpoint-level CID map rather than letting
/// independent connection tasks race on the UDP socket.  This compact key keeps
/// routing allocation-free after insertion and handles every QUIC v1 CID length.
pub const ConnectionIdKey = struct {
    bytes: [max_connection_id_len]u8 = .{0} ** max_connection_id_len,
    len: u8 = 0,

    pub fn init(connection_id: []const u8) Error!ConnectionIdKey {
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidConnectionId;
        var key: ConnectionIdKey = .{ .len = @intCast(connection_id.len) };
        @memcpy(key.bytes[0..connection_id.len], connection_id);
        return key;
    }

    pub fn slice(self: *const ConnectionIdKey) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Context = struct {
    pub fn hash(_: Context, key: ConnectionIdKey) u64 {
        return std.hash.Wyhash.hash(0, key.slice());
    }

    pub fn eql(_: Context, a: ConnectionIdKey, b: ConnectionIdKey) bool {
        return a.len == b.len and std.mem.eql(u8, a.slice(), b.slice());
    }
};

pub const Router = struct {
    map: std.HashMap(ConnectionIdKey, Route, Context, 80),

    pub fn init(allocator: std.mem.Allocator) Router {
        return .{ .map = .initContext(allocator, .{}) };
    }

    pub fn deinit(self: *Router) void {
        self.map.deinit();
        self.* = undefined;
    }

    pub fn register(self: *Router, connection_id: []const u8, route: Route) Error!void {
        const key = try ConnectionIdKey.init(connection_id);
        if (self.map.contains(key)) return error.DuplicateConnectionId;
        try self.map.put(key, route);
    }

    pub fn registerOrReplace(self: *Router, connection_id: []const u8, route: Route) Error!void {
        try self.map.put(try ConnectionIdKey.init(connection_id), route);
    }

    pub fn lookup(self: Router, connection_id: []const u8) Error!?Route {
        return self.map.get(try ConnectionIdKey.init(connection_id));
    }

    pub fn unregister(self: *Router, connection_id: []const u8) Error!bool {
        return self.map.remove(try ConnectionIdKey.init(connection_id));
    }

    pub fn count(self: Router) usize {
        return self.map.count();
    }
};

test "QUIC connection router maps and retires connection IDs" {
    const allocator = std.testing.allocator;
    var router = Router.init(allocator);
    defer router.deinit();

    try router.register("server-cid-a", .{ .connection_index = 0, .sequence_number = 1 });
    try router.register("server-cid-b", .{ .connection_index = 1, .sequence_number = 2 });
    try std.testing.expectError(error.DuplicateConnectionId, router.register("server-cid-a", .{ .connection_index = 9 }));

    const first = (try router.lookup("server-cid-a")).?;
    try std.testing.expectEqual(@as(usize, 0), first.connection_index);
    try std.testing.expectEqual(@as(u64, 1), first.sequence_number);
    const second = (try router.lookup("server-cid-b")).?;
    try std.testing.expectEqual(@as(usize, 1), second.connection_index);
    try std.testing.expectEqual(@as(usize, 2), router.count());

    try router.registerOrReplace("server-cid-a", .{ .connection_index = 3, .sequence_number = 7 });
    try std.testing.expectEqual(@as(usize, 3), (try router.lookup("server-cid-a")).?.connection_index);
    try std.testing.expect(try router.unregister("server-cid-b"));
    try std.testing.expectEqual(@as(?Route, null), try router.lookup("server-cid-b"));
    try std.testing.expectEqual(@as(usize, 1), router.count());
}

test "QUIC connection router validates CID lengths" {
    const allocator = std.testing.allocator;
    var router = Router.init(allocator);
    defer router.deinit();

    try std.testing.expectError(error.InvalidConnectionId, router.register("", .{ .connection_index = 0 }));
    try std.testing.expectError(error.InvalidConnectionId, router.register(&([_]u8{0xaa} ** 21), .{ .connection_index = 0 }));
}
