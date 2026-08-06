const std = @import("std");

pub const max_connection_id_len = 20;

const net = std.Io.net;

pub const Error = error{
    InvalidConnectionId,
    InvalidPacket,
    DuplicateConnectionId,
    ActiveMigrationDisabled,
} || std.mem.Allocator.Error;

pub const Route = struct {
    connection_index: usize,
    sequence_number: u64 = 0,
    peer_address: ?net.IpAddress = null,
    active_migration_disabled: bool = false,
};

pub const RoutedDatagram = struct {
    route: Route,
    destination_connection_id: []const u8,
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

    pub fn routeDatagram(self: Router, packet: []const u8) Error!?RoutedDatagram {
        return try self.routeDatagramFrom(null, packet);
    }

    pub fn routeDatagramFrom(self: Router, from: ?net.IpAddress, packet: []const u8) Error!?RoutedDatagram {
        if (packet.len == 0) return error.InvalidPacket;
        const routed = if ((packet[0] & 0x80) != 0)
            try self.routeLongHeaderDatagram(packet)
        else
            self.routeShortHeaderDatagram(packet);
        if (routed) |candidate| try validateRoutePath(candidate.route, from);
        return routed;
    }

    fn routeLongHeaderDatagram(self: Router, packet: []const u8) Error!?RoutedDatagram {
        if (packet.len < 6) return error.InvalidPacket;
        const dcid_len = packet[5];
        if (dcid_len == 0 or dcid_len > max_connection_id_len) return error.InvalidConnectionId;
        const dcid_start: usize = 6;
        const dcid_end = dcid_start + @as(usize, dcid_len);
        if (packet.len < dcid_end) return error.InvalidPacket;
        const dcid = packet[dcid_start..dcid_end];
        const route = try self.lookup(dcid) orelse return null;
        return .{ .route = route, .destination_connection_id = dcid };
    }

    fn routeShortHeaderDatagram(self: Router, packet: []const u8) ?RoutedDatagram {
        if ((packet[0] & 0x40) == 0) return null;
        var iter = self.map.iterator();
        var best: ?RoutedDatagram = null;
        while (iter.next()) |entry| {
            const cid = entry.key_ptr.slice();
            if (packet.len < 1 + cid.len) continue;
            if (!std.mem.eql(u8, packet[1 .. 1 + cid.len], cid)) continue;
            if (best == null or cid.len > best.?.destination_connection_id.len) {
                best = .{ .route = entry.value_ptr.*, .destination_connection_id = packet[1 .. 1 + cid.len] };
            }
        }
        return best;
    }

    pub fn count(self: Router) usize {
        return self.map.count();
    }
};

fn validateRoutePath(route: Route, from: ?net.IpAddress) Error!void {
    if (!route.active_migration_disabled) return;
    const expected = route.peer_address orelse return;
    const actual = from orelse return;
    if (!expected.eql(&actual)) return error.ActiveMigrationDisabled;
}

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

test "QUIC connection router routes short and long header datagrams" {
    const allocator = std.testing.allocator;
    var router = Router.init(allocator);
    defer router.deinit();

    try router.register("abc", .{ .connection_index = 1, .sequence_number = 10 });
    try router.register("abcdef", .{ .connection_index = 2, .sequence_number = 20 });

    const short = [_]u8{ 0x40, 'a', 'b', 'c', 'd', 'e', 'f', 0x00, 0x01 };
    const short_route = (try router.routeDatagram(&short)).?;
    try std.testing.expectEqual(@as(usize, 2), short_route.route.connection_index);
    try std.testing.expectEqualStrings("abcdef", short_route.destination_connection_id);

    const long = [_]u8{ 0xc0, 0, 0, 0, 1, 3, 'a', 'b', 'c', 0, 0, 0 };
    const long_route = (try router.routeDatagram(&long)).?;
    try std.testing.expectEqual(@as(usize, 1), long_route.route.connection_index);
    try std.testing.expectEqualStrings("abc", long_route.destination_connection_id);

    try std.testing.expectEqual(@as(?RoutedDatagram, null), try router.routeDatagram(&.{ 0x40, 'z', 'z' }));
}

test "QUIC connection router rejects changed paths when migration disabled" {
    const allocator = std.testing.allocator;
    var router = Router.init(allocator);
    defer router.deinit();

    const path_a = net.IpAddress{ .ip4 = .loopback(1111) };
    const path_b = net.IpAddress{ .ip4 = .loopback(2222) };
    try router.register("abc", .{
        .connection_index = 1,
        .peer_address = path_a,
        .active_migration_disabled = true,
    });

    const short = [_]u8{ 0x40, 'a', 'b', 'c', 0x00 };
    const routed = (try router.routeDatagramFrom(path_a, &short)).?;
    try std.testing.expectEqual(@as(usize, 1), routed.route.connection_index);
    try std.testing.expectError(error.ActiveMigrationDisabled, router.routeDatagramFrom(path_b, &short));

    try router.register("def", .{
        .connection_index = 2,
        .peer_address = path_a,
        .active_migration_disabled = false,
    });
    const migrated = [_]u8{ 0x40, 'd', 'e', 'f', 0x00 };
    try std.testing.expect((try router.routeDatagramFrom(path_b, &migrated)) != null);
}

test "QUIC connection router validates CID lengths" {
    const allocator = std.testing.allocator;
    var router = Router.init(allocator);
    defer router.deinit();

    try std.testing.expectError(error.InvalidConnectionId, router.register("", .{ .connection_index = 0 }));
    try std.testing.expectError(error.InvalidConnectionId, router.register(&([_]u8{0xaa} ** 21), .{ .connection_index = 0 }));
}
