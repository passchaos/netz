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
    /// RFC 9287 is negotiated per connection. The router needs this bit before
    /// decryption so a greased short-header packet can reach the connection
    /// that advertised support, while other routes retain QUIC v1 strictness.
    accept_zero_fixed_bit: bool = false,
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
        return initAssumeValid(connection_id);
    }

    fn initAssumeValid(connection_id: []const u8) ConnectionIdKey {
        std.debug.assert(connection_id.len != 0);
        std.debug.assert(connection_id.len <= max_connection_id_len);
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
    /// Number of registered CIDs per length. Short-header packets do not carry
    /// a CID length, so routing used to scan every registered CID looking for
    /// the longest prefix match. This compact histogram lets the hot path probe
    /// only lengths that can actually match, longest first, using the map's
    /// exact key lookup.
    length_counts: [max_connection_id_len + 1]usize = .{0} ** (max_connection_id_len + 1),
    /// Cached upper bound for short-header prefix routing. Most deployments use
    /// one CID length per endpoint; keeping the current maximum avoids walking
    /// the whole 20-byte QUIC CID range before every short packet lookup.
    longest_connection_id_len: u8 = 0,

    pub fn init(allocator: std.mem.Allocator) Router {
        return .{ .map = .initContext(allocator, .{}) };
    }

    pub fn deinit(self: *Router) void {
        self.map.deinit();
        self.* = undefined;
    }

    pub fn register(self: *Router, connection_id: []const u8, route: Route) Error!void {
        const key = try ConnectionIdKey.init(connection_id);
        const entry = try self.map.getOrPut(key);
        if (entry.found_existing) return error.DuplicateConnectionId;
        entry.value_ptr.* = route;
        self.noteRegisteredLength(key.len);
    }

    pub fn registerOrReplace(self: *Router, connection_id: []const u8, route: Route) Error!void {
        const key = try ConnectionIdKey.init(connection_id);
        const entry = try self.map.getOrPut(key);
        if (!entry.found_existing) self.noteRegisteredLength(key.len);
        entry.value_ptr.* = route;
    }

    pub fn lookup(self: Router, connection_id: []const u8) Error!?Route {
        const key = try ConnectionIdKey.init(connection_id);
        if (self.length_counts[key.len] == 0) return null;
        return self.map.get(key);
    }

    pub fn unregister(self: *Router, connection_id: []const u8) Error!bool {
        const key = try ConnectionIdKey.init(connection_id);
        if (self.length_counts[key.len] == 0) return false;
        const removed = self.map.remove(key);
        if (removed) self.noteUnregisteredLength(key.len);
        return removed;
    }

    pub fn routeDatagram(self: Router, packet: []const u8) Error!?RoutedDatagram {
        return try self.routeDatagramFrom(null, packet);
    }

    pub fn routeDatagramFrom(self: Router, from: ?net.IpAddress, packet: []const u8) Error!?RoutedDatagram {
        if (packet.len == 0) return error.InvalidPacket;
        const long_header = (packet[0] & 0x80) != 0;
        const fixed_bit = (packet[0] & 0x40) != 0;
        const routed = if (long_header)
            try self.routeLongHeaderDatagram(packet)
        else
            self.routeShortHeaderDatagram(packet);
        if (routed) |candidate| {
            if (!fixed_bit and !candidate.route.accept_zero_fixed_bit) {
                return null;
            }
            try validateRoutePath(candidate.route, from);
        }
        return routed;
    }

    fn routeLongHeaderDatagram(self: Router, packet: []const u8) Error!?RoutedDatagram {
        if (packet.len < 6) return error.InvalidPacket;
        const version = std.mem.readInt(u32, packet[1..5], .big);
        if (version == 0) return null;
        const dcid_len = packet[5];
        if (dcid_len == 0) return null;
        if (dcid_len > max_connection_id_len) return error.InvalidConnectionId;
        const dcid_start: usize = 6;
        const dcid_end = dcid_start + @as(usize, dcid_len);
        if (packet.len < dcid_end) return error.InvalidPacket;
        const dcid = packet[dcid_start..dcid_end];
        if (self.length_counts[dcid_len] == 0) return null;
        const route = self.map.get(ConnectionIdKey.initAssumeValid(dcid)) orelse
            return null;
        return .{ .route = route, .destination_connection_id = dcid };
    }

    fn routeShortHeaderDatagram(self: Router, packet: []const u8) ?RoutedDatagram {
        if (packet.len <= 1) return null;
        var len = @min(
            @as(usize, self.longest_connection_id_len),
            packet.len - 1,
        );
        while (len != 0) : (len -= 1) {
            if (self.length_counts[len] == 0) continue;
            const candidate = packet[1 .. 1 + len];
            const route = self.map.get(ConnectionIdKey.initAssumeValid(candidate)) orelse continue;
            return .{ .route = route, .destination_connection_id = candidate };
        }
        return null;
    }

    pub fn count(self: Router) usize {
        return self.map.count();
    }

    fn noteRegisteredLength(self: *Router, len: u8) void {
        self.length_counts[len] += 1;
        self.longest_connection_id_len = @max(
            self.longest_connection_id_len,
            len,
        );
    }

    fn noteUnregisteredLength(self: *Router, len: u8) void {
        self.length_counts[len] -= 1;
        if (self.longest_connection_id_len != len or self.length_counts[len] != 0) {
            return;
        }
        var next = len;
        while (next != 0) {
            next -= 1;
            if (self.length_counts[next] != 0) {
                self.longest_connection_id_len = next;
                return;
            }
        }
        self.longest_connection_id_len = 0;
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
    try std.testing.expectEqual(@as(usize, 2), router.length_counts[12]);
    try std.testing.expectError(error.DuplicateConnectionId, router.register("server-cid-a", .{ .connection_index = 9 }));
    try std.testing.expect(!(try router.unregister("xy")));
    try std.testing.expectEqual(@as(usize, 0), router.length_counts[2]);

    const first = (try router.lookup("server-cid-a")).?;
    try std.testing.expectEqual(@as(usize, 0), first.connection_index);
    try std.testing.expectEqual(@as(u64, 1), first.sequence_number);
    const second = (try router.lookup("server-cid-b")).?;
    try std.testing.expectEqual(@as(usize, 1), second.connection_index);
    try std.testing.expectEqual(@as(usize, 2), router.count());

    try router.registerOrReplace("server-cid-a", .{ .connection_index = 3, .sequence_number = 7 });
    try std.testing.expectEqual(@as(usize, 2), router.length_counts[12]);
    try std.testing.expectEqual(@as(usize, 3), (try router.lookup("server-cid-a")).?.connection_index);
    try std.testing.expect(try router.unregister("server-cid-b"));
    try std.testing.expectEqual(@as(usize, 1), router.length_counts[12]);
    try std.testing.expectEqual(@as(?Route, null), try router.lookup("server-cid-b"));
    try std.testing.expectEqual(@as(usize, 1), router.count());
}

test "QUIC connection router routes short and long header datagrams" {
    const allocator = std.testing.allocator;
    var router = Router.init(allocator);
    defer router.deinit();

    try router.register("abc", .{ .connection_index = 1, .sequence_number = 10 });
    try router.register("abcdef", .{ .connection_index = 2, .sequence_number = 20 });
    try std.testing.expectEqual(@as(usize, 1), router.length_counts[3]);
    try std.testing.expectEqual(@as(usize, 1), router.length_counts[6]);
    try std.testing.expectEqual(@as(u8, 6), router.longest_connection_id_len);

    const short = [_]u8{ 0x40, 'a', 'b', 'c', 'd', 'e', 'f', 0x00, 0x01 };
    const short_route = (try router.routeDatagram(&short)).?;
    try std.testing.expectEqual(@as(usize, 2), short_route.route.connection_index);
    try std.testing.expectEqualStrings("abcdef", short_route.destination_connection_id);

    try std.testing.expect(try router.unregister("abcdef"));
    try std.testing.expectEqual(@as(usize, 0), router.length_counts[6]);
    try std.testing.expectEqual(@as(u8, 3), router.longest_connection_id_len);
    const shorter_route = (try router.routeDatagram(&short)).?;
    try std.testing.expectEqual(@as(usize, 1), shorter_route.route.connection_index);
    try std.testing.expectEqualStrings("abc", shorter_route.destination_connection_id);

    const long = [_]u8{ 0xc0, 0, 0, 0, 1, 3, 'a', 'b', 'c', 0, 0, 0 };
    const long_route = (try router.routeDatagram(&long)).?;
    try std.testing.expectEqual(@as(usize, 1), long_route.route.connection_index);
    try std.testing.expectEqualStrings("abc", long_route.destination_connection_id);

    try std.testing.expectEqual(@as(?RoutedDatagram, null), try router.routeDatagram(&.{ 0x40, 'z', 'z' }));

    const fixed_bit_clear_long = [_]u8{ 0x80, 0, 0, 0, 1, 3, 'a', 'b', 'c', 0, 0, 0 };
    try std.testing.expectEqual(@as(?RoutedDatagram, null), try router.routeDatagram(&fixed_bit_clear_long));

    const version_negotiation = [_]u8{ 0xc0, 0, 0, 0, 0, 3, 'a', 'b', 'c', 0, 0, 0 };
    try std.testing.expectEqual(@as(?RoutedDatagram, null), try router.routeDatagram(&version_negotiation));

    const zero_length_dcid = [_]u8{ 0xc0, 0, 0, 0, 1, 0, 0, 0 };
    try std.testing.expectEqual(@as(?RoutedDatagram, null), try router.routeDatagram(&zero_length_dcid));

    const fixed_bit_clear_short = [_]u8{ 0x00, 'a', 'b', 'c', 0x00 };
    try std.testing.expectEqual(@as(?RoutedDatagram, null), try router.routeDatagram(&fixed_bit_clear_short));

    try router.registerOrReplace("abc", .{
        .connection_index = 1,
        .sequence_number = 10,
        .accept_zero_fixed_bit = true,
    });
    const greased_route = (try router.routeDatagram(
        &fixed_bit_clear_short,
    )).?;
    try std.testing.expectEqual(@as(usize, 1), greased_route.route.connection_index);
    try std.testing.expectEqualStrings(
        "abc",
        greased_route.destination_connection_id,
    );

    const greased_long = [_]u8{
        0x80, 0, 0, 0, 1, 3, 'a', 'b', 'c', 0, 0, 0,
    };
    const greased_long_route = (try router.routeDatagram(
        &greased_long,
    )).?;
    try std.testing.expectEqual(
        @as(usize, 1),
        greased_long_route.route.connection_index,
    );
}

test "QUIC connection router probes short-header CID lengths without revalidation" {
    const allocator = std.testing.allocator;
    var router = Router.init(allocator);
    defer router.deinit();

    try router.register("a", .{ .connection_index = 1 });
    try router.register("abcd", .{ .connection_index = 4 });
    try router.register(&([_]u8{'x'} ** max_connection_id_len), .{ .connection_index = 20 });
    try std.testing.expectEqual(@as(u8, max_connection_id_len), router.longest_connection_id_len);

    const short = [_]u8{ 0x40, 'a', 'b', 'c', 'd', 0, 1, 2 };
    const routed = (try router.routeDatagram(&short)).?;
    try std.testing.expectEqual(@as(usize, 4), routed.route.connection_index);
    try std.testing.expectEqualStrings("abcd", routed.destination_connection_id);

    try std.testing.expect(try router.unregister("abcd"));
    const fallback = (try router.routeDatagram(&short)).?;
    try std.testing.expectEqual(@as(usize, 1), fallback.route.connection_index);
    try std.testing.expectEqualStrings("a", fallback.destination_connection_id);
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
