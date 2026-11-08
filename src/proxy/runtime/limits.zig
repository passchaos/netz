//! Bounded concurrent-connection accounting for proxy servers.

const std = @import("std");

const net = std.Io.net;

pub const Error = error{
    ConnectionLimitExceeded,
    ClientConnectionLimitExceeded,
    ClientTableFull,
};

pub const Options = struct {
    max_total: usize = 1024,
    max_per_client: usize = 64,
    /// Fixed table capacity. New clients are rejected once the table and its
    /// reusable tombstones are exhausted.
    max_clients: usize = 1024,
};

const Key = struct {
    family: net.IpAddress.Family = .ip4,
    bytes: [16]u8 = @splat(0),

    fn fromAddress(address: net.IpAddress) Key {
        return switch (address) {
            .ip4 => |ip4| .{
                .family = .ip4,
                .bytes = .{ ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3] } ++
                    ([_]u8{0} ** 12),
            },
            .ip6 => |ip6| .{ .family = .ip6, .bytes = ip6.bytes },
        };
    }

    fn eql(self: Key, other: Key) bool {
        return self.family == other.family and
            std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    fn hash(self: Key) u64 {
        return std.hash.Wyhash.hash(@intFromEnum(self.family), &self.bytes);
    }
};

const State = enum { empty, occupied, tombstone };

const Slot = struct {
    key: Key = .{},
    count: usize = 0,
    state: State = .empty,
};

pub const ConnectionLimiter = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    options: Options,
    slots: []Slot,
    total: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) std.mem.Allocator.Error!ConnectionLimiter {
        const capacity = @max(options.max_clients, 1);
        const slots = try allocator.alloc(Slot, capacity);
        @memset(slots, .{});
        return .{
            .allocator = allocator,
            .io = io,
            .options = options,
            .slots = slots,
        };
    }

    pub fn deinit(self: *ConnectionLimiter) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    pub fn acquire(
        self: *ConnectionLimiter,
        client: net.IpAddress,
    ) Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.total >= self.options.max_total) {
            return error.ConnectionLimitExceeded;
        }

        const key = Key.fromAddress(client);
        var index = self.find(key);
        if (index) |found| {
            const slot = &self.slots[found];
            if (slot.count >= self.options.max_per_client) {
                return error.ClientConnectionLimitExceeded;
            }
            slot.count += 1;
            self.total += 1;
            return;
        }

        index = self.findInsertionSlot(key) orelse
            return error.ClientTableFull;
        const slot = &self.slots[index.?];
        slot.* = .{
            .key = key,
            .count = 1,
            .state = .occupied,
        };
        self.total += 1;
    }

    pub fn release(self: *ConnectionLimiter, client: net.IpAddress) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const key = Key.fromAddress(client);
        const index = self.find(key) orelse return;
        const slot = &self.slots[index];
        std.debug.assert(slot.count > 0);
        std.debug.assert(self.total > 0);
        slot.count -= 1;
        self.total -= 1;
        if (slot.count == 0) slot.state = .tombstone;
    }

    pub fn activeConnections(self: *ConnectionLimiter) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.total;
    }

    fn find(self: *const ConnectionLimiter, key: Key) ?usize {
        const mask = self.slots.len - 1;
        var index = @as(usize, @intCast(key.hash() & mask));
        var probes: usize = 0;
        while (probes < self.slots.len) : (probes += 1) {
            switch (self.slots[index].state) {
                .empty => return null,
                .occupied => if (self.slots[index].key.eql(key)) return index,
                .tombstone => {},
            }
            index = (index + 1) & mask;
        }
        return null;
    }

    fn findInsertionSlot(
        self: *const ConnectionLimiter,
        key: Key,
    ) ?usize {
        const mask = self.slots.len - 1;
        var index = @as(usize, @intCast(key.hash() & mask));
        var first_tombstone: ?usize = null;
        var probes: usize = 0;
        while (probes < self.slots.len) : (probes += 1) {
            switch (self.slots[index].state) {
                .empty => return first_tombstone orelse index,
                .tombstone => {
                    if (first_tombstone == null) first_tombstone = index;
                },
                .occupied => if (self.slots[index].key.eql(key)) return null,
            }
            index = (index + 1) & mask;
        }
        return first_tombstone;
    }
};

test "connection limiter enforces total and per-client bounds" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var limiter = try ConnectionLimiter.init(std.testing.allocator, threaded.io(), .{
        .max_total = 3,
        .max_per_client = 2,
        .max_clients = 4,
    });
    defer limiter.deinit();

    const a = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 0 } };
    const b = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 0 } };

    try limiter.acquire(a);
    try limiter.acquire(a);
    try std.testing.expectError(
        error.ClientConnectionLimitExceeded,
        limiter.acquire(a),
    );
    try limiter.acquire(b);
    try std.testing.expectError(
        error.ConnectionLimitExceeded,
        limiter.acquire(b),
    );
    try std.testing.expectEqual(@as(usize, 3), limiter.activeConnections());

    limiter.release(a);
    limiter.release(a);
    limiter.release(b);
    try std.testing.expectEqual(@as(usize, 0), limiter.activeConnections());
}

test "connection limiter reuses tombstones for new clients" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var limiter = try ConnectionLimiter.init(std.testing.allocator, threaded.io(), .{
        .max_total = 4,
        .max_per_client = 1,
        .max_clients = 2,
    });
    defer limiter.deinit();

    const a = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 0 } };
    const b = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 0 } };
    const c = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 3 }, .port = 0 } };

    try limiter.acquire(a);
    try limiter.acquire(b);
    try std.testing.expectError(
        error.ClientTableFull,
        limiter.acquire(c),
    );
    limiter.release(a);
    try limiter.acquire(c);
    try std.testing.expectEqual(@as(usize, 2), limiter.activeConnections());
    limiter.release(b);
    limiter.release(c);
}

test "connection limiter distinguishes IPv6 clients" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var limiter = try ConnectionLimiter.init(std.testing.allocator, threaded.io(), .{
        .max_total = 4,
        .max_per_client = 1,
        .max_clients = 4,
    });
    defer limiter.deinit();

    const first = net.IpAddress{ .ip6 = .{
        .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .port = 0,
    } };
    const second = net.IpAddress{ .ip6 = .{
        .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 },
        .port = 0,
    } };
    try limiter.acquire(first);
    try limiter.acquire(second);
    try std.testing.expectError(
        error.ClientConnectionLimitExceeded,
        limiter.acquire(first),
    );
    limiter.release(first);
    limiter.release(second);
}
