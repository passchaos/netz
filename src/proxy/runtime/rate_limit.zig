//! Bounded per-client token-bucket rate limiting.

const std = @import("std");

const net = std.Io.net;

pub const Options = struct {
    max_clients: usize = 1024,
    /// Sustained tokens per second.
    tokens_per_second: u64 = 100,
    /// Maximum burst size; also the bucket capacity.
    burst: u64 = 100,
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
    state: State = .empty,
    key: Key = .{},
    tokens: u64 = 0,
    last_ns: i96 = 0,
};

pub const Limiter = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    slots: []Slot,
    options: Options,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) !Limiter {
        if (options.max_clients == 0 or options.burst == 0) {
            return error.InvalidOptions;
        }
        const slots = try allocator.alloc(Slot, options.max_clients);
        @memset(slots, .{});
        return .{
            .allocator = allocator,
            .io = io,
            .slots = slots,
            .options = options,
        };
    }

    pub fn deinit(self: *Limiter) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    /// Consume `cost` tokens for `client`. A full client table fails closed.
    pub fn allow(
        self: *Limiter,
        client: net.IpAddress,
        cost: u64,
        now_ns: i96,
    ) bool {
        if (cost > self.options.burst) return false;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const key = Key.fromAddress(client);
        const index = self.find(key) orelse
            self.insert(key, now_ns) orelse return false;
        const slot = &self.slots[index];

        const elapsed = @max(now_ns - slot.last_ns, 0);
        const refill = @as(u64, @intCast(elapsed)) *
            self.options.tokens_per_second / std.time.ns_per_s;
        slot.tokens = @min(slot.tokens + refill, self.options.burst);
        slot.last_ns = now_ns;
        if (slot.tokens < cost) return false;
        slot.tokens -= cost;
        return true;
    }

    fn find(self: *Limiter, key: Key) ?usize {
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

    fn insert(
        self: *Limiter,
        key: Key,
        now_ns: i96,
    ) ?usize {
        const mask = self.slots.len - 1;
        var index = @as(usize, @intCast(key.hash() & mask));
        var first_tombstone: ?usize = null;
        var probes: usize = 0;
        while (probes < self.slots.len) : (probes += 1) {
            switch (self.slots[index].state) {
                .empty => {
                    const target = first_tombstone orelse index;
                    self.slots[target] = .{
                        .state = .occupied,
                        .key = key,
                        .tokens = self.options.burst,
                        .last_ns = now_ns,
                    };
                    return target;
                },
                .tombstone => {
                    if (first_tombstone == null) first_tombstone = index;
                },
                .occupied => {},
            }
            index = (index + 1) & mask;
        }
        if (first_tombstone) |target| {
            self.slots[target] = .{
                .state = .occupied,
                .key = key,
                .tokens = self.options.burst,
                .last_ns = now_ns,
            };
            return target;
        }
        return null;
    }
};

test "rate limiter enforces burst and refills over time" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var limiter = try Limiter.init(allocator, io, .{
        .max_clients = 4,
        .tokens_per_second = 1000,
        .burst = 3,
    });
    defer limiter.deinit();

    const client = net.IpAddress{ .ip4 = .{
        .bytes = .{ 192, 0, 2, 1 },
        .port = 0,
    } };
    var now = std.Io.Timestamp.now(io, .awake).nanoseconds;
    try std.testing.expect(limiter.allow(client, 1, now));
    try std.testing.expect(limiter.allow(client, 1, now));
    try std.testing.expect(limiter.allow(client, 1, now));
    try std.testing.expect(!limiter.allow(client, 1, now));

    now += std.time.ns_per_ms;
    try std.testing.expect(limiter.allow(client, 1, now));
}

test "rate limiter distinguishes clients and fails closed when full" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var limiter = try Limiter.init(allocator, io, .{
        .max_clients = 2,
        .tokens_per_second = 1000,
        .burst = 1,
    });
    defer limiter.deinit();

    const first = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 0 } };
    const second = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 0 } };
    const third = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 3 }, .port = 0 } };
    const now = std.Io.Timestamp.now(io, .awake).nanoseconds;
    try std.testing.expect(limiter.allow(first, 1, now));
    try std.testing.expect(limiter.allow(second, 1, now));
    try std.testing.expect(!limiter.allow(third, 1, now));
}
