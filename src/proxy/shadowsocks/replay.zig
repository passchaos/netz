//! Bounded replay protection for Shadowsocks connection and packet salts.

const std = @import("std");

pub const max_salt_len: usize = 32;

pub const Options = struct {
    capacity: usize = 4096,
    /// Salts older than this window may be reused for a new connection.
    window: std.Io.Duration = .fromSeconds(600),
};

const State = enum { empty, occupied, tombstone };

const Slot = struct {
    state: State = .empty,
    hash: u64 = 0,
    salt: [max_salt_len]u8 = @splat(0),
    salt_len: u8 = 0,
    timestamp: i96 = 0,
};

pub const Cache = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    slots: []Slot,
    options: Options,
    live: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) !Cache {
        const capacity = @max(options.capacity, 1);
        const slots = try allocator.alloc(Slot, capacity);
        @memset(slots, .{});
        return .{
            .allocator = allocator,
            .io = io,
            .slots = slots,
            .options = options,
        };
    }

    pub fn deinit(self: *Cache) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    /// Return true for a fresh salt and false for a replay or a full table.
    pub fn accept(self: *Cache, salt: []const u8) bool {
        if (salt.len == 0 or salt.len > max_salt_len) return false;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        const window = self.options.window.nanoseconds;
        const hash = std.hash.Wyhash.hash(0, salt);
        const mask = self.slots.len - 1;
        var index = @as(usize, @intCast(hash & mask));
        var first_tombstone: ?usize = null;
        var probes: usize = 0;
        while (probes < self.slots.len) : (probes += 1) {
            const slot = &self.slots[index];
            switch (slot.state) {
                .empty => {
                    const target = first_tombstone orelse index;
                    self.insert(target, hash, salt, now);
                    return true;
                },
                .tombstone => {
                    if (first_tombstone == null) first_tombstone = index;
                },
                .occupied => {
                    if (slot.hash == hash and
                        std.mem.eql(u8, slot.salt[0..@as(usize, slot.salt_len)], salt))
                    {
                        if (now - slot.timestamp < window) return false;
                        slot.timestamp = now;
                        return true;
                    }
                    if (now - slot.timestamp >= window) {
                        slot.state = .tombstone;
                        self.live -= 1;
                        if (first_tombstone == null) first_tombstone = index;
                    }
                },
            }
            index = (index + 1) & mask;
        }

        if (first_tombstone) |target| {
            self.insert(target, hash, salt, now);
            return true;
        }
        return false;
    }

    pub fn count(self: *Cache) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.live;
    }

    fn insert(self: *Cache, index: usize, hash: u64, salt: []const u8, now: i96) void {
        const slot = &self.slots[index];
        if (slot.state != .occupied) self.live += 1;
        slot.* = .{
            .state = .occupied,
            .hash = hash,
            .salt = @splat(0),
            .salt_len = @intCast(salt.len),
            .timestamp = now,
        };
        @memcpy(slot.salt[0..salt.len], salt);
    }
};

test "replay cache rejects duplicates and accepts distinct salts" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cache = try Cache.init(allocator, io, .{
        .capacity = 16,
        .window = .fromSeconds(60),
    });
    defer cache.deinit();

    try std.testing.expect(cache.accept("salt-one"));
    try std.testing.expect(!cache.accept("salt-one"));
    try std.testing.expect(cache.accept("salt-two"));
    try std.testing.expectEqual(@as(usize, 2), cache.count());
}

test "replay cache expires old salts and fails closed when full" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cache = try Cache.init(allocator, io, .{
        .capacity = 1,
        .window = .fromMilliseconds(1),
    });
    defer cache.deinit();

    try std.testing.expect(cache.accept("first"));
    try std.testing.expect(!cache.accept("second"));
    std.Io.sleep(io, .fromMilliseconds(5), .awake) catch {};
    try std.testing.expect(cache.accept("second"));
    try std.testing.expectEqual(@as(usize, 1), cache.count());
}
