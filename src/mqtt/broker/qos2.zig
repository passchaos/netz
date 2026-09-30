//! Bounded inbound QoS 2 transaction storage for the live broker.
//!
//! A QoS 2 PUBLISH must not be routed until PUBREL. The runtime tracks the
//! protocol receive window in connection-local state; this store owns the
//! application
//! bytes needed to route exactly once at that later control packet.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");
const persistence = @import("../persistence/codec.zig");
const router = @import("../router.zig");

pub const Error = mqtt.Error || error{
    PendingLimitExceeded,
    ReceiveMaximumExceeded,
};

pub const Key = packed struct(u80) {
    publisher_id: router.SubscriberId,
    packet_id: u16,
};

const PendingStorageCache = struct {
    const max_cacheable_storage: usize = 64 * 1024;
    const max_cached_bytes: usize = 1024 * 1024;
    const class_count: usize = @ctz(max_cacheable_storage) + 1;
    const link_size = @sizeOf(usize);

    allocator: std.mem.Allocator,
    max_blocks: usize,
    heads: [class_count]?[*]u8 = .{null} ** class_count,
    block_count: usize = 0,
    byte_count: usize = 0,

    fn init(
        allocator: std.mem.Allocator,
        max_blocks: usize,
    ) PendingStorageCache {
        return .{ .allocator = allocator, .max_blocks = max_blocks };
    }

    fn deinit(self: *PendingStorageCache) void {
        for (self.heads, 0..) |maybe_head, size_class| {
            var head = maybe_head;
            const storage_len = @as(usize, 1) << @intCast(size_class);
            while (head) |pointer| {
                const storage = pointer[0..storage_len];
                const next_address = std.mem.readInt(
                    usize,
                    storage[0..link_size],
                    .native,
                );
                head = if (next_address == 0)
                    null
                else
                    @ptrFromInt(next_address);
                self.allocator.free(storage);
            }
        }
        self.* = undefined;
    }

    fn acquire(
        self: *PendingStorageCache,
        required_len: usize,
    ) std.mem.Allocator.Error![]u8 {
        if (required_len == 0) return self.allocator.alloc(u8, 0);
        const storage_len = if (required_len <= max_cacheable_storage)
            std.math.ceilPowerOfTwo(usize, required_len) catch unreachable
        else
            required_len;
        if (storage_len <= max_cacheable_storage) {
            const size_class: usize = @ctz(storage_len);
            if (self.heads[size_class]) |pointer| {
                const storage = pointer[0..storage_len];
                const next_address = std.mem.readInt(
                    usize,
                    storage[0..link_size],
                    .native,
                );
                self.heads[size_class] = if (next_address == 0)
                    null
                else
                    @ptrFromInt(next_address);
                self.block_count -= 1;
                self.byte_count -= storage.len;
                return storage;
            }
        }
        return self.allocator.alloc(u8, storage_len);
    }

    fn release(self: *PendingStorageCache, storage: []u8) void {
        if (storage.len >= link_size and
            storage.len <= max_cacheable_storage and
            std.math.isPowerOfTwo(storage.len) and
            self.block_count < self.max_blocks and
            storage.len <= max_cached_bytes -
                @min(max_cached_bytes, self.byte_count))
        {
            const size_class: usize = @ctz(storage.len);
            const next_address = if (self.heads[size_class]) |head|
                @intFromPtr(head)
            else
                0;
            std.mem.writeInt(
                usize,
                storage[0..link_size],
                next_address,
                .native,
            );
            self.heads[size_class] = storage.ptr;
            self.block_count += 1;
            self.byte_count += storage.len;
            return;
        }
        self.allocator.free(storage);
    }
};

pub const Pending = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    allocation_len: usize,
    topic_len: usize,
    retain: bool,
    /// Retained-source identity captured from the first PUBLISH. The strings
    /// are MQTT u16-bounded and the Store's transaction count bounds their
    /// aggregate memory even if a peer stalls before PUBREL.
    source_client_id: ?[]u8,
    source_username: ?[]u8,
    source_listener_id: ?u64,
    properties: []mqtt.Property,
    stored_at_ns: i96,
    expiry_interval: ?u32,

    pub fn create(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) Error!Pending {
        return createWithSource(allocator, publish, null, null, null, now);
    }

    pub fn createWithSource(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
        source_client_id: ?[]const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        now: std.Io.Timestamp,
    ) Error!Pending {
        return createWithSourceAndCache(
            allocator,
            null,
            publish,
            source_client_id,
            source_username,
            source_listener_id,
            now,
        );
    }

    fn createWithSourceAndCache(
        allocator: std.mem.Allocator,
        cache: ?*PendingStorageCache,
        publish: mqtt.Publish,
        source_client_id: ?[]const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        now: std.Io.Timestamp,
    ) Error!Pending {
        if (source_client_id == null and
            (source_username != null or source_listener_id != null))
        {
            return error.InvalidProperty;
        }
        if (source_client_id) |value| {
            if (value.len > std.math.maxInt(u16)) return error.InvalidUtf8;
            try mqtt.validateUtf8String(value);
        }
        if (source_username) |value| {
            if (value.len > std.math.maxInt(u16)) return error.InvalidUtf8;
            try mqtt.validateUtf8String(value);
        }
        const bytes_len = std.math.add(
            usize,
            publish.topic.len,
            publish.payload.len,
        ) catch return error.OutOfMemory;
        const source_client_id_len = if (source_client_id) |value|
            value.len
        else
            0;
        const source_username_len = if (source_username) |value|
            value.len
        else
            0;
        const allocation_len = std.math.add(
            usize,
            std.math.add(
                usize,
                bytes_len,
                source_client_id_len,
            ) catch return error.OutOfMemory,
            source_username_len,
        ) catch return error.OutOfMemory;
        const allocation = if (cache) |value|
            try value.acquire(allocation_len)
        else
            try allocator.alloc(u8, allocation_len);
        errdefer if (cache) |value|
            value.release(allocation)
        else
            allocator.free(allocation);
        const bytes = allocation[0..bytes_len];
        @memcpy(bytes[0..publish.topic.len], publish.topic);
        @memcpy(bytes[publish.topic.len..], publish.payload);
        var identity_offset = bytes_len;
        const source_client_id_owned = if (source_client_id) |value| blk: {
            const owned = allocation[identity_offset..][0..value.len];
            @memcpy(owned, value);
            identity_offset += value.len;
            break :blk owned;
        } else null;
        const source_username_owned = if (source_username) |value| blk: {
            const owned = allocation[identity_offset..][0..value.len];
            @memcpy(owned, value);
            identity_offset += value.len;
            break :blk owned;
        } else null;
        std.debug.assert(identity_offset <= allocation.len);
        const property_result = owned_properties.clone(
            allocator,
            publish.properties,
            keepPendingProperty,
        ) catch |err| switch (err) {
            error.OwnedPropertyLimitExceeded => return error.PendingLimitExceeded,
            else => return @errorCast(err),
        };
        return .{
            .allocator = allocator,
            .bytes = bytes,
            .allocation_len = allocation.len,
            .topic_len = publish.topic.len,
            .retain = publish.retain,
            .source_client_id = source_client_id_owned,
            .source_username = source_username_owned,
            .source_listener_id = source_listener_id,
            .properties = property_result.properties,
            .stored_at_ns = now.nanoseconds,
            .expiry_interval = mqtt.messageExpiryInterval(
                publish.properties,
            ),
        };
    }

    pub fn deinit(self: *Pending) void {
        self.deinitWithCache(null);
    }

    fn deinitWithCache(
        self: *Pending,
        cache: ?*PendingStorageCache,
    ) void {
        owned_properties.deinit(self.allocator, self.properties);
        const allocation = self.bytes.ptr[0..self.allocation_len];
        if (cache) |value|
            value.release(allocation)
        else
            self.allocator.free(allocation);
        self.* = undefined;
    }

    pub fn asPublish(
        self: Pending,
        packet_id: u16,
        now: std.Io.Timestamp,
        adjusted_properties: *std.ArrayList(mqtt.Property),
    ) Error!?mqtt.Publish {
        const remaining = remainingExpiry(
            self.expiry_interval,
            self.stored_at_ns,
            now.nanoseconds,
        );
        if (remaining == 0) return null;
        try adjusted_properties.ensureTotalCapacity(
            self.allocator,
            self.properties.len,
        );
        for (self.properties) |property| {
            if (property == .four_byte and
                property.four_byte.id == .message_expiry_interval)
            {
                adjusted_properties.appendAssumeCapacity(.{
                    .four_byte = .{
                        .id = .message_expiry_interval,
                        .value = remaining.?,
                    },
                });
            } else {
                adjusted_properties.appendAssumeCapacity(property);
            }
        }
        return mqtt.Publish{
            .dup = false,
            .qos = .exactly_once,
            .retain = self.retain,
            .topic = self.bytes[0..self.topic_len],
            .packet_id = packet_id,
            .properties = adjusted_properties.items,
            .payload = self.bytes[self.topic_len..],
        };
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    maximum: usize,
    entries: std.AutoHashMapUnmanaged(Key, Pending) = .empty,
    storage_cache: PendingStorageCache,

    pub fn init(
        allocator: std.mem.Allocator,
        maximum: usize,
    ) std.mem.Allocator.Error!Store {
        var self = Store{
            .allocator = allocator,
            .maximum = maximum,
            .storage_cache = .init(allocator, maximum),
        };
        errdefer self.deinit();
        try self.entries.ensureTotalCapacity(
            allocator,
            @intCast(maximum),
        );
        return self;
    }

    pub fn deinit(self: *Store) void {
        var values = self.entries.valueIterator();
        while (values.next()) |pending| pending.deinit();
        self.entries.deinit(self.allocator);
        self.storage_cache.deinit();
        self.* = undefined;
    }

    pub fn count(self: Store) usize {
        return self.entries.count();
    }

    /// Store a new transaction, or validate an MQTT retransmission.
    ///
    /// Until PUBREL arrives, MQTT requires every subsequent PUBLISH with the
    /// same Packet Identifier to receive PUBREC without delivering another
    /// Application Message. Preserve the first transaction even when a broken
    /// sender clears DUP or changes later bytes; replacing it would make the
    /// exactly-once result depend on a retransmission race.
    pub fn record(
        self: *Store,
        publisher_id: router.SubscriberId,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) !bool {
        return self.recordWithSource(
            publisher_id,
            publish,
            null,
            null,
            null,
            now,
        );
    }

    pub fn recordWithSource(
        self: *Store,
        publisher_id: router.SubscriberId,
        publish: mqtt.Publish,
        source_client_id: ?[]const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        now: std.Io.Timestamp,
    ) !bool {
        const packet_id = publish.packet_id orelse
            return error.InvalidPacketIdentifier;
        const key = Key{
            .publisher_id = publisher_id,
            .packet_id = packet_id,
        };
        if (self.entries.contains(key)) return false;
        if (self.entries.count() >= self.maximum) {
            return error.ReceiveMaximumExceeded;
        }
        const pending = try Pending.createWithSourceAndCache(
            self.allocator,
            &self.storage_cache,
            publish,
            source_client_id,
            source_username,
            source_listener_id,
            now,
        );
        self.entries.putAssumeCapacityNoClobber(key, pending);
        return true;
    }

    pub fn take(
        self: *Store,
        publisher_id: router.SubscriberId,
        packet_id: u16,
    ) ?Pending {
        const removed = self.entries.fetchRemove(.{
            .publisher_id = publisher_id,
            .packet_id = packet_id,
        }) orelse return null;
        return removed.value;
    }

    pub fn recycle(self: *Store, pending: *Pending) void {
        pending.deinitWithCache(&self.storage_cache);
    }

    pub fn removePublisher(
        self: *Store,
        publisher_id: router.SubscriberId,
    ) usize {
        var removed: usize = 0;
        var iterator = self.entries.iterator();
        while (iterator.next()) |entry| {
            if (entry.key_ptr.publisher_id != publisher_id) continue;
            var pending = entry.value_ptr.*;
            const key = entry.key_ptr.*;
            std.debug.assert(self.entries.remove(key));
            self.recycle(&pending);
            removed += 1;
            // Removal invalidates the iterator's traversal state. Restarting is
            // bounded by this connection's Receive Maximum and happens only at
            // disconnect, not on the publish hot path.
            iterator = self.entries.iterator();
        }
        return removed;
    }

    pub fn writeSnapshot(
        self: *Store,
        out: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        now: std.Io.Timestamp,
        context: anytype,
        comptime publisherExists: anytype,
    ) (Error || persistence.Error)!void {
        return self.writeSnapshotMode(
            out,
            allocator,
            now,
            context,
            publisherExists,
            false,
        );
    }

    /// Persist durable inbound QoS 2 transactions from a live checkpoint.
    /// Transactions owned by transient Sessions are connection-scoped and are
    /// omitted; a broker restart cannot resume those clients or their Packet
    /// Identifier namespace.
    pub fn writeLiveSnapshot(
        self: *Store,
        out: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        now: std.Io.Timestamp,
        context: anytype,
        comptime publisherExists: anytype,
    ) (Error || persistence.Error)!void {
        return self.writeSnapshotMode(
            out,
            allocator,
            now,
            context,
            publisherExists,
            true,
        );
    }

    fn writeSnapshotMode(
        self: *Store,
        out: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        now: std.Io.Timestamp,
        context: anytype,
        comptime publisherExists: anytype,
        skip_transient_publishers: bool,
    ) (Error || persistence.Error)!void {
        var snapshot_count: u32 = 0;
        var iterator = self.entries.iterator();
        while (iterator.next()) |entry| {
            if (!publisherExists(context, entry.key_ptr.publisher_id)) {
                // Live checkpoints omit every transaction whose owner is not
                // a persistent Session. Broker canonicalization gives even a
                // transient connection a route-shaped identifier, so the tag
                // alone cannot distinguish durable from transient ownership.
                if (skip_transient_publishers) continue;
                return error.CorruptSnapshot;
            }
            if (remainingExpiryNs(
                entry.value_ptr.*,
                now.nanoseconds,
            ) == 0) continue;
            snapshot_count = std.math.add(
                u32,
                snapshot_count,
                1,
            ) catch return error.SnapshotLimitExceeded;
        }
        try persistence.appendInt(out, allocator, u32, snapshot_count);
        iterator = self.entries.iterator();
        while (iterator.next()) |entry| {
            if (!publisherExists(context, entry.key_ptr.publisher_id) and
                skip_transient_publishers) continue;
            const pending = entry.value_ptr.*;
            const remaining_ns = remainingExpiryNs(
                pending,
                now.nanoseconds,
            );
            if (remaining_ns == 0) continue;
            try persistence.appendInt(
                out,
                allocator,
                u64,
                entry.key_ptr.publisher_id,
            );
            try persistence.appendInt(
                out,
                allocator,
                u16,
                entry.key_ptr.packet_id,
            );
            try persistence.appendBlob(
                out,
                allocator,
                pending.bytes[0..pending.topic_len],
            );
            try persistence.appendBlob(
                out,
                allocator,
                pending.bytes[pending.topic_len..],
            );
            try persistence.appendBool(out, allocator, pending.retain);
            try persistence.appendBool(
                out,
                allocator,
                pending.source_client_id != null,
            );
            if (pending.source_client_id) |value| {
                try persistence.appendBlob(out, allocator, value);
            }
            try persistence.appendBool(
                out,
                allocator,
                pending.source_username != null,
            );
            if (pending.source_username) |value| {
                try persistence.appendBlob(out, allocator, value);
            }
            try persistence.appendOptionalInt(
                out,
                allocator,
                u64,
                pending.source_listener_id,
            );
            try persistence.appendOptionalInt(
                out,
                allocator,
                u64,
                remaining_ns,
            );
            try persistence.appendProperties(
                out,
                allocator,
                pending.properties,
            );
        }
    }

    pub fn restoreSnapshot(
        self: *Store,
        cursor: *persistence.Cursor,
        restore_now: std.Io.Timestamp,
        downtime_ns: i96,
        context: anytype,
        comptime publisherExists: anytype,
    ) (Error || persistence.Error)!void {
        const snapshot_count = try cursor.readInt(u32);
        if (snapshot_count > self.maximum) {
            return error.ReceiveMaximumExceeded;
        }
        for (0..snapshot_count) |_| {
            const publisher_id = try cursor.readInt(u64);
            const packet_id = try cursor.readInt(u16);
            const topic = try cursor.readBlob();
            const payload = try cursor.readBlob();
            const retain = try cursor.readBool();
            const source_client_id = if (try cursor.readBool())
                try cursor.readBlob()
            else
                null;
            const source_username = if (try cursor.readBool())
                try cursor.readBlob()
            else
                null;
            const source_listener_id = try cursor.readOptionalInt(u64);
            const saved_remaining_ns = try cursor.readOptionalInt(u64);
            const properties = try cursor.readProperties(self.allocator);
            defer self.allocator.free(properties);
            if (!publisherExists(context, publisher_id) or packet_id == 0 or
                (mqtt.messageExpiryInterval(properties) == null) !=
                    (saved_remaining_ns == null))
            {
                return error.CorruptSnapshot;
            }
            try mqtt.validateTopicName(topic);
            try mqtt.validatePublishProperties(properties);
            if (mqtt.subscriptionIdentifier(properties) != null) {
                return error.CorruptSnapshot;
            }
            const remaining_ns = remainingAfterDowntimeNs(
                saved_remaining_ns,
                downtime_ns,
            );
            if (remaining_ns == 0) continue;
            const publish = mqtt.Publish{
                .dup = false,
                .qos = .exactly_once,
                .retain = retain,
                .topic = topic,
                .packet_id = packet_id,
                .properties = properties,
                .payload = payload,
            };
            _ = try self.recordWithSource(
                publisher_id,
                publish,
                source_client_id,
                source_username,
                source_listener_id,
                restore_now,
            );
            if (remaining_ns) |remaining| {
                const stored = self.entries.getPtr(.{
                    .publisher_id = publisher_id,
                    .packet_id = packet_id,
                }) orelse return error.CorruptSnapshot;
                const interval = stored.expiry_interval orelse
                    return error.CorruptSnapshot;
                const lifetime_ns = @as(u64, interval) *
                    std.time.ns_per_s;
                if (remaining > lifetime_ns) {
                    return error.CorruptSnapshot;
                }
                stored.stored_at_ns = restore_now.nanoseconds -
                    @as(i96, lifetime_ns - remaining);
            }
        }
    }

    pub fn swap(self: *Store, other: *Store) void {
        const value = self.*;
        self.* = other.*;
        other.* = value;
    }
};

fn keepPendingProperty(property: mqtt.Property) bool {
    // Topic Alias is scoped to the publisher connection. `readBrokerEvent`
    // has already expanded the full Topic Name before this transaction is
    // stored.
    return !(property == .two_byte and
        property.two_byte.id == .topic_alias);
}

fn sessionRouteId(id: router.SubscriberId) ?u64 {
    const tag: u64 = 1 << 63;
    if ((id & tag) == 0) return null;
    return id & ~tag;
}

fn remainingExpiry(
    interval: ?u32,
    stored_at_ns: i96,
    now_ns: i96,
) ?u32 {
    const value = interval orelse return null;
    if (value == 0) return 0;
    const elapsed_ns = @max(now_ns - stored_at_ns, 0);
    const expiry_ns = @as(i96, value) * std.time.ns_per_s;
    if (elapsed_ns >= expiry_ns) return 0;
    const elapsed_seconds: u32 = @intCast(
        @divTrunc(elapsed_ns, std.time.ns_per_s),
    );
    return value - elapsed_seconds;
}

fn remainingExpiryNs(pending: Pending, now_ns: i96) ?u64 {
    const interval = pending.expiry_interval orelse return null;
    const lifetime_ns = @as(u64, interval) * std.time.ns_per_s;
    const elapsed_ns: u64 = @intCast(@max(
        now_ns - pending.stored_at_ns,
        0,
    ));
    return lifetime_ns -| elapsed_ns;
}

fn remainingAfterDowntimeNs(
    remaining: ?u64,
    downtime_ns: i96,
) ?u64 {
    const value = remaining orelse return null;
    const elapsed: u64 = @intCast(@min(
        @max(downtime_ns, 0),
        std.math.maxInt(u64),
    ));
    return value -| elapsed;
}

test "QoS 2 pending storage cache respects the transaction bound" {
    const allocator = std.testing.allocator;
    {
        var cache = PendingStorageCache.init(allocator, 2);
        defer cache.deinit();

        const first = try cache.acquire(80);
        const second = try cache.acquire(80);
        const excess = try cache.acquire(80);
        cache.release(first);
        cache.release(second);
        cache.release(excess);
        try std.testing.expectEqual(@as(usize, 2), cache.block_count);
        try std.testing.expectEqual(@as(usize, 256), cache.byte_count);
    }
    {
        var cache = PendingStorageCache.init(
            allocator,
            std.math.maxInt(usize),
        );
        defer cache.deinit();
        const block_count = PendingStorageCache.max_cached_bytes /
            PendingStorageCache.max_cacheable_storage;
        var blocks: [block_count + 1][]u8 = undefined;
        for (&blocks) |*storage| {
            storage.* = try cache.acquire(
                PendingStorageCache.max_cacheable_storage,
            );
        }
        for (blocks) |storage| cache.release(storage);
        try std.testing.expectEqual(block_count, cache.block_count);
        try std.testing.expectEqual(
            PendingStorageCache.max_cached_bytes,
            cache.byte_count,
        );
    }
}

test "QoS 2 pending coallocates message and source identity bytes" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );
    var pending = try Pending.createWithSource(
        failing.allocator(),
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "coallocated/topic",
            .packet_id = 7,
            .payload = "payload",
        },
        "client",
        "user",
        1883,
        .zero,
    );
    defer pending.deinit();

    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(
        @intFromPtr(pending.bytes.ptr) + pending.bytes.len,
        @intFromPtr(pending.source_client_id.?.ptr),
    );
    try std.testing.expectEqual(
        @intFromPtr(pending.source_client_id.?.ptr) +
            pending.source_client_id.?.len,
        @intFromPtr(pending.source_username.?.ptr),
    );
    try std.testing.expectEqualStrings(
        "coallocated/topic",
        pending.bytes[0..pending.topic_len],
    );
    try std.testing.expectEqualStrings(
        "payload",
        pending.bytes[pending.topic_len..],
    );
}

test "QoS 2 pending coallocation is failure-safe with properties" {
    const Context = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var properties = [_]mqtt.Property{.{ .utf8_pair = .{
                .id = .user_property,
                .key = "source",
                .value = "test",
            } }};
            var pending = try Pending.createWithSource(
                allocator,
                .{
                    .dup = false,
                    .qos = .exactly_once,
                    .retain = false,
                    .topic = "failure/topic",
                    .packet_id = 9,
                    .properties = &properties,
                    .payload = "payload",
                },
                "client",
                "user",
                1883,
                .zero,
            );
            pending.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Context.run,
        .{},
    );
}

test "QoS 2 store reuses bounded pending storage" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var store = try Store.init(failing.allocator(), 2);
    defer store.deinit();
    const first_publish = mqtt.Publish{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "cached/topic",
        .packet_id = 7,
        .payload = "payload",
    };
    try std.testing.expect(try store.recordWithSource(
        10,
        first_publish,
        "client",
        null,
        null,
        .zero,
    ));
    const allocations_after_first = failing.allocations;
    var first = store.take(10, 7).?;
    const first_storage = first.bytes.ptr;
    store.recycle(&first);
    try std.testing.expectEqual(@as(usize, 1), store.storage_cache.block_count);

    var second_publish = first_publish;
    second_publish.packet_id = 8;
    try std.testing.expect(try store.recordWithSource(
        10,
        second_publish,
        "client",
        null,
        null,
        .zero,
    ));
    try std.testing.expectEqual(allocations_after_first, failing.allocations);
    var second = store.take(10, 8).?;
    try std.testing.expectEqual(
        @intFromPtr(first_storage),
        @intFromPtr(second.bytes.ptr),
    );
    store.recycle(&second);
}

test "QoS 2 store owns bytes and preserves the first duplicate PUBLISH" {
    var store = try Store.init(std.testing.allocator, 2);
    defer store.deinit();

    var topic = [_]u8{ 'q', '/', '2' };
    var payload = [_]u8{ 'o', 'n', 'e' };
    var source_client_id = [_]u8{ 'c', 'l', 'i', 'e', 'n', 't' };
    var source_username = [_]u8{ 'u', 's', 'e', 'r' };
    const publish = mqtt.Publish{
        .dup = false,
        .qos = .exactly_once,
        .retain = true,
        .topic = &topic,
        .packet_id = 7,
        .payload = &payload,
    };
    try std.testing.expect(try store.recordWithSource(
        10,
        publish,
        &source_client_id,
        &source_username,
        1883,
        std.Io.Timestamp.zero,
    ));
    @memset(&topic, 'x');
    @memset(&payload, 'x');
    @memset(&source_client_id, 'x');
    @memset(&source_username, 'x');

    var retry = publish;
    retry.dup = true;
    retry.topic = "q/2";
    retry.payload = "one";
    try std.testing.expect(!try store.record(
        10,
        retry,
        std.Io.Timestamp.zero,
    ));

    var repeated = retry;
    repeated.dup = false;
    repeated.topic = "q/2/replaced";
    repeated.payload = "two";
    try std.testing.expect(!try store.record(
        10,
        repeated,
        std.Io.Timestamp.zero,
    ));
    repeated.dup = true;
    repeated.topic = "q/2/conflicting-dup";
    repeated.payload = "three";
    try std.testing.expect(!try store.record(
        10,
        repeated,
        std.Io.Timestamp.zero,
    ));
    try std.testing.expectEqual(@as(usize, 1), store.count());

    var pending = store.take(10, 7).?;
    defer pending.deinit();
    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(std.testing.allocator);
    const restored = (try pending.asPublish(
        7,
        std.Io.Timestamp.zero,
        &properties,
    )).?;
    try std.testing.expectEqualStrings("q/2", restored.topic);
    try std.testing.expectEqualStrings("one", restored.payload);
    try std.testing.expect(restored.retain);
    try std.testing.expectEqualStrings(
        "client",
        pending.source_client_id.?,
    );
    try std.testing.expectEqualStrings("user", pending.source_username.?);
    try std.testing.expectEqual(@as(?u64, 1883), pending.source_listener_id);
}

test "QoS 2 snapshot deducts downtime expiry" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, 2);
    defer store.deinit();
    const publisher_id: router.SubscriberId =
        (@as(u64, 1) << 63) | 9;
    var expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 2,
    } }};
    _ = try store.record(
        publisher_id,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "qos2/expiring",
            .packet_id = 4,
            .properties = &expiry,
            .payload = "payload",
        },
        .zero,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try store.writeSnapshot(
        &encoded,
        allocator,
        .zero,
        {},
        struct {
            fn exists(_: void, _: router.SubscriberId) bool {
                return true;
            }
        }.exists,
    );

    var restored = try Store.init(allocator, 2);
    defer restored.deinit();
    var cursor = persistence.Cursor.init(encoded.items);
    try restored.restoreSnapshot(
        &cursor,
        .zero,
        3 * std.time.ns_per_s,
        {},
        struct {
            fn exists(_: void, _: router.SubscriberId) bool {
                return true;
            }
        }.exists,
    );
    try cursor.finish();
    try std.testing.expectEqual(@as(usize, 0), restored.count());
}

test "QoS 2 snapshot preserves retained source identity" {
    const allocator = std.testing.allocator;
    const publisher_id: router.SubscriberId =
        (@as(u64, 1) << 63) | 11;
    var store = try Store.init(allocator, 1);
    defer store.deinit();
    _ = try store.recordWithSource(
        publisher_id,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = true,
            .topic = "qos2/source",
            .packet_id = 9,
            .payload = "value",
        },
        "publisher",
        "writer",
        1883,
        .zero,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try store.writeSnapshot(
        &encoded,
        allocator,
        .zero,
        {},
        struct {
            fn exists(_: void, _: router.SubscriberId) bool {
                return true;
            }
        }.exists,
    );

    var restored = try Store.init(allocator, 1);
    defer restored.deinit();
    var cursor = persistence.Cursor.init(encoded.items);
    try restored.restoreSnapshot(
        &cursor,
        .zero,
        0,
        {},
        struct {
            fn exists(_: void, _: router.SubscriberId) bool {
                return true;
            }
        }.exists,
    );
    try cursor.finish();
    var pending = restored.take(publisher_id, 9).?;
    defer pending.deinit();
    try std.testing.expectEqualStrings(
        "publisher",
        pending.source_client_id.?,
    );
    try std.testing.expectEqualStrings("writer", pending.source_username.?);
    try std.testing.expectEqual(@as(?u64, 1883), pending.source_listener_id);
}
