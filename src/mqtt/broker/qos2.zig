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
const publication_mod = @import("publication.zig");
const router = @import("../router.zig");
const StorageCache = @import("../storage_cache.zig").Cache;
const Publication = publication_mod.Publication;

pub const Error = mqtt.Error || error{
    PendingLimitExceeded,
    ReceiveMaximumExceeded,
};

pub const Key = packed struct(u80) {
    publisher_id: router.SubscriberId,
    packet_id: u16,
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

    const storage_transferred_flag: usize = @as(usize, 1) <<
        (@bitSizeOf(usize) - 1);
    const publication_prefix_flag: usize = @as(usize, 1) <<
        (@bitSizeOf(usize) - 2);
    const allocation_len_mask: usize = ~(storage_transferred_flag |
        publication_prefix_flag);

    pub fn create(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) Error!Pending {
        return createWithSourceAndPrefix(
            allocator,
            publish,
            null,
            null,
            null,
            now,
            false,
        );
    }

    pub fn createWithSource(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
        source_client_id: ?[]const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        now: std.Io.Timestamp,
    ) Error!Pending {
        return createWithSourceAndPrefix(
            allocator,
            publish,
            source_client_id,
            source_username,
            source_listener_id,
            now,
            false,
        );
    }

    fn createWithSourceAndPrefix(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
        source_client_id: ?[]const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        now: std.Io.Timestamp,
        reserve_publication_prefix: bool,
    ) Error!Pending {
        return createWithSourceAndCache(
            allocator,
            null,
            publish,
            source_client_id,
            source_username,
            source_listener_id,
            now,
            reserve_publication_prefix,
            true,
        );
    }

    fn createWithSourceAndCache(
        allocator: std.mem.Allocator,
        cache: ?*StorageCache,
        publish: mqtt.Publish,
        source_client_id: ?[]const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        now: std.Io.Timestamp,
        reserve_publication_prefix: bool,
        validate_source_identity: bool,
    ) Error!Pending {
        if (source_client_id == null and
            (source_username != null or source_listener_id != null))
        {
            return error.InvalidProperty;
        }
        if (validate_source_identity) {
            if (source_client_id) |value| {
                if (value.len > std.math.maxInt(u16)) return error.InvalidUtf8;
                try mqtt.validateUtf8String(value);
            }
            if (source_username) |value| {
                if (value.len > std.math.maxInt(u16)) return error.InvalidUtf8;
                try mqtt.validateUtf8String(value);
            }
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
        const message_and_identity_len = std.math.add(
            usize,
            std.math.add(
                usize,
                bytes_len,
                source_client_id_len,
            ) catch return error.OutOfMemory,
            source_username_len,
        ) catch return error.OutOfMemory;
        const publication_prefix_len: usize = if (reserve_publication_prefix)
            @sizeOf(Publication)
        else
            0;
        const allocation_len = std.math.add(
            usize,
            publication_prefix_len,
            message_and_identity_len,
        ) catch return error.OutOfMemory;
        const allocation: publication_mod.Allocation = if (cache) |value|
            @alignCast(try value.acquireThreadSafe(allocation_len))
        else
            try allocator.alignedAlloc(
                u8,
                .fromByteUnits(publication_mod.allocation_alignment),
                allocation_len,
            );
        errdefer if (cache) |value|
            value.releaseThreadSafe(allocation)
        else
            allocator.free(allocation);
        if (allocation.len > allocation_len_mask) return error.OutOfMemory;
        const storage = allocation[publication_prefix_len..];
        const bytes = storage[0..bytes_len];
        @memcpy(bytes[0..publish.topic.len], publish.topic);
        @memcpy(bytes[publish.topic.len..], publish.payload);
        var identity_offset = bytes_len;
        const source_client_id_owned = if (source_client_id) |value| blk: {
            const owned = storage[identity_offset..][0..value.len];
            @memcpy(owned, value);
            identity_offset += value.len;
            break :blk owned;
        } else null;
        const source_username_owned = if (source_username) |value| blk: {
            const owned = storage[identity_offset..][0..value.len];
            @memcpy(owned, value);
            identity_offset += value.len;
            break :blk owned;
        } else null;
        std.debug.assert(identity_offset <= storage.len);
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
            .allocation_len = allocation.len |
                (if (reserve_publication_prefix)
                    publication_prefix_flag
                else
                    0),
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
        cache: ?*StorageCache,
    ) void {
        owned_properties.deinit(self.allocator, self.properties);
        if (!self.storageTransferred()) {
            const allocation = self.storageAllocation();
            if (cache) |value|
                value.releaseThreadSafe(allocation)
            else
                self.allocator.free(allocation);
        }
        self.* = undefined;
    }

    fn storageAllocation(self: Pending) publication_mod.Allocation {
        const address = @intFromPtr(self.bytes.ptr) -
            self.publicationPrefixLen();
        const pointer: [*]u8 = @ptrFromInt(address);
        return @alignCast(pointer[0..self.storageLen()]);
    }

    pub fn canAdoptPublication(self: Pending) bool {
        return !self.storageTransferred() and
            self.publicationPrefixLen() == @sizeOf(Publication);
    }

    fn storageLen(self: Pending) usize {
        return self.allocation_len & allocation_len_mask;
    }

    fn publicationPrefixLen(self: Pending) usize {
        return if ((self.allocation_len & publication_prefix_flag) != 0)
            @sizeOf(Publication)
        else
            0;
    }

    pub fn storageTransferred(self: Pending) bool {
        return (self.allocation_len & storage_transferred_flag) != 0;
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
    storage_cache: StorageCache,

    pub fn init(
        allocator: std.mem.Allocator,
        maximum: usize,
    ) std.mem.Allocator.Error!Store {
        return Store{
            .allocator = allocator,
            .maximum = maximum,
            .storage_cache = .initAligned(
                allocator,
                maximum,
                .fromByteUnits(publication_mod.allocation_alignment),
            ),
        };
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
        return self.recordWithSourceOptions(
            publisher_id,
            publish,
            source_client_id,
            source_username,
            source_listener_id,
            now,
            false,
            true,
        );
    }

    pub fn recordWithSourceAndPublicationPrefix(
        self: *Store,
        publisher_id: router.SubscriberId,
        publish: mqtt.Publish,
        source_client_id: ?[]const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        now: std.Io.Timestamp,
        reserve_publication_prefix: bool,
    ) !bool {
        return self.recordWithSourceOptions(
            publisher_id,
            publish,
            source_client_id,
            source_username,
            source_listener_id,
            now,
            reserve_publication_prefix,
            true,
        );
    }

    /// Broker ingress variant after CONNECT parsing and policy validation have
    /// already established the source Client ID and optional username.
    pub fn recordValidatedSourceAndPublicationPrefix(
        self: *Store,
        publisher_id: router.SubscriberId,
        publish: mqtt.Publish,
        source_client_id: ?[]const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        now: std.Io.Timestamp,
        reserve_publication_prefix: bool,
    ) !bool {
        return self.recordWithSourceOptions(
            publisher_id,
            publish,
            source_client_id,
            source_username,
            source_listener_id,
            now,
            reserve_publication_prefix,
            false,
        );
    }

    fn recordWithSourceOptions(
        self: *Store,
        publisher_id: router.SubscriberId,
        publish: mqtt.Publish,
        source_client_id: ?[]const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        now: std.Io.Timestamp,
        reserve_publication_prefix: bool,
        validate_source_identity: bool,
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
        // Reserve the map commit before taking ownership of any PUBLISH bytes.
        // Most brokers use only a small fraction of their aggregate bound; a
        // failed growth therefore leaves no Pending state while avoiding a
        // maximum-sized table at Broker initialization.
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        const pending = try Pending.createWithSourceAndCache(
            self.allocator,
            &self.storage_cache,
            publish,
            source_client_id,
            source_username,
            source_listener_id,
            now,
            reserve_publication_prefix,
            validate_source_identity,
        );
        self.entries.putAssumeCapacityNoClobber(key, pending);
        return true;
    }

    pub fn take(
        self: *Store,
        publisher_id: router.SubscriberId,
        packet_id: u16,
    ) ?Pending {
        var pending: Pending = undefined;
        if (!self.takeInto(publisher_id, packet_id, &pending)) return null;
        return pending;
    }

    /// Remove one transaction directly into caller-owned final storage.
    /// `fetchRemove` returns a full key/value aggregate and large `Pending`
    /// values can then cross multiple optional/result return slots. The broker
    /// already has stable stack storage for the transaction, so copy it once
    /// from the table before tombstoning that exact entry.
    pub fn takeInto(
        self: *Store,
        publisher_id: router.SubscriberId,
        packet_id: u16,
        out: *Pending,
    ) bool {
        const entry = self.entries.getEntry(.{
            .publisher_id = publisher_id,
            .packet_id = packet_id,
        }) orelse return false;
        out.* = entry.value_ptr.*;
        self.entries.removeByPtr(entry.key_ptr);
        return true;
    }

    pub fn recycle(self: *Store, pending: *Pending) void {
        pending.deinitWithCache(&self.storage_cache);
    }

    /// Transfer a removed transaction's aligned cached backing into a shared
    /// broker Publication. The Publication's allocator returns that block to
    /// this Store's bounded cache after its final destination releases it.
    pub fn adoptPublication(
        self: *Store,
        pending: *Pending,
        publish: mqtt.Publish,
        reference_count: usize,
        now: std.Io.Timestamp,
    ) publication_mod.Error!*Publication {
        std.debug.assert(pending.canAdoptPublication());
        const allocation = pending.storageAllocation();
        const packet_bytes = allocation[@sizeOf(Publication)..];
        const publication = try Publication.createFromPrefixedPublish(
            self.storage_cache.asAllocator(),
            publish,
            reference_count,
            now,
            allocation,
            packet_bytes,
        );
        // `publish.properties` still borrows nested values from the Pending
        // record while route-specific Session properties are cloned. Keep
        // those values alive until the caller recycles Pending after routing;
        // only the message backing moves to Publication here.
        pending.allocation_len |= Pending.storage_transferred_flag;
        return publication;
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

test {
    _ = @import("qos2/tests.zig");
}
