//! MQTT retained-message store and subscription-time delivery planning.
//!
//! The store owns all topic, payload, and property bytes. Matching returns
//! borrowed views into that stable storage and therefore allocates nothing.
//! Mutating the store invalidates previously returned views.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");
const persistence = @import("../persistence/codec.zig");

pub const Error = mqtt.Error || error{
    RetainedLimitExceeded,
    MatchBufferTooSmall,
};

pub const Options = struct {
    max_messages: usize = 65_536,
    max_message_bytes: usize = 16 * 1024 * 1024,
    max_total_bytes: usize = 256 * 1024 * 1024,
    /// Bound on retained topic-index memory. The trie and its edge map are
    /// shared by every stored Topic Name, so deep or highly fragmented topics
    /// must not amplify one bounded message into unbounded index nodes.
    max_index_bytes: usize = 64 * 1024 * 1024,
};

pub const StoreResult = enum {
    ignored,
    inserted,
    replaced,
    removed,
};

/// Stable broker-internal identity compatible with `mqtt.router.SubscriberId`.
///
/// Applications can map MQTT ClientID strings to these compact identities.
pub const ClientId = u64;

pub const DeliveryContext = struct {
    subscription_existed: bool = false,
    subscriber_id: ?ClientId = null,
    subscriber_client_id: ?[]const u8 = null,
    subscription_identifier: ?usize = null,
    /// Mosquitto-compatible, non-standard policy: raise a retained message to
    /// the subscription QoS instead of applying the MQTT min(source, grant).
    upgrade_outgoing_qos: bool = false,
};

pub const Match = struct {
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    properties: []const mqtt.Property,
    publisher_id: ?ClientId,
    /// Identity of the original retained publisher. Unlike `publisher_id`,
    /// these values remain meaningful after its Session is removed and can
    /// therefore be re-authorized at replay time.
    source_client_id: ?[]const u8,
    source_username: ?[]const u8 = null,
    source_listener_id: ?u64 = null,
    /// Remaining MQTT 5 Message Expiry Interval at this lookup instant.
    message_expiry_interval: ?u32,
};

pub const Delivery = struct {
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    source_qos: mqtt.QoS,
    retain: bool,
    properties: []const mqtt.Property,
    source_client_id: ?[]const u8,
    source_username: ?[]const u8 = null,
    source_listener_id: ?u64 = null,
    subscription_identifier: ?usize,
    /// Remaining MQTT 5 Message Expiry Interval at this delivery instant.
    /// Encoders can replace the stored property value with this value.
    message_expiry_interval: ?u32,

    /// Encode this retained delivery with its current expiry value.
    pub fn writePublish(
        self: Delivery,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: mqtt.ProtocolVersion,
        packet_id: ?u16,
    ) Error!void {
        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(allocator);
        if (protocol == .v5) {
            try properties.ensureTotalCapacity(
                allocator,
                self.properties.len +
                    @intFromBool(self.subscription_identifier != null),
            );
            for (self.properties) |property| {
                if (property == .four_byte and
                    property.four_byte.id == .message_expiry_interval)
                {
                    const remaining = self.message_expiry_interval orelse
                        continue;
                    properties.appendAssumeCapacity(.{ .four_byte = .{
                        .id = .message_expiry_interval,
                        .value = remaining,
                    } });
                } else {
                    properties.appendAssumeCapacity(property);
                }
            }
            if (self.subscription_identifier) |identifier| {
                properties.appendAssumeCapacity(.{ .varint = .{
                    .id = .subscription_identifier,
                    .value = identifier,
                } });
            }
        }
        try mqtt.writePublish(
            list,
            allocator,
            protocol,
            self.topic,
            self.payload,
            .{
                .qos = self.qos,
                .retain = true,
                .packet_id = packet_id,
                .properties = properties.items,
            },
        );
    }
};

const Entry = struct {
    topic: []u8,
    payload: []u8,
    qos: mqtt.QoS,
    properties: []mqtt.Property,
    publisher_id: ?ClientId,
    source_client_id: ?[]u8,
    source_username: ?[]u8,
    source_listener_id: ?u64,
    stored_at_ns: i96,
    expiry_interval: ?u32,
    allocation_bytes: usize,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        owned_properties.deinit(allocator, self.properties);
        if (self.source_client_id) |value| allocator.free(value);
        if (self.source_username) |value| allocator.free(value);
        allocator.free(self.payload);
        allocator.free(self.topic);
        self.* = undefined;
    }

    /// Release everything except the Topic Name allocation. Replacement
    /// keeps the stored Topic Name so trie edge keys that borrow it stay
    /// valid across the swap.
    fn deinitExceptTopic(self: *Entry, allocator: std.mem.Allocator) void {
        owned_properties.deinit(allocator, self.properties);
        if (self.source_client_id) |value| allocator.free(value);
        if (self.source_username) |value| allocator.free(value);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

/// Sentinel for absent trie links. A u32 index keeps one node at 40 bytes, so
/// wildcard traversal touches far fewer cache lines than optional-usize links.
const trie_none: u32 = std.math.maxInt(u32);

/// One node in the retained-topic trie. Node 0 is the root and is never
/// freed. Children are linked through `child_head`/`next_sibling` so wildcard
/// traversal can enumerate them without a hash map per node; `trie_edges`
/// provides O(1) literal lookup. `parent_edge` borrows the owning Entry's
/// topic bytes, so an Entry is only released after its edges are unlinked.
const TrieNode = struct {
    entry_index: u32 = trie_none,
    parent: u32 = trie_none,
    parent_edge: []const u8 = &.{},
    child_head: u32 = trie_none,
    next_sibling: u32 = trie_none,
    prev_sibling: u32 = trie_none,
    next_free: u32 = trie_none,
};

inline fn trieIndex(slot: u32) ?usize {
    return if (slot == trie_none) null else @intCast(slot);
}

inline fn trieSlot(index: usize) u32 {
    std.debug.assert(index < trie_none);
    return @intCast(index);
}

const TrieEdge = struct {
    parent: usize,
    level: []const u8,
};

/// Approximate bytes owned by one trie level: the node plus one edge-map
/// key/value slot with load-factor and metadata headroom.
const trie_level_bytes = @sizeOf(TrieNode) + @sizeOf(TrieEdge) +
    @sizeOf(usize) + 8;

const TrieEdgeContext = struct {
    pub fn hash(_: TrieEdgeContext, edge: TrieEdge) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&edge.parent));
        hasher.update(edge.level);
        return hasher.final();
    }

    pub fn eql(_: TrieEdgeContext, a: TrieEdge, b: TrieEdge) bool {
        return a.parent == b.parent and
            std.mem.eql(u8, a.level, b.level);
    }
};

const TrieEdges = std.HashMapUnmanaged(
    TrieEdge,
    usize,
    TrieEdgeContext,
    std.hash_map.default_max_load_percentage,
);

const max_filter_levels = 64;
/// Literal child lookups scan this many siblings before hashing. Real topic
/// trees branch rarely, and the scan is cache-friendlier than a hash probe.
const max_child_scan = 8;

const FilterLevels = struct {
    ends: [max_filter_levels]usize = undefined,
    count: usize = 0,
    complete: bool = true,
};

fn computeFilterLevels(filter: []const u8) FilterLevels {
    var levels = FilterLevels{};
    var start: usize = 0;
    while (true) {
        const end = std.mem.indexOfScalarPos(u8, filter, start, '/') orelse
            filter.len;
        if (levels.count == levels.ends.len) {
            levels.complete = false;
            return levels;
        }
        levels.ends[levels.count] = end;
        levels.count += 1;
        if (end == filter.len) break;
        start = end + 1;
    }
    return levels;
}

const MatchFrame = struct {
    node: usize,
    level_index: usize,
    next_child: ?usize,
    /// `+` iteration state: distinguishes "not started" from "exhausted",
    /// both of which have a null `next_child`.
    started: bool = false,
    /// Literal levels have exactly one candidate child; this records that the
    /// frame already descended so returning to it pops instead of repeating.
    descended: bool = false,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    options: Options,
    entries: std.ArrayList(?Entry) = .empty,
    index: std.StringHashMapUnmanaged(usize) = .empty,
    /// Retained-topic trie backing wildcard lookups. Edge keys borrow Entry
    /// topic bytes; replacement reuses the old Topic Name allocation so they
    /// cannot dangle.
    trie_nodes: std.ArrayList(TrieNode) = .empty,
    trie_edges: TrieEdges = .empty,
    trie_free_head: u32 = trie_none,
    /// Approximate bytes owned by the trie and edge map, charged against
    /// `Options.max_index_bytes`.
    index_bytes: usize = 0,
    /// Scratch bitmap over `entries` used to order wildcard matches by table
    /// position without allocating in the lookup path. Capacity is reserved
    /// when entries are inserted.
    match_bits: std.ArrayList(u64) = .empty,
    /// Word range the previous match marked. Clearing only this range keeps
    /// selective lookups from touching the whole bitmap.
    match_clear_lo: usize = std.math.maxInt(usize),
    match_clear_hi: usize = 0,
    message_count: usize = 0,
    total_bytes: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        options: Options,
    ) Store {
        return .{ .allocator = allocator, .options = options };
    }

    pub fn deinit(self: *Store) void {
        for (self.entries.items) |*maybe_entry| {
            if (maybe_entry.*) |*entry| entry.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
        self.index.deinit(self.allocator);
        self.trie_edges.deinit(self.allocator);
        self.trie_nodes.deinit(self.allocator);
        self.match_bits.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: Store) usize {
        return self.message_count;
    }

    pub fn totalBytes(self: Store) usize {
        return self.total_bytes;
    }

    /// Approximate bytes currently owned by the retained topic index.
    pub fn indexBytes(self: Store) usize {
        return self.index_bytes;
    }

    /// Encode all unexpired retained Application Messages.
    ///
    /// Expiry is persisted as remaining seconds so restoring on a different
    /// process monotonic epoch cannot extend message lifetime.
    pub fn writeSnapshot(
        self: *Store,
        out: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        now: std.Io.Timestamp,
    ) (Error || persistence.Error)!void {
        var snapshot_count: u32 = 0;
        for (self.entries.items) |*maybe_entry| {
            const entry = if (maybe_entry.*) |*value| value else continue;
            if (remainingExpiryNs(entry, now.nanoseconds) == 0) continue;
            snapshot_count = std.math.add(u32, snapshot_count, 1) catch
                return error.SnapshotLimitExceeded;
        }
        try persistence.appendInt(out, allocator, u32, snapshot_count);
        for (self.entries.items) |*maybe_entry| {
            const entry = if (maybe_entry.*) |*value| value else continue;
            const remaining_ns = remainingExpiryNs(
                entry,
                now.nanoseconds,
            );
            if (remaining_ns == 0) continue;
            try persistence.appendBlob(out, allocator, entry.topic);
            try persistence.appendBlob(out, allocator, entry.payload);
            try persistence.appendInt(
                out,
                allocator,
                u8,
                @intFromEnum(entry.qos),
            );
            try persistence.appendOptionalInt(
                out,
                allocator,
                u64,
                entry.publisher_id,
            );
            try persistence.appendBool(
                out,
                allocator,
                entry.source_client_id != null,
            );
            if (entry.source_client_id) |source_client_id| {
                try persistence.appendBlob(
                    out,
                    allocator,
                    source_client_id,
                );
            }
            try persistence.appendBool(
                out,
                allocator,
                entry.source_username != null,
            );
            if (entry.source_username) |source_username| {
                try persistence.appendBlob(
                    out,
                    allocator,
                    source_username,
                );
            }
            try persistence.appendOptionalInt(
                out,
                allocator,
                u64,
                entry.source_listener_id,
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
                entry.properties,
            );
        }
    }

    pub fn restoreSnapshot(
        self: *Store,
        cursor: *persistence.Cursor,
        restore_now: std.Io.Timestamp,
        downtime_ns: i96,
    ) (Error || persistence.Error)!void {
        const snapshot_count = try cursor.readInt(u32);
        if (snapshot_count > self.options.max_messages) {
            return error.RetainedLimitExceeded;
        }
        for (0..snapshot_count) |_| {
            const topic = try cursor.readBlob();
            const payload = try cursor.readBlob();
            const qos = try persistence.qosFromByte(
                try cursor.readInt(u8),
            );
            const publisher_id = try cursor.readOptionalInt(u64);
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
            if ((mqtt.messageExpiryInterval(properties) == null) !=
                (saved_remaining_ns == null))
            {
                return error.CorruptSnapshot;
            }

            const remaining_ns = remainingAfterDowntimeNs(
                saved_remaining_ns,
                downtime_ns,
            );
            if (remaining_ns == 0) continue;
            if (self.index.contains(topic)) {
                return error.CorruptSnapshot;
            }
            _ = try self.applyPublish(
                topic,
                payload,
                .{
                    .retain = true,
                    .qos = qos,
                    .properties = properties,
                    .publisher_id = publisher_id,
                    .source_client_id = source_client_id,
                    .source_username = source_username,
                    .source_listener_id = source_listener_id,
                    .now = restore_now,
                },
            );
            if (remaining_ns) |remaining| {
                const entry_index = self.index.get(topic) orelse
                    return error.CorruptSnapshot;
                const entry = &self.entries.items[entry_index].?;
                const interval = entry.expiry_interval orelse
                    return error.CorruptSnapshot;
                const lifetime_ns = @as(u64, interval) *
                    std.time.ns_per_s;
                if (remaining > lifetime_ns) {
                    return error.CorruptSnapshot;
                }
                entry.stored_at_ns = restore_now.nanoseconds -
                    @as(i96, lifetime_ns - remaining);
            }
        }
    }

    pub fn swap(self: *Store, other: *Store) void {
        const value = self.*;
        self.* = other.*;
        other.* = value;
    }

    /// Apply the retained state effect of a PUBLISH packet.
    ///
    /// A non-retained PUBLISH never changes retained state. A retained PUBLISH
    /// with an empty payload removes the retained entry for its Topic Name.
    pub fn applyPublish(
        self: *Store,
        topic: []const u8,
        payload: []const u8,
        options: struct {
            retain: bool,
            qos: mqtt.QoS = .at_most_once,
            properties: []const mqtt.Property = &.{},
            publisher_id: ?ClientId = null,
            source_client_id: ?[]const u8 = null,
            source_username: ?[]const u8 = null,
            source_listener_id: ?u64 = null,
            now: std.Io.Timestamp,
        },
    ) Error!StoreResult {
        try mqtt.validateTopicName(topic);
        if (!options.retain) return .ignored;
        try mqtt.validatePublishProperties(options.properties);
        if (options.source_client_id == null and
            (options.source_username != null or
                options.source_listener_id != null))
        {
            return error.InvalidProperty;
        }
        if (options.source_client_id) |client_id| {
            if (client_id.len > std.math.maxInt(u16)) return error.InvalidUtf8;
            try mqtt.validateUtf8String(client_id);
        }
        if (options.source_username) |username| {
            if (username.len > std.math.maxInt(u16)) return error.InvalidUtf8;
            try mqtt.validateUtf8String(username);
        }
        if (mqtt.subscriptionIdentifier(options.properties) != null) {
            // MQTT 5 forbids a Client-to-Server PUBLISH from carrying this
            // server-generated delivery property.
            return error.InvalidProperty;
        }
        if (payload.len == 0 or
            mqtt.messageExpiryInterval(options.properties) == 0)
        {
            return if (self.remove(topic))
                .removed
            else
                .ignored;
        }

        var new_entry = try cloneEntry(
            self.allocator,
            topic,
            payload,
            options.qos,
            options.properties,
            options.publisher_id,
            options.source_client_id,
            options.source_username,
            options.source_listener_id,
            options.now.nanoseconds,
        );
        errdefer new_entry.deinit(self.allocator);
        if (new_entry.allocation_bytes > self.options.max_message_bytes or
            new_entry.allocation_bytes > self.options.max_total_bytes)
        {
            return error.RetainedLimitExceeded;
        }

        if (self.index.get(topic)) |entry_index| {
            var old_entry = self.entries.items[entry_index].?;
            const prospective_total = self.total_bytes -
                old_entry.allocation_bytes +
                new_entry.allocation_bytes;
            if (prospective_total > self.options.max_total_bytes) {
                return error.RetainedLimitExceeded;
            }

            // Trie edge keys borrow the stored Topic Name. Reuse the old
            // allocation so replacement cannot leave dangling keys, and the
            // index key pointer therefore stays valid too.
            self.allocator.free(new_entry.topic);
            new_entry.topic = old_entry.topic;
            self.entries.items[entry_index] = new_entry;
            self.total_bytes = prospective_total;
            new_entry = undefined;
            old_entry.deinitExceptTopic(self.allocator);
            return .replaced;
        }

        if (self.message_count >= self.options.max_messages or
            new_entry.allocation_bytes >
                self.options.max_total_bytes - self.total_bytes)
        {
            return error.RetainedLimitExceeded;
        }
        const index_cost = self.trieInsertCost(new_entry.topic);
        if (index_cost > self.options.max_index_bytes -| self.index_bytes) {
            return error.RetainedLimitExceeded;
        }
        try self.index.ensureUnusedCapacity(self.allocator, 1);
        const entry_index = for (self.entries.items, 0..) |
            maybe_entry,
            index,
        | {
            if (maybe_entry == null) break index;
        } else blk: {
            try self.entries.append(self.allocator, null);
            break :blk self.entries.items.len - 1;
        };
        // Reserve every allocation the commit needs so the trie insert and
        // bitmap sizing below cannot fail and leave borrowed keys dangling.
        const previous_words = self.match_bits.items.len;
        try self.match_bits.resize(
            self.allocator,
            (self.entries.items.len + 63) / 64,
        );
        // New words start zero so the bitmap is zero at every match boundary.
        @memset(self.match_bits.items[previous_words..], 0);
        const trie_levels: u32 = @intCast(
            std.mem.count(u8, new_entry.topic, "/") + 1,
        );
        try self.trie_nodes.ensureUnusedCapacity(
            self.allocator,
            trie_levels + @intFromBool(self.trie_nodes.items.len == 0),
        );
        try self.trie_edges.ensureUnusedCapacity(
            self.allocator,
            trie_levels,
        );

        self.entries.items[entry_index] = new_entry;
        self.trieInsertAssumeCapacity(new_entry.topic, entry_index);
        self.index.putAssumeCapacityNoClobber(
            new_entry.topic,
            entry_index,
        );
        self.message_count += 1;
        self.total_bytes += new_entry.allocation_bytes;
        self.index_bytes += index_cost;
        new_entry = undefined;
        return .inserted;
    }

    /// Apply retained state from an already parsed PUBLISH.
    ///
    /// Callers must resolve Topic Alias before parsing/storing so `publish.topic`
    /// is the full Topic Name. The alias property itself is stripped from the
    /// retained copy.
    pub fn applyParsedPublish(
        self: *Store,
        publish: mqtt.Publish,
        publisher_id: ?ClientId,
        source_client_id: ?[]const u8,
        now: std.Io.Timestamp,
    ) Error!StoreResult {
        return self.applyParsedPublishWithSource(
            publish,
            publisher_id,
            source_client_id,
            null,
            null,
            now,
        );
    }

    pub fn applyParsedPublishWithSource(
        self: *Store,
        publish: mqtt.Publish,
        publisher_id: ?ClientId,
        source_client_id: ?[]const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        now: std.Io.Timestamp,
    ) Error!StoreResult {
        return self.applyPublish(
            publish.topic,
            publish.payload,
            .{
                .retain = publish.retain,
                .qos = publish.qos,
                .properties = publish.properties,
                .publisher_id = publisher_id,
                .source_client_id = source_client_id,
                .source_username = source_username,
                .source_listener_id = source_listener_id,
                .now = now,
            },
        );
    }

    pub fn remove(self: *Store, topic: []const u8) bool {
        const removed = self.index.fetchRemove(topic) orelse return false;
        var entry = self.entries.items[removed.value].?;
        self.entries.items[removed.value] = null;
        self.message_count -= 1;
        self.total_bytes -= entry.allocation_bytes;
        // Unlink borrowed trie keys before the Topic Name is freed.
        const freed_index_bytes = self.trieRemove(topic);
        std.debug.assert(freed_index_bytes <= self.index_bytes);
        self.index_bytes -= freed_index_bytes;
        entry.deinit(self.allocator);
        return true;
    }

    /// Remove all expired retained messages.
    pub fn pruneExpired(
        self: *Store,
        now: std.Io.Timestamp,
    ) usize {
        var removed: usize = 0;
        var entry_index: usize = 0;
        while (entry_index < self.entries.items.len) : (entry_index += 1) {
            const entry = &(self.entries.items[entry_index] orelse continue);
            if (remainingExpiry(entry, now.nanoseconds) != 0) {
                continue;
            }
            std.debug.assert(self.remove(entry.topic));
            removed += 1;
        }
        return removed;
    }

    /// Insert one Topic Name path. All required allocations were reserved by
    /// the caller, so this cannot fail.
    fn trieInsertAssumeCapacity(
        self: *Store,
        topic: []const u8,
        entry_index: usize,
    ) void {
        if (self.trie_nodes.items.len == 0) {
            self.trie_nodes.appendAssumeCapacity(.{});
        }
        var node: usize = 0;
        var start: usize = 0;
        while (true) {
            const end = std.mem.indexOfScalarPos(u8, topic, start, '/') orelse
                topic.len;
            const level = topic[start..end];
            const slot = self.trie_edges.getOrPutAssumeCapacity(.{
                .parent = node,
                .level = level,
            });
            if (!slot.found_existing) {
                slot.value_ptr.* = self.trieNewChildAssumeCapacity(
                    node,
                    level,
                );
            }
            node = slot.value_ptr.*;
            if (end == topic.len) break;
            start = end + 1;
        }
        std.debug.assert(self.trie_nodes.items[node].entry_index == trie_none);
        self.trie_nodes.items[node].entry_index = trieSlot(entry_index);
    }

    fn trieNewChildAssumeCapacity(
        self: *Store,
        parent: usize,
        level: []const u8,
    ) usize {
        var index: usize = undefined;
        if (trieIndex(self.trie_free_head)) |free_index| {
            self.trie_free_head = self.trie_nodes.items[free_index].next_free;
            index = free_index;
        } else {
            self.trie_nodes.appendAssumeCapacity(.{});
            index = self.trie_nodes.items.len - 1;
        }
        const head = self.trie_nodes.items[parent].child_head;
        self.trie_nodes.items[index] = .{
            .parent = trieSlot(parent),
            .parent_edge = level,
            .next_sibling = head,
        };
        if (trieIndex(head)) |head_index| {
            self.trie_nodes.items[head_index].prev_sibling = trieSlot(index);
        }
        self.trie_nodes.items[parent].child_head = trieSlot(index);
        return index;
    }

    /// Bytes the trie will allocate for `topic`, counting only levels that do
    /// not already exist. Runs before the insert commit so an oversized index
    /// cannot be allocated and then abandoned.
    fn trieInsertCost(self: *const Store, topic: []const u8) usize {
        const total_levels = std.mem.count(u8, topic, "/") + 1;
        if (self.trie_nodes.items.len == 0) {
            return @sizeOf(TrieNode) + total_levels * trie_level_bytes;
        }
        var node: usize = 0;
        var start: usize = 0;
        var remaining = total_levels;
        while (true) {
            const end = std.mem.indexOfScalarPos(u8, topic, start, '/') orelse
                topic.len;
            const child = self.trieChild(node, topic[start..end]) orelse
                break;
            node = child;
            remaining -= 1;
            if (end == topic.len) return 0;
            start = end + 1;
        }
        return remaining * trie_level_bytes;
    }

    /// Unlink `topic` from the trie and release empty nodes upward. Returns the
    /// bytes returned to the index budget. Must run before the Entry's Topic
    /// Name allocation is freed because edge keys borrow it.
    fn trieRemove(self: *Store, topic: []const u8) usize {
        if (self.trie_nodes.items.len == 0) return 0;
        var node: usize = 0;
        var start: usize = 0;
        while (true) {
            const end = std.mem.indexOfScalarPos(u8, topic, start, '/') orelse
                topic.len;
            node = self.trie_edges.get(.{
                .parent = node,
                .level = topic[start..end],
            }) orelse {
                std.debug.assert(false);
                return 0;
            };
            if (end == topic.len) break;
            start = end + 1;
        }
        std.debug.assert(self.trie_nodes.items[node].entry_index != trie_none);
        self.trie_nodes.items[node].entry_index = trie_none;
        var freed: usize = 0;
        while (node != 0) {
            const current = self.trie_nodes.items[node];
            if (current.entry_index != trie_none or
                current.child_head != trie_none)
            {
                break;
            }
            const parent = trieIndex(current.parent) orelse break;
            if (trieIndex(current.prev_sibling)) |prev| {
                self.trie_nodes.items[prev].next_sibling =
                    current.next_sibling;
            } else {
                self.trie_nodes.items[parent].child_head =
                    current.next_sibling;
            }
            if (trieIndex(current.next_sibling)) |next| {
                self.trie_nodes.items[next].prev_sibling =
                    current.prev_sibling;
            }
            const removed = self.trie_edges.remove(.{
                .parent = parent,
                .level = current.parent_edge,
            });
            std.debug.assert(removed);
            self.trie_nodes.items[node].next_free = self.trie_free_head;
            self.trie_free_head = trieSlot(node);
            freed += trie_level_bytes;
            node = parent;
        }
        return freed;
    }

    /// Literal child lookup. Topic trees are narrow away from their branch
    /// points, so scanning a few siblings avoids hashing for the common
    /// `devices/+/state` shape. Wide nodes fall back to the edge map.
    fn trieChild(
        self: *const Store,
        parent: usize,
        level: []const u8,
    ) ?usize {
        var child = trieIndex(self.trie_nodes.items[parent].child_head);
        var scanned: usize = 0;
        while (child) |child_index| {
            const node = &self.trie_nodes.items[child_index];
            if (std.mem.eql(u8, node.parent_edge, level)) {
                return child_index;
            }
            scanned += 1;
            if (scanned == max_child_scan) break;
            child = trieIndex(node.next_sibling);
        }
        return self.trie_edges.get(.{ .parent = parent, .level = level });
    }

    fn setMatchBit(self: *Store, entry_index: usize) void {
        const word = entry_index / 64;
        self.match_bits.items[word] |=
            @as(u64, 1) << @intCast(entry_index % 64);
        self.match_clear_lo = @min(self.match_clear_lo, word);
        self.match_clear_hi = @max(self.match_clear_hi, word + 1);
    }

    /// Clear exactly the words the previous match marked. The bitmap is zero
    /// at every match boundary, so a selective lookup never touches the rest
    /// of the table.
    fn clearMatchBits(self: *Store) void {
        if (self.match_clear_lo < self.match_clear_hi) {
            @memset(
                self.match_bits.items[self.match_clear_lo..self.match_clear_hi],
                0,
            );
        }
        self.match_clear_lo = std.math.maxInt(usize);
        self.match_clear_hi = 0;
    }

    /// Mark every retained entry matching `filter` in `match_bits`.
    fn collectMatches(self: *Store, filter: []const u8) void {
        if (self.message_count == 0) return;
        const levels = computeFilterLevels(filter);
        if (!levels.complete or self.trie_nodes.items.len == 0) {
            // Filters deeper than the inline bound are vanishingly rare. A
            // linear scan keeps the lookup allocation-free instead of growing
            // a heap traversal stack.
            for (self.entries.items, 0..) |maybe_entry, entry_index| {
                const entry = maybe_entry orelse continue;
                if (mqtt.topicMatchesFilter(entry.topic, filter)) {
                    self.setMatchBit(entry_index);
                }
            }
            return;
        }
        self.traverseFilter(filter, &levels);
    }

    fn traverseFilter(
        self: *Store,
        filter: []const u8,
        levels: *const FilterLevels,
    ) void {
        // One frame per filter level plus the terminal frame. The depth is
        // bounded by `max_filter_levels`, so this needs no allocation.
        var stack: [max_filter_levels + 1]MatchFrame = undefined;
        var depth: usize = 0;
        stack[0] = .{ .node = 0, .level_index = 0, .next_child = null };
        while (true) {
            const frame = &stack[depth];
            if (frame.level_index == levels.count) {
                if (trieIndex(self.trie_nodes.items[frame.node].entry_index)) |index| {
                    self.setMatchBit(index);
                }
                if (depth == 0) return;
                depth -= 1;
                continue;
            }
            const level_start = if (frame.level_index == 0)
                0
            else
                levels.ends[frame.level_index - 1] + 1;
            const level = filter[level_start..levels.ends[frame.level_index]];
            if (level.len == 1 and level[0] == '#') {
                // `#` is validated to be the final level.
                self.collectSubtree(frame.node, frame.level_index == 0);
                if (depth == 0) return;
                depth -= 1;
                continue;
            }
            if (level.len == 1 and level[0] == '+') {
                var child: ?usize = undefined;
                if (frame.started) {
                    child = frame.next_child;
                } else {
                    frame.started = true;
                    child = trieIndex(
                        self.trie_nodes.items[frame.node].child_head,
                    );
                }
                // MQTT reserves `$` topics from a leading wildcard.
                if (frame.level_index == 0) {
                    while (child) |child_index| {
                        if (!std.mem.startsWith(
                            u8,
                            self.trie_nodes.items[child_index].parent_edge,
                            "$",
                        )) break;
                        child = trieIndex(
                            self.trie_nodes.items[child_index].next_sibling,
                        );
                    }
                }
                if (child) |child_index| {
                    frame.next_child = trieIndex(
                        self.trie_nodes.items[child_index].next_sibling,
                    );
                    depth += 1;
                    stack[depth] = .{
                        .node = child_index,
                        .level_index = frame.level_index + 1,
                        .next_child = null,
                    };
                } else if (depth == 0) {
                    return;
                } else {
                    depth -= 1;
                }
                continue;
            }
            if (frame.descended) {
                if (depth == 0) return;
                depth -= 1;
                continue;
            }
            frame.descended = true;
            if (self.trieChild(frame.node, level)) |child_index| {
                depth += 1;
                stack[depth] = .{
                    .node = child_index,
                    .level_index = frame.level_index + 1,
                    .next_child = null,
                };
            } else if (depth == 0) {
                return;
            } else {
                depth -= 1;
            }
        }
    }

    fn collectSubtree(self: *Store, start: usize, skip_system: bool) void {
        if (trieIndex(self.trie_nodes.items[start].entry_index)) |index| {
            self.setMatchBit(index);
        }
        var child = trieIndex(self.trie_nodes.items[start].child_head);
        while (child) |child_index| {
            if (skip_system and std.mem.startsWith(
                u8,
                self.trie_nodes.items[child_index].parent_edge,
                "$",
            )) {
                child = trieIndex(
                    self.trie_nodes.items[child_index].next_sibling,
                );
                continue;
            }
            self.collectSubtreeFrom(child_index);
            child = trieIndex(
                self.trie_nodes.items[child_index].next_sibling,
            );
        }
    }

    /// Pre-order walk of one child's subtree using sibling and parent links
    /// instead of an explicit stack.
    fn collectSubtreeFrom(self: *Store, root_child: usize) void {
        var current = root_child;
        while (true) {
            if (trieIndex(self.trie_nodes.items[current].entry_index)) |index| {
                self.setMatchBit(index);
            }
            if (trieIndex(self.trie_nodes.items[current].child_head)) |child| {
                current = child;
                continue;
            }
            while (true) {
                if (current == root_child) return;
                if (trieIndex(
                    self.trie_nodes.items[current].next_sibling,
                )) |sibling| {
                    current = sibling;
                    break;
                }
                current = trieIndex(self.trie_nodes.items[current].parent).?;
            }
        }
    }

    pub fn matchInto(
        self: *Store,
        filter: []const u8,
        now: std.Io.Timestamp,
        out: []Match,
    ) Error![]Match {
        const effective_filter = effectiveFilter(filter);
        const has_wildcards = try mqtt.validateTopicFilterKind(filter);
        if (!has_wildcards) {
            const entry_index = self.index.get(effective_filter) orelse
                return out[0..0];
            const entry = &self.entries.items[entry_index].?;
            const remaining = remainingExpiry(
                entry,
                now.nanoseconds,
            );
            if (remaining == 0) return out[0..0];
            if (out.len == 0) return error.MatchBufferTooSmall;
            out[0] = matchForEntry(entry, remaining);
            return out[0..1];
        }
        self.collectMatches(effective_filter);
        defer self.clearMatchBits();
        if (out.len < self.message_count) {
            // With room for the whole live store, MatchBufferTooSmall is
            // impossible and the emit pass below doubles as the count.
            var required: usize = 0;
            for (self.match_bits.items, 0..) |word, word_index| {
                var bits = word;
                while (bits != 0) {
                    const entry_index =
                        word_index * 64 + @as(usize, @intCast(@ctz(bits)));
                    bits &= bits - 1;
                    const entry = &self.entries.items[entry_index].?;
                    if (remainingExpiry(entry, now.nanoseconds) != 0) {
                        required += 1;
                    }
                }
            }
            if (out.len < required) return error.MatchBufferTooSmall;
        }

        var written: usize = 0;
        for (self.match_bits.items, 0..) |word, word_index| {
            var bits = word;
            while (bits != 0) {
                const entry_index =
                    word_index * 64 + @as(usize, @intCast(@ctz(bits)));
                bits &= bits - 1;
                const entry = &self.entries.items[entry_index].?;
                const remaining = remainingExpiry(entry, now.nanoseconds);
                if (remaining == 0) continue;
                out[written] = matchForEntry(entry, remaining);
                written += 1;
            }
        }
        return out[0..written];
    }

    pub fn matchAlloc(
        self: *Store,
        allocator: std.mem.Allocator,
        filter: []const u8,
        now: std.Io.Timestamp,
    ) Error![]Match {
        const matches = try allocator.alloc(Match, self.message_count);
        errdefer allocator.free(matches);
        const written = try self.matchInto(filter, now, matches);
        if (written.len == matches.len) return matches;
        if (written.len == 0) {
            allocator.free(matches);
            return allocator.alloc(Match, 0);
        }
        if (allocator.resize(matches, written.len)) {
            return matches[0..written.len];
        }
        const exact = try allocator.dupe(Match, written);
        allocator.free(matches);
        return exact;
    }

    /// Plan retained deliveries for one successful SUBSCRIBE filter.
    ///
    /// Shared subscriptions never receive retained messages at subscribe time,
    /// as required by MQTT 5 §3.8.4. Non-shared Retain Handling values 0/1/2
    /// implement always/new-only/never respectively. For MQTT 3.1.1 callers,
    /// pass default subscription options and omit the subscription identifier.
    pub fn deliveriesInto(
        self: *Store,
        subscription: mqtt.Subscription,
        context: DeliveryContext,
        now: std.Io.Timestamp,
        out: []Delivery,
    ) Error![]Delivery {
        const has_wildcards = try mqtt.validateTopicFilterKind(
            subscription.topic_filter,
        );
        if (subscription.retain_handling > 2) {
            return error.InvalidSubscription;
        }
        if (context.subscription_identifier) |identifier| {
            if (identifier == 0 or identifier > 268_435_455) {
                return error.InvalidProperty;
            }
        }
        if (std.mem.startsWith(
            u8,
            subscription.topic_filter,
            "$share/",
        ) or subscription.retain_handling == 2 or
            (subscription.retain_handling == 1 and
                context.subscription_existed))
        {
            return out[0..0];
        }

        const effective_filter = effectiveFilter(
            subscription.topic_filter,
        );
        if (!has_wildcards) {
            const entry_index = self.index.get(effective_filter) orelse
                return out[0..0];
            const entry = &self.entries.items[entry_index].?;
            const remaining = remainingExpiry(
                entry,
                now.nanoseconds,
            );
            if (remaining == 0) return out[0..0];
            if (skipNoLocal(entry, subscription, context)) {
                return out[0..0];
            }
            if (out.len == 0) return error.MatchBufferTooSmall;
            out[0] = deliveryForEntry(
                entry,
                subscription.qos,
                context.subscription_identifier,
                remaining,
                context.upgrade_outgoing_qos,
            );
            return out[0..1];
        }
        self.collectMatches(effective_filter);
        defer self.clearMatchBits();
        if (out.len < self.message_count) {
            var required: usize = 0;
            for (self.match_bits.items, 0..) |word, word_index| {
                var bits = word;
                while (bits != 0) {
                    const entry_index =
                        word_index * 64 + @as(usize, @intCast(@ctz(bits)));
                    bits &= bits - 1;
                    const entry = &self.entries.items[entry_index].?;
                    if (remainingExpiry(entry, now.nanoseconds) == 0) {
                        continue;
                    }
                    if (skipNoLocal(entry, subscription, context)) continue;
                    required += 1;
                }
            }
            if (out.len < required) return error.MatchBufferTooSmall;
        }

        var written: usize = 0;
        for (self.match_bits.items, 0..) |word, word_index| {
            var bits = word;
            while (bits != 0) {
                const entry_index =
                    word_index * 64 + @as(usize, @intCast(@ctz(bits)));
                bits &= bits - 1;
                const entry = &self.entries.items[entry_index].?;
                const remaining = remainingExpiry(entry, now.nanoseconds);
                if (remaining == 0) continue;
                if (skipNoLocal(entry, subscription, context)) continue;
                out[written] = deliveryForEntry(
                    entry,
                    subscription.qos,
                    context.subscription_identifier,
                    remaining,
                    context.upgrade_outgoing_qos,
                );
                written += 1;
            }
        }
        return out[0..written];
    }

    pub fn deliveriesAlloc(
        self: *Store,
        allocator: std.mem.Allocator,
        subscription: mqtt.Subscription,
        context: DeliveryContext,
        now: std.Io.Timestamp,
    ) Error![]Delivery {
        const deliveries = try allocator.alloc(
            Delivery,
            self.message_count,
        );
        errdefer allocator.free(deliveries);
        const written = try self.deliveriesInto(
            subscription,
            context,
            now,
            deliveries,
        );
        if (written.len == deliveries.len) return deliveries;
        if (written.len == 0) {
            allocator.free(deliveries);
            return allocator.alloc(Delivery, 0);
        }
        if (allocator.resize(deliveries, written.len)) {
            return deliveries[0..written.len];
        }
        const exact = try allocator.dupe(Delivery, written);
        allocator.free(deliveries);
        return exact;
    }
};

fn cloneEntry(
    allocator: std.mem.Allocator,
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    properties: []const mqtt.Property,
    publisher_id: ?ClientId,
    source_client_id: ?[]const u8,
    source_username: ?[]const u8,
    source_listener_id: ?u64,
    now_ns: i96,
) Error!Entry {
    const topic_owned = try allocator.dupe(u8, topic);
    errdefer allocator.free(topic_owned);
    const payload_owned = try allocator.dupe(u8, payload);
    errdefer allocator.free(payload_owned);
    const source_client_id_owned = if (source_client_id) |value|
        try allocator.dupe(u8, value)
    else
        null;
    errdefer if (source_client_id_owned) |value| allocator.free(value);
    const source_username_owned = if (source_username) |value|
        try allocator.dupe(u8, value)
    else
        null;
    errdefer if (source_username_owned) |value| allocator.free(value);
    const property_result = owned_properties.clone(
        allocator,
        properties,
        keepRetainedProperty,
    ) catch |err| switch (err) {
        error.OwnedPropertyLimitExceeded => return error.RetainedLimitExceeded,
        else => return @errorCast(err),
    };
    errdefer owned_properties.deinit(
        allocator,
        property_result.properties,
    );
    const allocation_bytes = std.math.add(
        usize,
        topic_owned.len + payload_owned.len +
            (if (source_client_id_owned) |value| value.len else 0) +
            (if (source_username_owned) |value| value.len else 0),
        property_result.allocation_bytes,
    ) catch return error.RetainedLimitExceeded;
    return .{
        .topic = topic_owned,
        .payload = payload_owned,
        .qos = qos,
        .properties = property_result.properties,
        .publisher_id = publisher_id,
        .source_client_id = source_client_id_owned,
        .source_username = source_username_owned,
        .source_listener_id = source_listener_id,
        .stored_at_ns = now_ns,
        .expiry_interval = mqtt.messageExpiryInterval(properties),
        .allocation_bytes = allocation_bytes,
    };
}

fn keepRetainedProperty(property: mqtt.Property) bool {
    // Topic Alias is scoped to one Network Connection and must not survive in
    // broker state or be replayed to another subscriber.
    return !(property == .two_byte and
        property.two_byte.id == .topic_alias);
}

fn remainingExpiry(entry: *const Entry, now_ns: i96) ?u32 {
    const interval = entry.expiry_interval orelse return null;
    if (interval == 0) return 0;
    const elapsed_ns = @max(now_ns - entry.stored_at_ns, 0);
    const expiry_ns = @as(i96, interval) * std.time.ns_per_s;
    if (elapsed_ns >= expiry_ns) return 0;
    const elapsed_seconds: u32 = @intCast(
        @divTrunc(elapsed_ns, std.time.ns_per_s),
    );
    return interval - elapsed_seconds;
}

fn remainingExpiryNs(entry: *const Entry, now_ns: i96) ?u64 {
    const interval = entry.expiry_interval orelse return null;
    const lifetime_ns = @as(u64, interval) * std.time.ns_per_s;
    const elapsed_ns: u64 = @intCast(@max(
        now_ns - entry.stored_at_ns,
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

fn matchForEntry(entry: *const Entry, remaining: ?u32) Match {
    return .{
        .topic = entry.topic,
        .payload = entry.payload,
        .qos = entry.qos,
        .properties = entry.properties,
        .publisher_id = entry.publisher_id,
        .source_client_id = entry.source_client_id,
        .source_username = entry.source_username,
        .source_listener_id = entry.source_listener_id,
        .message_expiry_interval = remaining,
    };
}

fn deliveryForEntry(
    entry: *const Entry,
    subscription_qos: mqtt.QoS,
    subscription_identifier: ?usize,
    remaining: ?u32,
    upgrade_outgoing_qos: bool,
) Delivery {
    return .{
        .topic = entry.topic,
        .payload = entry.payload,
        .qos = if (upgrade_outgoing_qos)
            subscription_qos
        else
            minQos(entry.qos, subscription_qos),
        .source_qos = entry.qos,
        // Retained messages sent because of a subscription always carry
        // RETAIN=1, independent of Retain As Published.
        .retain = true,
        .properties = entry.properties,
        .source_client_id = entry.source_client_id,
        .source_username = entry.source_username,
        .source_listener_id = entry.source_listener_id,
        .subscription_identifier = subscription_identifier,
        .message_expiry_interval = remaining,
    };
}

fn skipNoLocal(
    entry: *const Entry,
    subscription: mqtt.Subscription,
    context: DeliveryContext,
) bool {
    if (!subscription.no_local) return false;
    if (context.subscriber_client_id) |subscriber_client_id| {
        if (entry.source_client_id) |source_client_id| {
            return std.mem.eql(
                u8,
                subscriber_client_id,
                source_client_id,
            );
        }
    }
    const subscriber_id = context.subscriber_id orelse return false;
    const publisher_id = entry.publisher_id orelse return false;
    return subscriber_id == publisher_id;
}

fn effectiveFilter(filter: []const u8) []const u8 {
    if (!std.mem.startsWith(u8, filter, "$share/")) return filter;
    const rest = filter["$share/".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse
        return filter;
    return rest[slash + 1 ..];
}

fn minQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) <= @intFromEnum(b)) a else b;
}

test {
    _ = @import("tests.zig");
}
