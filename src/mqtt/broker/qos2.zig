//! Bounded inbound QoS 2 transaction storage for the live broker.
//!
//! A QoS 2 PUBLISH must not be routed until PUBREL. The runtime tracks the
//! protocol receive window in fixed bitsets; this store owns the application
//! bytes needed to route exactly once at that later control packet.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");
const router = @import("../router.zig");

pub const Error = mqtt.Error || error{
    PendingLimitExceeded,
};

pub const Key = packed struct(u80) {
    publisher_id: router.SubscriberId,
    packet_id: u16,
};

pub const Pending = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    topic_len: usize,
    retain: bool,
    properties: []mqtt.Property,
    stored_at_ns: i96,
    expiry_interval: ?u32,

    pub fn create(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) Error!Pending {
        const bytes_len = std.math.add(
            usize,
            publish.topic.len,
            publish.payload.len,
        ) catch return error.OutOfMemory;
        const bytes = try allocator.alloc(u8, bytes_len);
        errdefer allocator.free(bytes);
        @memcpy(bytes[0..publish.topic.len], publish.topic);
        @memcpy(bytes[publish.topic.len..], publish.payload);
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
            .topic_len = publish.topic.len,
            .retain = publish.retain,
            .properties = property_result.properties,
            .stored_at_ns = now.nanoseconds,
            .expiry_interval = mqtt.messageExpiryInterval(
                publish.properties,
            ),
        };
    }

    pub fn deinit(self: *Pending) void {
        owned_properties.deinit(self.allocator, self.properties);
        self.allocator.free(self.bytes);
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

    pub fn init(
        allocator: std.mem.Allocator,
        maximum: usize,
    ) std.mem.Allocator.Error!Store {
        var self = Store{
            .allocator = allocator,
            .maximum = maximum,
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
        self.* = undefined;
    }

    /// Store a new transaction, or validate an MQTT retransmission.
    ///
    /// MQTT permits a DUP=1 PUBLISH to repeat an unacknowledged transaction.
    /// It must describe the same Application Message; accepting different
    /// bytes under the same Packet Identifier would make exactly-once routing
    /// ambiguous.
    pub fn record(
        self: *Store,
        publisher_id: router.SubscriberId,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) !bool {
        const packet_id = publish.packet_id orelse
            return error.InvalidPacketIdentifier;
        const key = Key{
            .publisher_id = publisher_id,
            .packet_id = packet_id,
        };
        if (self.entries.get(key)) |existing| {
            if (!publish.dup or
                existing.retain != publish.retain or
                !std.mem.eql(u8, existing.bytes[0..existing.topic_len], publish.topic) or
                !std.mem.eql(u8, existing.bytes[existing.topic_len..], publish.payload))
            {
                return error.InvalidPacketIdentifier;
            }
            return false;
        }
        if (self.entries.count() >= self.maximum) {
            return error.ReceiveMaximumExceeded;
        }
        const pending = try Pending.create(
            self.allocator,
            publish,
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
            pending.deinit();
            removed += 1;
            // Removal invalidates the iterator's traversal state. Restarting is
            // bounded by this connection's Receive Maximum and happens only at
            // disconnect, not on the publish hot path.
            iterator = self.entries.iterator();
        }
        return removed;
    }
};

fn keepPendingProperty(property: mqtt.Property) bool {
    // Topic Alias is scoped to the publisher connection. `readBrokerEvent`
    // has already expanded the full Topic Name before this transaction is
    // stored.
    return !(property == .two_byte and
        property.two_byte.id == .topic_alias);
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

test "QoS 2 store owns bytes and validates duplicate PUBLISH" {
    var store = try Store.init(std.testing.allocator, 2);
    defer store.deinit();

    var topic = [_]u8{ 'q', '/', '2' };
    var payload = [_]u8{ 'o', 'n', 'e' };
    const publish = mqtt.Publish{
        .dup = false,
        .qos = .exactly_once,
        .retain = true,
        .topic = &topic,
        .packet_id = 7,
        .payload = &payload,
    };
    try std.testing.expect(try store.record(
        10,
        publish,
        std.Io.Timestamp.zero,
    ));
    @memset(&topic, 'x');
    @memset(&payload, 'x');

    var retry = publish;
    retry.dup = true;
    retry.topic = "q/2";
    retry.payload = "one";
    try std.testing.expect(!try store.record(
        10,
        retry,
        std.Io.Timestamp.zero,
    ));

    var changed = retry;
    changed.payload = "two";
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        store.record(10, changed, std.Io.Timestamp.zero),
    );

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
}
