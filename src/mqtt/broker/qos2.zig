//! Bounded inbound QoS 2 transaction storage for the live broker.
//!
//! A QoS 2 PUBLISH must not be routed until PUBREL. The runtime tracks the
//! protocol receive window in fixed bitsets; this store owns the application
//! bytes needed to route exactly once at that later control packet.

const std = @import("std");
const mqtt = @import("../mod.zig");
const router = @import("../router.zig");

pub const Key = packed struct(u80) {
    publisher_id: router.SubscriberId,
    packet_id: u16,
};

pub const Pending = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    topic_len: usize,
    retain: bool,

    pub fn create(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
    ) std.mem.Allocator.Error!Pending {
        const bytes_len = std.math.add(
            usize,
            publish.topic.len,
            publish.payload.len,
        ) catch return error.OutOfMemory;
        const bytes = try allocator.alloc(u8, bytes_len);
        @memcpy(bytes[0..publish.topic.len], publish.topic);
        @memcpy(bytes[publish.topic.len..], publish.payload);
        return .{
            .allocator = allocator,
            .bytes = bytes,
            .topic_len = publish.topic.len,
            .retain = publish.retain,
        };
    }

    pub fn deinit(self: *Pending) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn asPublish(
        self: Pending,
        packet_id: u16,
    ) mqtt.Publish {
        return .{
            .dup = false,
            .qos = .exactly_once,
            .retain = self.retain,
            .topic = self.bytes[0..self.topic_len],
            .packet_id = packet_id,
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
        const pending = try Pending.create(self.allocator, publish);
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
    try std.testing.expect(try store.record(10, publish));
    @memset(&topic, 'x');
    @memset(&payload, 'x');

    var retry = publish;
    retry.dup = true;
    retry.topic = "q/2";
    retry.payload = "one";
    try std.testing.expect(!try store.record(10, retry));

    var changed = retry;
    changed.payload = "two";
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        store.record(10, changed),
    );

    var pending = store.take(10, 7).?;
    defer pending.deinit();
    const restored = pending.asPublish(7);
    try std.testing.expectEqualStrings("q/2", restored.topic);
    try std.testing.expectEqualStrings("one", restored.payload);
    try std.testing.expect(restored.retain);
}
