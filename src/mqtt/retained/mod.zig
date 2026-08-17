//! MQTT retained-message store and subscription-time delivery planning.
//!
//! The store owns all topic, payload, and property bytes. Matching returns
//! borrowed views into that stable storage and therefore allocates nothing.
//! Mutating the store invalidates previously returned views.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");

pub const Error = mqtt.Error || error{
    RetainedLimitExceeded,
    MatchBufferTooSmall,
};

pub const Options = struct {
    max_messages: usize = 65_536,
    max_message_bytes: usize = 16 * 1024 * 1024,
    max_total_bytes: usize = 256 * 1024 * 1024,
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
    subscription_identifier: ?usize = null,
};

pub const Match = struct {
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    properties: []const mqtt.Property,
    publisher_id: ?ClientId,
    /// Remaining MQTT 5 Message Expiry Interval at this lookup instant.
    message_expiry_interval: ?u32,
};

pub const Delivery = struct {
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []const mqtt.Property,
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
    stored_at_ns: i96,
    expiry_interval: ?u32,
    allocation_bytes: usize,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        owned_properties.deinit(allocator, self.properties);
        allocator.free(self.payload);
        allocator.free(self.topic);
        self.* = undefined;
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    options: Options,
    entries: std.ArrayList(?Entry) = .empty,
    index: std.StringHashMapUnmanaged(usize) = .empty,
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
        self.* = undefined;
    }

    pub fn count(self: Store) usize {
        return self.message_count;
    }

    pub fn totalBytes(self: Store) usize {
        return self.total_bytes;
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
            now: std.Io.Timestamp,
        },
    ) Error!StoreResult {
        try mqtt.validateTopicName(topic);
        if (!options.retain) return .ignored;
        try mqtt.validatePublishProperties(options.properties);
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
            options.now.nanoseconds,
        );
        errdefer new_entry.deinit(self.allocator);
        if (new_entry.allocation_bytes > self.options.max_message_bytes or
            new_entry.allocation_bytes > self.options.max_total_bytes)
        {
            return error.RetainedLimitExceeded;
        }

        if (self.index.get(topic)) |entry_index| {
            const old = &self.entries.items[entry_index].?;
            const prospective_total = self.total_bytes -
                old.allocation_bytes +
                new_entry.allocation_bytes;
            if (prospective_total > self.options.max_total_bytes) {
                return error.RetainedLimitExceeded;
            }

            const map_value = self.index.getPtr(topic).?;
            std.debug.assert(map_value.* == entry_index);
            var old_entry = self.entries.items[entry_index].?;
            self.entries.items[entry_index] = new_entry;
            // StringHashMap keys point into the owned Entry. Replace the key
            // pointer before freeing the old topic, without perturbing table
            // capacity or probing state.
            self.index.getEntry(topic).?.key_ptr.* = new_entry.topic;
            self.total_bytes = prospective_total;
            new_entry = undefined;
            old_entry.deinit(self.allocator);
            return .replaced;
        }

        if (self.message_count >= self.options.max_messages or
            new_entry.allocation_bytes >
                self.options.max_total_bytes - self.total_bytes)
        {
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

        self.entries.items[entry_index] = new_entry;
        self.index.putAssumeCapacityNoClobber(
            new_entry.topic,
            entry_index,
        );
        self.message_count += 1;
        self.total_bytes += new_entry.allocation_bytes;
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
            if (remainingExpiry(entry.*, now.nanoseconds) != 0) {
                continue;
            }
            std.debug.assert(self.remove(entry.topic));
            removed += 1;
        }
        return removed;
    }

    pub fn matchInto(
        self: *Store,
        filter: []const u8,
        now: std.Io.Timestamp,
        out: []Match,
    ) Error![]Match {
        try mqtt.validateTopicFilter(filter);
        const effective_filter = effectiveFilter(filter);
        if (!mqtt.hasWildcards(effective_filter)) {
            const entry_index = self.index.get(effective_filter) orelse
                return out[0..0];
            const entry = self.entries.items[entry_index].?;
            const remaining = remainingExpiry(
                entry,
                now.nanoseconds,
            );
            if (remaining == 0) return out[0..0];
            if (out.len == 0) return error.MatchBufferTooSmall;
            out[0] = matchForEntry(entry, remaining);
            return out[0..1];
        }
        var required: usize = 0;
        for (self.entries.items) |maybe_entry| {
            const entry = maybe_entry orelse continue;
            if (remainingExpiry(entry, now.nanoseconds) == 0) continue;
            if (mqtt.topicMatchesFilter(
                entry.topic,
                effective_filter,
            )) required += 1;
        }
        if (out.len < required) return error.MatchBufferTooSmall;

        var written: usize = 0;
        for (self.entries.items) |maybe_entry| {
            const entry = maybe_entry orelse continue;
            const remaining = remainingExpiry(entry, now.nanoseconds);
            if (remaining == 0 or !mqtt.topicMatchesFilter(
                entry.topic,
                effective_filter,
            )) continue;
            out[written] = matchForEntry(entry, remaining);
            written += 1;
        }
        std.debug.assert(written == required);
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
        try mqtt.validateTopicFilter(subscription.topic_filter);
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

        var required: usize = 0;
        const effective_filter = effectiveFilter(
            subscription.topic_filter,
        );
        if (!mqtt.hasWildcards(effective_filter)) {
            const entry_index = self.index.get(effective_filter) orelse
                return out[0..0];
            const entry = self.entries.items[entry_index].?;
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
            );
            return out[0..1];
        }
        for (self.entries.items) |maybe_entry| {
            const entry = maybe_entry orelse continue;
            if (remainingExpiry(entry, now.nanoseconds) == 0) continue;
            if (skipNoLocal(entry, subscription, context)) continue;
            if (mqtt.topicMatchesFilter(
                entry.topic,
                effective_filter,
            )) required += 1;
        }
        if (out.len < required) return error.MatchBufferTooSmall;

        var written: usize = 0;
        for (self.entries.items) |maybe_entry| {
            const entry = maybe_entry orelse continue;
            const remaining = remainingExpiry(entry, now.nanoseconds);
            if (skipNoLocal(entry, subscription, context)) continue;
            if (remaining == 0 or !mqtt.topicMatchesFilter(
                entry.topic,
                effective_filter,
            )) continue;
            out[written] = deliveryForEntry(
                entry,
                subscription.qos,
                context.subscription_identifier,
                remaining,
            );
            written += 1;
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
    now_ns: i96,
) Error!Entry {
    const topic_owned = try allocator.dupe(u8, topic);
    errdefer allocator.free(topic_owned);
    const payload_owned = try allocator.dupe(u8, payload);
    errdefer allocator.free(payload_owned);
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
        topic_owned.len + payload_owned.len,
        property_result.allocation_bytes,
    ) catch return error.RetainedLimitExceeded;
    return .{
        .topic = topic_owned,
        .payload = payload_owned,
        .qos = qos,
        .properties = property_result.properties,
        .publisher_id = publisher_id,
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

fn remainingExpiry(entry: Entry, now_ns: i96) ?u32 {
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

fn matchForEntry(entry: Entry, remaining: ?u32) Match {
    return .{
        .topic = entry.topic,
        .payload = entry.payload,
        .qos = entry.qos,
        .properties = entry.properties,
        .publisher_id = entry.publisher_id,
        .message_expiry_interval = remaining,
    };
}

fn deliveryForEntry(
    entry: Entry,
    subscription_qos: mqtt.QoS,
    subscription_identifier: ?usize,
    remaining: ?u32,
) Delivery {
    return .{
        .topic = entry.topic,
        .payload = entry.payload,
        .qos = minQos(entry.qos, subscription_qos),
        // Retained messages sent because of a subscription always carry
        // RETAIN=1, independent of Retain As Published.
        .retain = true,
        .properties = entry.properties,
        .subscription_identifier = subscription_identifier,
        .message_expiry_interval = remaining,
    };
}

fn skipNoLocal(
    entry: Entry,
    subscription: mqtt.Subscription,
    context: DeliveryContext,
) bool {
    if (!subscription.no_local) return false;
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
