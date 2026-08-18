//! Shared owned Application Message used by broker delivery queues.
//!
//! Topic, payload, and variable-length MQTT 5 properties are cloned once and
//! reference-counted across every matching subscriber. Message Expiry is
//! evaluated again at the actual network write, so time spent behind Receive
//! Maximum backpressure cannot extend a message's lifetime.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");
const retained = @import("../retained/mod.zig");

pub const Error = mqtt.Error || error{
    PublicationLimitExceeded,
};

pub const Publication = struct {
    allocator: std.mem.Allocator,
    references: std.atomic.Value(usize),
    bytes: []u8,
    topic_len: usize,
    properties: []mqtt.Property,
    stored_at_ns: i96,
    expiry_interval: ?u32,

    pub fn createFromPublish(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
        reference_count: usize,
        now: std.Io.Timestamp,
    ) Error!*Publication {
        return create(
            allocator,
            publish.topic,
            publish.payload,
            publish.properties,
            reference_count,
            now,
            mqtt.messageExpiryInterval(publish.properties),
        );
    }

    pub fn createFromRetained(
        allocator: std.mem.Allocator,
        delivery: retained.Delivery,
        reference_count: usize,
        now: std.Io.Timestamp,
    ) Error!*Publication {
        return create(
            allocator,
            delivery.topic,
            delivery.payload,
            delivery.properties,
            reference_count,
            now,
            delivery.message_expiry_interval,
        );
    }

    fn create(
        allocator: std.mem.Allocator,
        topic_bytes: []const u8,
        payload_bytes: []const u8,
        properties: []const mqtt.Property,
        reference_count: usize,
        now: std.Io.Timestamp,
        expiry_interval: ?u32,
    ) Error!*Publication {
        std.debug.assert(reference_count != 0);
        const bytes_len = std.math.add(
            usize,
            topic_bytes.len,
            payload_bytes.len,
        ) catch return error.PublicationLimitExceeded;
        const bytes = try allocator.alloc(u8, bytes_len);
        errdefer allocator.free(bytes);
        @memcpy(bytes[0..topic_bytes.len], topic_bytes);
        @memcpy(bytes[topic_bytes.len..], payload_bytes);

        const property_result = owned_properties.clone(
            allocator,
            properties,
            keepForwardProperty,
        ) catch |err| switch (err) {
            error.OwnedPropertyLimitExceeded => return error.PublicationLimitExceeded,
            else => return @errorCast(err),
        };
        errdefer owned_properties.deinit(
            allocator,
            property_result.properties,
        );

        const publication = try allocator.create(Publication);
        publication.* = .{
            .allocator = allocator,
            .references = .init(reference_count),
            .bytes = bytes,
            .topic_len = topic_bytes.len,
            .properties = property_result.properties,
            .stored_at_ns = now.nanoseconds,
            .expiry_interval = expiry_interval,
        };
        return publication;
    }

    pub fn topic(self: Publication) []const u8 {
        return self.bytes[0..self.topic_len];
    }

    pub fn payload(self: Publication) []const u8 {
        return self.bytes[self.topic_len..];
    }

    /// Build delivery properties and return false when Message Expiry elapsed.
    pub fn appendDeliveryProperties(
        self: Publication,
        out: *std.ArrayList(mqtt.Property),
        allocator: std.mem.Allocator,
        protocol: mqtt.ProtocolVersion,
        subscription_identifier: ?usize,
        now: std.Io.Timestamp,
    ) Error!bool {
        const remaining = remainingExpiry(
            self.expiry_interval,
            self.stored_at_ns,
            now.nanoseconds,
        );
        if (remaining == 0) return false;
        if (protocol == .v3_1_1) return true;
        try out.ensureTotalCapacity(
            allocator,
            self.properties.len +
                @intFromBool(subscription_identifier != null),
        );
        for (self.properties) |property| {
            if (property == .four_byte and
                property.four_byte.id == .message_expiry_interval)
            {
                out.appendAssumeCapacity(.{ .four_byte = .{
                    .id = .message_expiry_interval,
                    .value = remaining.?,
                } });
            } else {
                out.appendAssumeCapacity(property);
            }
        }
        if (subscription_identifier) |identifier| {
            out.appendAssumeCapacity(.{ .varint = .{
                .id = .subscription_identifier,
                .value = identifier,
            } });
        }
        return true;
    }

    pub fn release(self: *Publication) void {
        const previous = self.references.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        if (previous != 1) return;
        const allocator = self.allocator;
        owned_properties.deinit(allocator, self.properties);
        allocator.free(self.bytes);
        self.* = undefined;
        allocator.destroy(self);
    }
};

fn keepForwardProperty(property: mqtt.Property) bool {
    // Topic Alias is scoped to the publisher connection. Subscription
    // Identifier is generated from each matching broker subscription below.
    return !((property == .two_byte and
        property.two_byte.id == .topic_alias) or
        (property == .varint and
            property.varint.id == .subscription_identifier));
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

test "publication strips aliases and decrements expiry at queue write" {
    const allocator = std.testing.allocator;
    var source_properties = [_]mqtt.Property{
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
        .{ .four_byte = .{
            .id = .message_expiry_interval,
            .value = 10,
        } },
    };
    const publish = mqtt.Publish{
        .dup = false,
        .qos = .at_least_once,
        .retain = true,
        .topic = "state",
        .packet_id = 1,
        .properties = &source_properties,
        .payload = "on",
    };
    const publication = try Publication.createFromPublish(
        allocator,
        publish,
        1,
        std.Io.Timestamp.fromNanoseconds(2 * std.time.ns_per_s),
    );
    defer publication.release();

    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(allocator);
    try std.testing.expect(try publication.appendDeliveryProperties(
        &properties,
        allocator,
        .v5,
        7,
        std.Io.Timestamp.fromNanoseconds(5 * std.time.ns_per_s),
    ));
    try std.testing.expectEqual(@as(usize, 2), properties.items.len);
    try std.testing.expectEqual(
        @as(?u32, 7),
        mqtt.messageExpiryInterval(properties.items),
    );
    try std.testing.expectEqual(
        @as(?usize, 7),
        mqtt.subscriptionIdentifier(properties.items),
    );

    properties.clearRetainingCapacity();
    try std.testing.expect(try publication.appendDeliveryProperties(
        &properties,
        allocator,
        .v3_1_1,
        7,
        std.Io.Timestamp.fromNanoseconds(5 * std.time.ns_per_s),
    ));
    try std.testing.expectEqual(@as(usize, 0), properties.items.len);
}
