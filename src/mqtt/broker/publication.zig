//! Shared owned Application Message used by live and offline broker delivery
//! queues.
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

pub const allocation_alignment = 16;
pub const Allocation = []align(allocation_alignment) u8;

pub const Publication = struct {
    allocator: std.mem.Allocator,
    references: std.atomic.Value(usize),
    bytes: []u8,
    allocation_len: u32,
    topic_len: u32,
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
        const allocation_len = std.math.add(
            usize,
            @sizeOf(Publication),
            bytes_len,
        ) catch return error.PublicationLimitExceeded;
        if (allocation_len > std.math.maxInt(u32)) {
            return error.PublicationLimitExceeded;
        }
        const allocation = try allocator.alignedAlloc(
            u8,
            .@"16",
            allocation_len,
        );
        errdefer allocator.free(allocation);
        return initialize(
            allocator,
            allocation,
            topic_bytes,
            payload_bytes,
            properties,
            reference_count,
            now,
            expiry_interval,
        );
    }

    /// Adopt an owned wire packet whose allocation reserved exactly one
    /// `Publication`-sized prefix. Property values are cloned before the wire
    /// bytes are compacted in place, after which the packet must relinquish
    /// ownership to the returned publication.
    pub fn createFromPrefixedPublish(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
        reference_count: usize,
        now: std.Io.Timestamp,
        allocation: Allocation,
        packet_bytes: []u8,
    ) Error!*Publication {
        std.debug.assert(reference_count != 0);
        std.debug.assert(@alignOf(Publication) <= allocation_alignment);
        std.debug.assert(
            @intFromPtr(packet_bytes.ptr) ==
                @intFromPtr(allocation.ptr) + @sizeOf(Publication),
        );
        std.debug.assert(
            allocation.len == @sizeOf(Publication) + packet_bytes.len,
        );
        std.debug.assert(sliceWithin(packet_bytes, publish.topic));
        std.debug.assert(sliceWithin(packet_bytes, publish.payload));

        return initialize(
            allocator,
            allocation,
            publish.topic,
            publish.payload,
            publish.properties,
            reference_count,
            now,
            mqtt.messageExpiryInterval(publish.properties),
        );
    }

    fn initialize(
        allocator: std.mem.Allocator,
        allocation: Allocation,
        topic_bytes: []const u8,
        payload_bytes: []const u8,
        properties: []const mqtt.Property,
        reference_count: usize,
        now: std.Io.Timestamp,
        expiry_interval: ?u32,
    ) Error!*Publication {
        const bytes_len = std.math.add(
            usize,
            topic_bytes.len,
            payload_bytes.len,
        ) catch return error.PublicationLimitExceeded;
        const compact_len = std.math.add(
            usize,
            @sizeOf(Publication),
            bytes_len,
        ) catch return error.PublicationLimitExceeded;
        if (compact_len > allocation.len) {
            return error.PublicationLimitExceeded;
        }
        if (allocation.len > std.math.maxInt(u32)) {
            return error.PublicationLimitExceeded;
        }

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
        const bytes = allocation[@sizeOf(Publication)..compact_len];
        @memmove(bytes[0..topic_bytes.len], topic_bytes);
        @memmove(bytes[topic_bytes.len..], payload_bytes);

        const publication: *Publication = @ptrCast(allocation.ptr);
        publication.* = .{
            .allocator = allocator,
            .references = .init(reference_count),
            .bytes = bytes,
            .allocation_len = @intCast(allocation.len),
            .topic_len = @intCast(topic_bytes.len),
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

    pub fn retain(self: *Publication) void {
        const previous = self.references.fetchAdd(1, .monotonic);
        std.debug.assert(previous != 0);
        std.debug.assert(previous != std.math.maxInt(usize));
    }

    /// Recover the coallocated owner from its complete message-byte slice.
    /// Callers must pass exactly `publication.bytes`, not a topic/payload
    /// subslice. This keeps shared Session storage pointer-sized.
    pub fn ownerForBytes(bytes: []u8) *Publication {
        const address = @intFromPtr(bytes.ptr) - @sizeOf(Publication);
        const publication: *Publication = @ptrFromInt(address);
        std.debug.assert(publication.bytes.ptr == bytes.ptr);
        std.debug.assert(publication.bytes.len == bytes.len);
        return publication;
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
        var storage: [1]usize = undefined;
        const identifiers = if (subscription_identifier) |identifier| blk: {
            storage[0] = identifier;
            break :blk storage[0..1];
        } else storage[0..0];
        return self.appendDeliveryPropertiesMany(
            out,
            allocator,
            protocol,
            identifiers,
            now,
        );
    }

    pub fn appendDeliveryPropertiesMany(
        self: Publication,
        out: *std.ArrayList(mqtt.Property),
        allocator: std.mem.Allocator,
        protocol: mqtt.ProtocolVersion,
        subscription_identifiers: []const usize,
        now: std.Io.Timestamp,
    ) Error!bool {
        const remaining = remainingExpiry(
            self.expiry_interval,
            self.stored_at_ns,
            now.nanoseconds,
        );
        if (remaining == 0) return false;
        if (protocol.isLegacy()) return true;
        const required = std.math.add(
            usize,
            self.properties.len,
            subscription_identifiers.len,
        ) catch return error.InvalidProperty;
        // Stack-first broker writers reserve this exact capacity before the
        // call; ordinary heap-backed callers retain the allocation fallback.
        if (out.capacity < required) {
            try out.ensureTotalCapacity(allocator, required);
        }
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
        for (subscription_identifiers) |identifier| {
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
        const allocation_len: usize = self.allocation_len;
        const allocation: Allocation = @alignCast(
            @as([*]u8, @ptrCast(self))[0..allocation_len],
        );
        owned_properties.deinit(allocator, self.properties);
        self.* = undefined;
        allocator.free(allocation);
    }
};

fn sliceWithin(container: []const u8, child: []const u8) bool {
    const container_start = @intFromPtr(container.ptr);
    const child_start = @intFromPtr(child.ptr);
    if (child_start < container_start) return false;
    const offset = child_start - container_start;
    return offset <= container.len and
        child.len <= container.len - offset;
}

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

    var property_stack: [2]mqtt.Property = undefined;
    var stack_properties = std.ArrayList(mqtt.Property).initBuffer(
        &property_stack,
    );
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expect(try publication.appendDeliveryProperties(
        &stack_properties,
        no_alloc.allocator(),
        .v5,
        7,
        std.Io.Timestamp.fromNanoseconds(5 * std.time.ns_per_s),
    ));
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 2), stack_properties.items.len);

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

test "publication coallocates header and message bytes" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1 },
    );
    const publication = try Publication.createFromPublish(
        failing.allocator(),
        .{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = "coallocated/topic",
            .packet_id = 7,
            .properties = &.{},
            .payload = "payload",
        },
        1,
        std.Io.Timestamp.fromNanoseconds(0),
    );
    defer publication.release();

    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(
        @intFromPtr(publication) + @sizeOf(Publication),
        @intFromPtr(publication.bytes.ptr),
    );
    try std.testing.expectEqual(
        publication,
        Publication.ownerForBytes(publication.bytes),
    );
    publication.retain();
    publication.release();
    try std.testing.expectEqualStrings("coallocated/topic", publication.topic());
    try std.testing.expectEqualStrings("payload", publication.payload());
}

test "publication adopts and compacts a prefixed wire packet" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1 },
    );
    const packet_len = 64;
    const allocation = try failing.allocator().alignedAlloc(
        u8,
        .@"16",
        @sizeOf(Publication) + packet_len,
    );
    var allocation_owned = true;
    defer if (allocation_owned) failing.allocator().free(allocation);
    const packet = allocation[@sizeOf(Publication)..];
    @memset(packet, 0xaa);
    @memcpy(packet[7..24], "coallocated/topic");
    @memcpy(packet[37..44], "payload");

    const publication = try Publication.createFromPrefixedPublish(
        failing.allocator(),
        .{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = packet[7..24],
            .packet_id = 7,
            .properties = &.{},
            .payload = packet[37..44],
        },
        1,
        std.Io.Timestamp.fromNanoseconds(0),
        allocation,
        packet,
    );
    allocation_owned = false;
    defer publication.release();

    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@intFromPtr(allocation.ptr), @intFromPtr(publication));
    try std.testing.expectEqualStrings("coallocated/topic", publication.topic());
    try std.testing.expectEqualStrings("payload", publication.payload());
}

test "prefixed publication adoption is failure-safe with owned properties" {
    const Context = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const packet_len = 64;
            const allocation = try allocator.alignedAlloc(
                u8,
                .@"16",
                @sizeOf(Publication) + packet_len,
            );
            var allocation_owned = true;
            defer if (allocation_owned) allocator.free(allocation);
            const packet = allocation[@sizeOf(Publication)..];
            @memset(packet, 0xaa);
            @memcpy(packet[7..20], "failure/topic");
            @memcpy(packet[20..27], "source!");
            @memcpy(packet[27..31], "test");
            @memcpy(packet[37..44], "payload");
            var properties = [_]mqtt.Property{.{ .utf8_pair = .{
                .id = .user_property,
                .key = packet[20..27],
                .value = packet[27..31],
            } }};

            const publication = try Publication.createFromPrefixedPublish(
                allocator,
                .{
                    .dup = false,
                    .qos = .at_least_once,
                    .retain = false,
                    .topic = packet[7..20],
                    .packet_id = 9,
                    .properties = &properties,
                    .payload = packet[37..44],
                },
                2,
                std.Io.Timestamp.fromNanoseconds(0),
                allocation,
                packet,
            );
            allocation_owned = false;
            try std.testing.expectEqual(
                @as(usize, 1),
                publication.properties.len,
            );
            try std.testing.expectEqualStrings(
                "source!",
                publication.properties[0].utf8_pair.key,
            );
            try std.testing.expectEqualStrings(
                "test",
                publication.properties[0].utf8_pair.value,
            );
            publication.release();
            publication.release();
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Context.run,
        .{},
    );
}

test "publication coallocation is failure-safe with owned properties" {
    const Context = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var properties = [_]mqtt.Property{.{ .utf8_pair = .{
                .id = .user_property,
                .key = "source",
                .value = "test",
            } }};
            const publication = try Publication.createFromPublish(
                allocator,
                .{
                    .dup = false,
                    .qos = .at_least_once,
                    .retain = false,
                    .topic = "failure/topic",
                    .packet_id = 9,
                    .properties = &properties,
                    .payload = "payload",
                },
                2,
                std.Io.Timestamp.fromNanoseconds(0),
            );
            publication.release();
            publication.release();
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Context.run,
        .{},
    );
}
