//! Prepared CONNACK bytes and scalar negotiation. Construction performs no
//! wire write or negotiated-state mutation; the owner applies state on send.

const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    owner: *runtime.Connection,
    encoded: std.ArrayList(u8) = .empty,
    fixed: [mqtt.ConnAck.no_properties_max_len]u8 = undefined,
    byte_len: usize = 0,
    max_incoming_inflight: u16,
    keep_alive_seconds: u16,
    session_expiry_interval: u32,
    incoming_topic_alias_maximum: u16,
    local_maximum_qos: mqtt.QoS,
    local_retain_available: bool,
    local_wildcard_subscription_available: bool,
    local_subscription_identifier_available: bool,
    local_shared_subscription_available: bool,
    written: bool = false,

    pub fn bytes(self: *Prepared) []u8 {
        return if (self.encoded.items.len != 0) self.encoded.items else self.fixed[0..self.byte_len];
    }

    pub fn apply(self: *Prepared, connection: *runtime.Connection) void {
        std.debug.assert(self.owner == connection);
        connection.max_incoming_inflight = self.max_incoming_inflight;
        connection.keep_alive_seconds = self.keep_alive_seconds;
        connection.session_expiry_interval = self.session_expiry_interval;
        connection.incoming_topic_alias_maximum = self.incoming_topic_alias_maximum;
        connection.capabilities.local_maximum_qos = self.local_maximum_qos;
        connection.capabilities.local_retain_available = self.local_retain_available;
        connection.capabilities.local_wildcard_subscription_available = self.local_wildcard_subscription_available;
        connection.capabilities.local_subscription_identifier_available = self.local_subscription_identifier_available;
        connection.capabilities.local_shared_subscription_available = self.local_shared_subscription_available;
    }

    /// Synchronous writers borrow the owner's existing control-packet buffer.
    /// Return it before disposing their short-lived plan, including on error.
    pub fn returnScratch(self: *Prepared, connection: *runtime.Connection) void {
        std.debug.assert(self.owner == connection);
        std.mem.swap(std.ArrayList(u8), &self.encoded, &connection.write_scratch);
        self.byte_len = 0;
    }

    pub fn deinit(self: *Prepared) void {
        self.encoded.deinit(self.allocator);
        self.* = undefined;
    }
};

pub fn prepare(self: *runtime.Connection, options: runtime.ConnAckOptions) runtime.Error!Prepared {
    return prepareMode(self, options, false);
}

pub fn prepareReusingScratch(self: *runtime.Connection, options: runtime.ConnAckOptions) runtime.Error!Prepared {
    return prepareMode(self, options, true);
}

fn prepareMode(self: *runtime.Connection, options: runtime.ConnAckOptions, reuse_scratch: bool) runtime.Error!Prepared {
    var prepared = Prepared{
        .allocator = self.allocator,
        .owner = self,
        .max_incoming_inflight = self.max_incoming_inflight,
        .keep_alive_seconds = self.keep_alive_seconds,
        .session_expiry_interval = self.session_expiry_interval,
        .incoming_topic_alias_maximum = self.incoming_topic_alias_maximum,
        .local_maximum_qos = self.capabilities.local_maximum_qos,
        .local_retain_available = self.capabilities.local_retain_available,
        .local_wildcard_subscription_available = self.capabilities.local_wildcard_subscription_available,
        .local_subscription_identifier_available = self.capabilities.local_subscription_identifier_available,
        .local_shared_subscription_available = self.capabilities.local_shared_subscription_available,
    };
    if (reuse_scratch) std.mem.swap(std.ArrayList(u8), &prepared.encoded, &self.write_scratch);
    errdefer {
        if (reuse_scratch) prepared.returnScratch(self);
        prepared.deinit();
    }
    const accepted = options.reason_code == 0;
    if (accepted and self.protocol == .v5) if (mqtt.sessionExpiryInterval(options.properties)) |interval| {
        prepared.session_expiry_interval = interval;
    };
    const accepted_v5 = accepted and self.protocol == .v5;
    const add_receive_maximum = accepted_v5 and
        mqtt.receiveMaximum(options.properties) == null and
        options.max_outgoing_inflight != std.math.maxInt(u16);
    const add_maximum_packet_size = accepted_v5 and
        mqtt.maximumPacketSize(options.properties) == null and
        self.limits.max_packet_size <= std.math.maxInt(u32);
    const add_topic_alias_maximum = accepted_v5 and
        options.topic_alias_maximum != 0 and
        mqtt.topicAliasMaximum(options.properties) == null;
    const add_server_keep_alive = accepted_v5 and
        mqtt.serverKeepAlive(options.properties) == null and
        options.server_keep_alive_seconds != null;
    const add_maximum_qos = accepted_v5 and
        mqtt.maximumQoS(options.properties) == null and
        options.maximum_qos != null and
        options.maximum_qos.? != .exactly_once;
    const add_retain_available = accepted_v5 and
        mqtt.retainAvailable(options.properties) == null and
        !options.retain_available;
    const add_wildcard_available = accepted_v5 and
        mqtt.wildcardSubscriptionAvailable(options.properties) == null and
        !options.wildcard_subscription_available;
    const add_subscription_identifier_available = accepted_v5 and
        mqtt.subscriptionIdentifierAvailable(options.properties) == null and
        !options.subscription_identifier_available;
    const add_shared_available = accepted_v5 and
        mqtt.sharedSubscriptionAvailable(options.properties) == null and
        !options.shared_subscription_available;
    const generated_property_count =
        @as(usize, @intFromBool(add_receive_maximum)) +
        @intFromBool(add_maximum_packet_size) +
        @intFromBool(add_topic_alias_maximum) +
        @intFromBool(add_server_keep_alive) +
        @intFromBool(add_maximum_qos) +
        @intFromBool(add_retain_available) +
        @intFromBool(add_wildcard_available) +
        @intFromBool(add_subscription_identifier_available) +
        @intFromBool(add_shared_available);
    var property_stack: [runtime.write_property_staging_capacity]mqtt.Property =
        undefined;
    var properties = try self.writePropertyList(
        &property_stack,
        std.math.add(
            usize,
            options.properties.len,
            generated_property_count,
        ) catch
            return error.OutOfMemory,
    );
    properties.appendSliceAssumeCapacity(options.properties);
    // Negotiated capabilities describe an accepted connection. On a
    // refusal, preserve only caller-supplied diagnostic properties so a
    // bare error CONNACK stays byte-compatible with common brokers.
    if (add_receive_maximum) {
        properties.appendAssumeCapacity(.{ .two_byte = .{ .id = .receive_maximum, .value = options.max_outgoing_inflight } });
    }
    if (add_maximum_packet_size) {
        properties.appendAssumeCapacity(.{ .four_byte = .{ .id = .maximum_packet_size, .value = @intCast(self.limits.max_packet_size) } });
    }
    if (add_topic_alias_maximum) {
        properties.appendAssumeCapacity(.{ .two_byte = .{
            .id = .topic_alias_maximum,
            .value = options.topic_alias_maximum,
        } });
    }
    if (add_server_keep_alive) {
        properties.appendAssumeCapacity(.{ .two_byte = .{
            .id = .server_keep_alive,
            .value = options.server_keep_alive_seconds.?,
        } });
    }
    if (add_maximum_qos) {
        properties.appendAssumeCapacity(.{ .byte = .{
            .id = .maximum_qos,
            .value = @intFromEnum(options.maximum_qos.?),
        } });
    }
    if (add_retain_available) {
        properties.appendAssumeCapacity(.{ .byte = .{ .id = .retain_available, .value = 0 } });
    }
    if (add_wildcard_available) {
        properties.appendAssumeCapacity(.{ .byte = .{ .id = .wildcard_subscription_available, .value = 0 } });
    }
    if (add_subscription_identifier_available) {
        properties.appendAssumeCapacity(.{ .byte = .{ .id = .subscription_identifier_available, .value = 0 } });
    }
    if (add_shared_available) {
        properties.appendAssumeCapacity(.{ .byte = .{ .id = .shared_subscription_available, .value = 0 } });
    }
    prepared.encoded.clearRetainingCapacity();
    const bytes = if (self.protocol == .v3_1 and
        options.v3_1_connack_mode == .mosquitto)
        try mqtt.ConnAck.writeMosquittoV31Into(
            &prepared.fixed,
            options.session_present,
            options.reason_code,
        )
    else if (properties.items.len == 0)
        try mqtt.ConnAck.writeNoPropertiesInto(
            &prepared.fixed,
            self.protocol,
            options.session_present,
            options.reason_code,
        )
    else blk: {
        try mqtt.ConnAck.write(
            &prepared.encoded,
            self.allocator,
            self.protocol,
            options.session_present,
            options.reason_code,
            properties.items,
        );
        break :blk prepared.encoded.items;
    };
    prepared.byte_len = bytes.len;
    if (bytes.len > self.peer_max_packet_size) return error.OutgoingPacketTooLarge;
    if (accepted) {
        // This is the Server's own inbound QoS 1/2 limit. MQTT 5 also
        // advertises it as Receive Maximum; MQTT 3.1.1 has no property,
        // but the configured resource bound must still be enforced.
        prepared.max_incoming_inflight = mqtt.receiveMaximum(
            properties.items,
        ) orelse options.max_outgoing_inflight;
    }
    prepared.local_maximum_qos =
        options.maximum_qos orelse .exactly_once;
    prepared.local_retain_available = options.retain_available;
    if (self.protocol == .v5) {
        // Server Keep Alive replaces the CONNECT value for both peers.
        // Updating the accepting endpoint here is essential now that the
        // broker enforces inactivity rather than merely advertising the
        // value to the client.
        prepared.keep_alive_seconds = mqtt.serverKeepAlive(
            properties.items,
        ) orelse prepared.keep_alive_seconds;
        prepared.incoming_topic_alias_maximum = mqtt.topicAliasMaximum(
            properties.items,
        ) orelse options.topic_alias_maximum;
        prepared.local_maximum_qos = mqtt.maximumQoS(
            properties.items,
        ) orelse prepared.local_maximum_qos;
        prepared.local_retain_available = mqtt.retainAvailable(
            properties.items,
        ) orelse prepared.local_retain_available;
        prepared.local_wildcard_subscription_available =
            mqtt.wildcardSubscriptionAvailable(
                properties.items,
            ) orelse options.wildcard_subscription_available;
        prepared.local_subscription_identifier_available =
            mqtt.subscriptionIdentifierAvailable(
                properties.items,
            ) orelse options.subscription_identifier_available;
        prepared.local_shared_subscription_available =
            mqtt.sharedSubscriptionAvailable(
                properties.items,
            ) orelse options.shared_subscription_available;
    }
    return prepared;
}

test "MQTT prepared CONNACK expiry applies only after the wire transaction commits" {
    var connection = runtime.Connection{ .allocator = std.testing.allocator, .transport = undefined, .session_expiry_interval = 60 };
    const properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 3 } }};
    {
        var abandoned = try prepare(&connection, .{ .properties = &properties });
        defer abandoned.deinit();
        try std.testing.expectEqual(@as(u32, 60), connection.sessionExpiryInterval());
    }
    try std.testing.expectEqual(@as(u32, 60), connection.sessionExpiryInterval());
    var accepted = try prepare(&connection, .{ .properties = &properties });
    defer accepted.deinit();
    accepted.apply(&connection);
    try std.testing.expectEqual(@as(u32, 3), connection.sessionExpiryInterval());
    var refused = try prepare(&connection, .{ .reason_code = 0x87, .properties = &properties });
    defer refused.deinit();
    try std.testing.expectEqual(@as(u32, 3), connection.sessionExpiryInterval());
}
