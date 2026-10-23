//! Owned Will data and resource admission before lifecycle changes.

const std = @import("std");
const mqtt = @import("../mod.zig");
const will_mod = @import("mod.zig");
const owned_properties = @import("../owned_properties.zig");

const State = enum {
    connected,
    scheduled,
    /// Removed from the deadline heap by `pollDue`; publication is now
    /// committed and a later reconnect must not suppress or reschedule it.
    due,
};

pub const Entry = struct {
    generation: u64,
    client_id: []u8,
    source_username: ?[]u8,
    source_listener_id: ?u64,
    topic: []u8,
    payload: []u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []mqtt.Property,
    will_delay_interval: u32,
    message_expiry_interval: ?u32,
    session_expiry_interval: u32,
    state: State = .connected,
    deadline_ns: i96 = 0,
    heap_index: ?usize = null,
    allocation_bytes: usize,

    pub fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        owned_properties.deinit(allocator, self.properties);
        if (self.source_username) |value| allocator.free(value);
        allocator.free(self.payload);
        allocator.free(self.topic);
        allocator.free(self.client_id);
        self.* = undefined;
    }
};

pub fn prepare(
    allocator: std.mem.Allocator,
    options: will_mod.Options,
    client_id: []const u8,
    will: mqtt.LastWill,
    source_username: ?[]const u8,
    source_listener_id: ?u64,
    session_expiry_interval: u32,
    final_count: usize,
    final_base_bytes: usize,
) will_mod.Error!Entry {
    try mqtt.validateTopicName(will.topic);
    try mqtt.validateWillProperties(will.properties, will.payload);
    if (final_count > options.max_wills) {
        return error.WillLimitExceeded;
    }

    const client_owned = try allocator.dupe(u8, client_id);
    errdefer allocator.free(client_owned);
    const source_username_owned = if (source_username) |value|
        try allocator.dupe(u8, value)
    else
        null;
    errdefer if (source_username_owned) |value| allocator.free(value);
    const topic_owned = try allocator.dupe(u8, will.topic);
    errdefer allocator.free(topic_owned);
    const payload_owned = try allocator.dupe(u8, will.payload);
    errdefer allocator.free(payload_owned);
    const property_result = owned_properties.clone(
        allocator,
        will.properties,
        owned_properties.keepAll,
    ) catch |err| switch (err) {
        error.OwnedPropertyLimitExceeded => return error.WillByteLimitExceeded,
        else => return @errorCast(err),
    };
    errdefer owned_properties.deinit(
        allocator,
        property_result.properties,
    );
    const bytes = std.math.add(
        usize,
        client_owned.len + topic_owned.len + payload_owned.len,
        if (source_username_owned) |value| value.len else 0,
    ) catch return error.WillByteLimitExceeded;
    const total_bytes = std.math.add(
        usize,
        bytes,
        property_result.allocation_bytes,
    ) catch return error.WillByteLimitExceeded;
    if (total_bytes > options.max_will_bytes or
        total_bytes > options.max_total_bytes -| final_base_bytes)
    {
        return error.WillByteLimitExceeded;
    }

    return .{
        // Generation is assigned only after every installation resource
        // has been reserved and the entry can be committed.
        .generation = 0,
        .client_id = client_owned,
        .source_username = source_username_owned,
        .source_listener_id = source_listener_id,
        .topic = topic_owned,
        .payload = payload_owned,
        .qos = will.qos,
        .retain = will.retain,
        .properties = property_result.properties,
        .will_delay_interval = mqtt.willDelayInterval(will.properties) orelse 0,
        .message_expiry_interval = mqtt.messageExpiryInterval(will.properties),
        .session_expiry_interval = session_expiry_interval,
        .allocation_bytes = total_bytes,
    };
}
