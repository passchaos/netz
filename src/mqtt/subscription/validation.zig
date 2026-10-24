//! Typed subscription metadata shared by codecs, routing and Session storage.
const std = @import("std");
const mqtt = @import("../mod.zig");

/// Validate before reserving storage or changing an existing subscription.
/// Wire codecs additionally enforce their protocol version's option layout.
pub fn validate(subscription: mqtt.Subscription, identifier: ?usize) mqtt.Error!void {
    try mqtt.validateTopicFilter(subscription.topic_filter);
    if (@intFromEnum(subscription.qos) > 2) return error.InvalidQoS;
    if (subscription.retain_handling > 2 or
        (subscription.no_local and std.mem.startsWith(u8, subscription.topic_filter, "$share/")))
    {
        return error.InvalidSubscription;
    }
    if (identifier) |value| {
        if (value == 0 or value > 268_435_455) return error.InvalidProperty;
    }
}
