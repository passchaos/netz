//! Fresh-session subscription recovery advances only after successful SUBACK.
const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");

pub fn run(comptime Error: type, client: anytype, deadline: ?std.Io.Clock.Timestamp) Error!void {
    const active = client.connection() orelse return error.ConnectionUnavailable;
    // A preserved broker Session may contain only the accepted prefix from a
    // failed recovery attempt. Continue its suffix, retaining the exact owned
    // options and properties rather than replaying already confirmed filters.
    while (client.subscription_replay_index) |index| {
        if (index == client.subscriptions.items.len) {
            client.subscription_replay_index = null;
            return;
        }
        const stored = client.subscriptions.items[index];
        const one = [_]mqtt.Subscription{stored.value()};
        const options = runtime.SubscribeOptions{ .properties = stored.properties };
        var suback = if (deadline) |absolute|
            try active.subscribeWithDeadline(&one, options, absolute)
        else
            try active.subscribe(&one, options);
        defer suback.deinit(client.allocator);
        if (suback.suback.reason_codes[0] >= 0x80) return error.SubscriptionRefused;
        client.subscription_replay_index = index + 1;
    }
}
