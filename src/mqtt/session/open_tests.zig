const std = @import("std");
const session = @import("mod.zig");

test "session failed replacement allocation preserves prior subscriptions and QoS state" {
    for (0..3) |mode| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var store = session.Store.init(failing.allocator(), .{ .max_sessions = 1 });
        defer store.deinit();
        const old = try store.open("replace-client", false, if (mode == 2) 0 else 60, .zero);
        _ = try store.setSubscription(old.handle, .{ .topic_filter = "devices/+", .qos = .at_least_once }, 17);
        _ = try store.enqueuePublish(old.handle, "devices/one", "inflight", .{ .qos = .at_least_once, .now = .zero });
        var transmissions: [1]session.Transmission = undefined;
        _ = try store.drainInto(old.handle, .zero, 1, &transmissions);
        _ = try store.enqueuePublish(old.handle, "devices/two", "queued", .{ .qos = .exactly_once, .now = .zero });
        if (mode == 1) try store.disconnect(old.handle, null, .zero);
        const before = try store.stats(old.handle);
        const bytes = store.total_bytes;
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, store.open("replace-client", mode != 2, 60, .zero));
        const preserved = store.find("replace-client", .zero) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(old.handle, preserved);
        try std.testing.expectEqualDeep(before, try store.stats(old.handle));
        try std.testing.expectEqual(bytes, store.total_bytes);
    }
}

test "session rejected replacement limits leave the previous session intact" {
    var store = session.Store.init(std.testing.allocator, .{ .max_sessions = 1 });
    defer store.deinit();
    const old = try store.open("replacement-limits", false, 60, .zero);
    _ = try store.setSubscription(old.handle, .{ .topic_filter = "devices/+" }, 8);
    _ = try store.enqueuePublish(old.handle, "devices/one", "keep", .{ .qos = .at_least_once, .now = .zero });
    const before = try store.stats(old.handle);
    store.options.max_session_bytes = "replacement-limits".len - 1;
    try std.testing.expectError(error.SessionByteLimitExceeded, store.open("replacement-limits", true, 60, .zero));
    try std.testing.expectEqualDeep(before, try store.stats(old.handle));
    store.options.max_session_bytes = 64 * 1024 * 1024;
    store.options.max_sessions = 0;
    try std.testing.expectError(error.SessionLimitExceeded, store.open("replacement-limits", true, 60, .zero));
    try std.testing.expectEqualDeep(before, try store.stats(old.handle));
}

test "session replacement credits the old allocation and owns a borrowed ClientID before retirement" {
    var store = session.Store.init(std.testing.allocator, .{ .max_sessions = 1 });
    defer store.deinit();
    const old = try store.open("borrowed-replacement", false, 1, .zero);
    _ = try store.setSubscription(old.handle, .{ .topic_filter = "devices/+" }, 8);
    _ = try store.enqueuePublish(old.handle, "devices/one", "retired", .{ .qos = .at_least_once, .now = .zero });
    store.options.max_total_bytes = store.totalBytes();
    const id = try store.clientId(old.handle);
    const replaced = try store.open(id, true, 60, .zero);
    try std.testing.expect(replaced.replaced_connection);
    try std.testing.expect(!replaced.session_present);
    try std.testing.expect(replaced.route_id != old.route_id);
    try std.testing.expectError(error.SessionNotFound, store.stats(old.handle));
    try std.testing.expectEqualStrings("borrowed-replacement", try store.clientId(replaced.handle));
    try std.testing.expectEqual(@as(usize, "borrowed-replacement".len), store.totalBytes());
    try std.testing.expectEqual(@as(usize, 0), (try store.stats(replaced.handle)).queued_count);
    try std.testing.expectEqual(@as(usize, 0), (try store.stats(replaced.handle)).subscription_count);
    try store.disconnect(replaced.handle, null, .zero);
    const expired_id = try store.clientId(replaced.handle);
    const after_expiry = try store.open(expired_id, false, 60, .fromNanoseconds(61 * std.time.ns_per_s));
    try std.testing.expect(!after_expiry.session_present);
    try std.testing.expectEqualStrings("borrowed-replacement", try store.clientId(after_expiry.handle));
}
