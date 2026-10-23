const std = @import("std");
const session = @import("mod.zig");

test "session prepared open abort preserves old state and reserved slot accounting" {
    const allocator = std.testing.allocator;
    for (0..4) |mode| {
        var store = session.Store.init(allocator, .{ .max_sessions = 2 });
        defer store.deinit();
        const old = try store.open("prepared-client", false, if (mode == 2) 0 else 60, .zero);
        _ = try store.setSubscription(old.handle, .{ .topic_filter = "prepared/+", .qos = .at_least_once }, 7);
        _ = try store.enqueuePublish(old.handle, "prepared/one", "keep", .{ .qos = .at_least_once, .now = .zero });
        const before = try store.stats(old.handle);
        const bytes = store.totalBytes();
        const slots = store.sessions.items.len;
        const generation = store.next_generation;
        const route = store.next_route_id;
        var prepared = try store.prepareOpen(if (mode == 3) "another-client" else "prepared-client", mode == 0 or mode == 3, 0, .zero);
        try std.testing.expectEqualDeep(before, try store.stats(old.handle));
        prepared.deinit();
        try std.testing.expectEqualDeep(before, try store.stats(old.handle));
        try std.testing.expectEqual(bytes, store.totalBytes());
        try std.testing.expectEqual(slots, store.sessions.items.len);
        try std.testing.expectEqual(generation, store.next_generation);
        try std.testing.expectEqual(route, store.next_route_id);
    }
}

test "session prepared open commit advances capability without allocating" {
    for ([_]bool{ false, true }) |clean_start| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var store = session.Store.init(failing.allocator(), .{ .max_sessions = 1 });
        defer store.deinit();
        const old = try store.open("commit-client", false, 60, .zero);
        _ = try store.setSubscription(old.handle, .{ .topic_filter = "prepared/+", .qos = .at_least_once }, 7);
        var prepared = try store.prepareOpen("commit-client", clean_start, 0, .zero);
        defer prepared.deinit();
        failing.fail_index = failing.alloc_index;
        const current = store.commitOpen(&prepared);
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(!clean_start, current.session_present);
        try std.testing.expect(current.replaced_connection);
        try std.testing.expectError(error.SessionNotFound, store.stats(old.handle));
        try std.testing.expectEqual(@as(usize, @intFromBool(!clean_start)), (try store.stats(current.handle)).subscription_count);
        try std.testing.expectEqual(@as(u32, 0), (try store.stats(current.handle)).expiry_interval);
    }
}

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
