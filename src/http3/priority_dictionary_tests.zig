//! Request metadata and persistent control hints share RFC 9218 semantics.
const std = @import("std");
const http3 = @import("mod.zig");
const vectors = @import("../internal/priority/test_vectors.zig");
const routing = @import("runtime/receive/routing/request.zig");
const lifecycle = @import("runtime/stream/lifecycle.zig");

test "HTTP/3 Priority Dictionaries survive control cloning and request lifecycle admission" {
    const allocator = std.testing.allocator;
    for (vectors.dictionaries) |case| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try (http3.Request{ .method = "GET", .scheme = "https", .authority = "example.test", .path = "/priority", .headers = &.{.{ .name = "priority", .value = case.field }} }).write(&encoded, allocator);
        var request = try http3.decodeRequest(allocator, encoded.items);
        defer request.deinit(allocator);
        const header_priority = for (request.headers) |field| {
            if (std.mem.eql(u8, field.name, "priority")) break http3.Priority.parse(field.value);
        } else return error.TestUnexpectedResult;
        try std.testing.expectEqual(case.urgency, header_priority.urgency);
        try std.testing.expectEqual(case.incremental, header_priority.incremental);
        encoded.clearRetainingCapacity();
        try http3.writePriorityUpdateFrameRaw(&encoded, allocator, http3.FrameType.priority_update_request, 0, case.field);
        var control = http3.ControlState{};
        defer control.deinit(allocator);
        control.settings.received = true;
        try control.applyFrame(allocator, try http3.Frame.parse(encoded.items));
        var copy = try control.clone(allocator);
        defer copy.deinit(allocator);
        const priority = copy.requestPriorityUpdate(0).?.priority();
        try std.testing.expectEqual(case.urgency, priority.urgency);
        try std.testing.expectEqual(case.incremental, priority.incremental);
        var requests = lifecycle.Server.init(allocator);
        defer requests.deinit();
        try routing.serverRequestReceived(&copy, &requests, 0, .{ .urgency = 7, .incremental = true });
        try std.testing.expectEqual(case.urgency, requests.priority(0).urgency);
        try std.testing.expectEqual(case.incremental, requests.priority(0).incremental);
        try std.testing.expect(copy.requestPriorityUpdate(0) == null);
        routing.finishServerRequest(&copy, &requests, 0);
    }
}
