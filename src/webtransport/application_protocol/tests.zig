const std = @import("std");
const protocol = @import("../application_protocol.zig");
const http3 = @import("../../http3/mod.zig");

test "WebTransport application protocol fields preserve escaped string values and preference order" {
    const allocator = std.testing.allocator;
    const values = [_][]const u8{ "horizon.v2", "quoted\"value", "back\\slash", "" };
    const encoded = try protocol.writeList(allocator, &values);
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("\"horizon.v2\", \"quoted\\\"value\", \"back\\\\slash\", \"\"", encoded);
    const fields = [_]http3.Qpack.HeaderField{.{ .name = protocol.available_header, .value = encoded }};
    const offered = protocol.offered(&fields).?;
    try std.testing.expectEqual(@as(usize, 4), offered.count);
    var items = offered.iterator();
    for (values) |value| try std.testing.expect(items.next().?.eql(value));
    try std.testing.expect(items.next() == null);
    try std.testing.expectEqualStrings("horizon.v2", offered.choose(&.{ "back\\slash", "horizon.v2" }).?);
    const response = [_]http3.Qpack.HeaderField{.{ .name = protocol.selected_header, .value = "\"quoted\\\"value\";version=2" }};
    const selected = (try protocol.validateResponse(&fields, &response, true)).?;
    var out: [32]u8 = undefined;
    try std.testing.expectEqualStrings("quoted\"value", try selected.decodeInto(&out));
}

test "WebTransport application protocols ignore valid RFC9651 parameters of every value type" {
    const fields = [_]http3.Qpack.HeaderField{.{
        .name = protocol.available_header,
        .value = "\"p1\"; flag;v=123;d=1.125;b=?0;bytes=:YWJj:;s=\"x\";t=token;date=@-123;label=%\"%e4%bd%a0%e5%a5%bd\", \"p2\"",
    }};
    const offered = protocol.offered(&fields).?;
    try std.testing.expectEqual(@as(usize, 2), offered.count);
    try std.testing.expect(offered.containsValue("p1"));
    try std.testing.expect(offered.containsValue("p2"));
    const response = [_]http3.Qpack.HeaderField{.{ .name = protocol.selected_header, .value = "\"p2\"; date=@123;label=%\"%22%25\"" }};
    try std.testing.expect((try protocol.validateResponse(&fields, &response, true)).?.eql("p2"));
    for ([_][]const u8{ "\"p1\"; d=1234567890123.1", "\"p1\";date=@1.2", "\"p1\";label=%\"%+a\"", "\"p1\";label=%\"%ff\"", "\"p1\";label=%\"%c2\"" }) |invalid| {
        try std.testing.expect(protocol.offered(&.{.{ .name = protocol.available_header, .value = invalid }}) == null);
    }
}

test "WebTransport application protocol fields ignore the entire malformed or non-string value" {
    const request = [_]http3.Qpack.HeaderField{.{ .name = protocol.available_header, .value = "\"p1\", \"p2\"" }};
    for ([_][]const u8{ "p1", "?1", "42", "(\"p1\")", "\"p1\", 42", "\"p1\",", "\"p1\" trailing", "\"bad\\x\"", "\"p1\", \"bad\x7f\"" }) |value| {
        try std.testing.expect(protocol.offered(&.{.{ .name = protocol.available_header, .value = value }}) == null);
    }
    for ([_][]const u8{ "p1", "?1", "42", "(\"p1\")", "\"p1\", \"p2\"", "\"p1\" trailing", "\"bad\\x\"" }) |value| {
        const response = [_]http3.Qpack.HeaderField{.{ .name = protocol.selected_header, .value = value }};
        try std.testing.expect(try protocol.validateResponse(&request, &response, false) == null);
        try std.testing.expectError(error.ApplicationProtocolNegotiationFailed, protocol.validateResponse(&request, &response, true));
    }
    try std.testing.expectError(error.ApplicationProtocolNegotiationFailed, protocol.validateResponse(&request, &.{.{ .name = protocol.selected_header, .value = "\"unoffered\"" }}, false));
    try std.testing.expectError(error.ApplicationProtocolNegotiationFailed, protocol.validateResponse(&.{}, &.{.{ .name = protocol.selected_header, .value = "\"p1\"" }}, false));
}

test "WebTransport application protocol lists combine field lines and single selection rejects duplication" {
    const request = [_]http3.Qpack.HeaderField{
        .{ .name = "WT-Available-Protocols", .value = "\"p2\"" },
        .{ .name = protocol.available_header, .value = "\"p1\";v=2" },
    };
    const offered = protocol.offered(&request).?;
    try std.testing.expectEqualStrings("p2", offered.choose(&.{ "p1", "p2" }).?);
    const response = [_]http3.Qpack.HeaderField{
        .{ .name = protocol.selected_header, .value = "\"p1\"" },
        .{ .name = "WT-Protocol", .value = "\"p1\"" },
    };
    try std.testing.expect(try protocol.validateResponse(&request, &response, false) == null);
    try std.testing.expectError(error.ApplicationProtocolNegotiationFailed, protocol.validateResponse(&request, &response, true));
    try std.testing.expect(protocol.offered(&.{ request[0], .{ .name = protocol.available_header, .value = "" } }) == null);
    const empty = protocol.offered(&.{.{ .name = protocol.available_header, .value = "" }}).?;
    try std.testing.expectEqual(@as(usize, 0), empty.count);
    try std.testing.expect(protocol.offered(&.{}) == null);
}

test "WebTransport application protocol validation precedes allocation and short decoding is atomic" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidApplicationProtocol, protocol.writeList(failing.allocator(), &.{ "ok", "bad\n" }));
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectError(error.OutOfMemory, protocol.writeItem(failing.allocator(), "valid"));
    const value = protocol.selected(&.{.{ .name = protocol.selected_header, .value = "\"long\"" }}).?;
    var output = [_]u8{0xa5} ** 3;
    try std.testing.expectError(error.BufferTooSmall, value.decodeInto(&output));
    try std.testing.expectEqualSlices(u8, &.{ 0xa5, 0xa5, 0xa5 }, &output);
}

test "WebTransport application protocol request snapshots validate before allocation and own values" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidApplicationProtocol, protocol.Request.init(failing.allocator(), .{ .required = true }, &.{.{ .name = protocol.available_header, .value = "42" }}));
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectError(error.InvalidApplicationProtocol, protocol.Request.init(failing.allocator(), .{ .values = &.{"p1"} }, &.{.{ .name = protocol.available_header, .value = "\"p1\"" }}));
    try std.testing.expect(!failing.has_induced_failure);
    var value = [_]u8{ 'p', '1' };
    var request = try protocol.Request.init(allocator, .{ .values = &.{&value}, .required = true }, &.{});
    defer request.deinit(allocator);
    value = .{ 'x', 'x' };
    try std.testing.expect((try request.validateResponse(&.{.{ .name = protocol.selected_header, .value = "\"p1\"" }})).?.eql("p1"));
    try std.testing.expectError(error.ApplicationProtocolNegotiationFailed, request.validateResponse(&.{.{ .name = protocol.selected_header, .value = "\"xx\"" }}));
}
