const std = @import("std");
const http1 = @import("../mod.zig");

test "HTTP/1 folded fields reject fatal bytes even in ignored continuation groups" {
    const allocator = std.testing.allocator;
    const options: http1.ParseOptions = .{ .allow_obs_fold = true, .ignore_invalid_headers_in_requests = true, .ignore_invalid_headers_in_responses = true };
    for ([_]u8{ 0, '\r', '\n' }) |fatal| {
        for ([_][]const u8{ "Malformed field\r\n", "X-Dropped: first\r\n \x01invalid\r\n" }) |discarded| {
            var request_buffer: [512]u8 = undefined;
            const request = try std.fmt.bufPrint(&request_buffer, "GET / HTTP/1.1\r\nHost: example\r\n{s} {c}danger\r\nContent-Length: 0\r\n\r\n", .{ discarded, fatal });
            try expectMalformed(http1.parseRequest(allocator, request, options));
            try expectMalformed(http1.parseOwnedRequestHead(allocator, request, options));
            var response_buffer: [512]u8 = undefined;
            const response = try std.fmt.bufPrint(&response_buffer, "HTTP/1.1 200 OK\r\n{s} {c}danger\r\nContent-Length: 0\r\n\r\n", .{ discarded, fatal });
            try expectMalformed(http1.parseResponse(allocator, response, options));
            try expectMalformed(http1.parseOwnedResponseHead(allocator, response, options, .{}));
        }
    }
}

fn expectMalformed(result: anytype) !void {
    if (result) |value| {
        var unexpected = value;
        unexpected.deinit(std.testing.allocator);
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(error.MalformedHeader, err);
}

test "HTTP/1 folded fields fit a linear allocation budget under repeated continuations" {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try bytes.appendSlice(std.testing.allocator, "HTTP/1.1 200 OK\r\nX-Many: seed");
    for (0..4096) |_| try bytes.appendSlice(std.testing.allocator, "\r\n x");
    try bytes.appendSlice(std.testing.allocator, "\r\nContent-Length: 0\r\n\r\n");
    var storage: [24 * 1024]u8 = undefined;
    var bounded = std.heap.FixedBufferAllocator.init(&storage);
    var response = try http1.parseOwnedResponseHead(bounded.allocator(), bytes.items, .{ .allow_obs_fold = true }, .{});
    defer response.deinit(bounded.allocator());
    const value = response.head.header("x-many").?;
    try std.testing.expectEqual(@as(usize, 4 + 4096 * 2), value.len);
    try std.testing.expectEqualStrings("seed", value[0..4]);
    for (0..4096) |index| try std.testing.expectEqualStrings(" x", value[4 + index * 2 ..][0..2]);
}

test "HTTP/1 folded fields replace empty continuations with whitespace" {
    const bytes = "HTTP/1.1 200 OK\r\nX-Trace: first\r\n \t\r\n second\r\nContent-Length: 0\r\n\r\n";
    var response = try http1.parseOwnedResponseHead(std.testing.allocator, bytes, .{ .allow_obs_fold = true }, .{});
    defer response.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("first  second", response.head.header("x-trace").?);
}

test "HTTP/1 folded fields discard safe invalid groups without consuming the next field" {
    for ([_][]const u8{ "Malformed field\r\n safe ignored\r\n", "X-Dropped: first\r\n \x01invalid\r\n safe ignored\r\n" }) |discarded| {
        var bytes: [512]u8 = undefined;
        const response = try std.fmt.bufPrint(&bytes, "HTTP/1.1 200 OK\r\n{s}X-Good: yes\r\nContent-Length: 0\r\n\r\n", .{discarded});
        var owned = try http1.parseOwnedResponseHead(std.testing.allocator, response, .{ .allow_obs_fold = true, .ignore_invalid_headers_in_responses = true, .max_headers = 2 }, .{});
        defer owned.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("yes", owned.head.header("x-good").?);
        try std.testing.expect(owned.head.header("x-dropped") == null);
        try std.testing.expectEqual(@as(?usize, 0), owned.head.content_length);
    }
}
