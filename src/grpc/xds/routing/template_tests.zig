const std = @import("std");
const template = @import("template.zig");

fn expectMatch(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    path: []const u8,
    expected: []const struct { name: []const u8, value: []const u8 },
) !void {
    const match = try template.Match.compile(allocator, pattern, .{});
    var captures: template.Captures = .{};
    try std.testing.expect(try match.match(path, &captures));
    for (expected) |variable| {
        try std.testing.expectEqualStrings(
            variable.value,
            captures.get(variable.name) orelse return error.MissingCapture,
        );
    }
}

fn expectRewrite(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    rewrite_pattern: []const u8,
    path: []const u8,
    expected: []const u8,
) !void {
    const match = try template.Match.compile(allocator, pattern, .{});
    const rewrite = try template.Rewrite.compile(
        allocator,
        rewrite_pattern,
        match.variables,
        .{},
    );
    var captures: template.Captures = .{};
    try std.testing.expect(try match.match(path, &captures));
    const length = try rewrite.outputLen(&captures);
    const output = try allocator.alloc(u8, length);
    try std.testing.expectEqualStrings(
        expected,
        try rewrite.write(&captures, output),
    );
}

test "URI template swaps path variables" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try expectMatch(allocator, "/{one}/{two}", "/cat/dog", &.{
        .{ .name = "one", .value = "cat" },
        .{ .name = "two", .value = "dog" },
    });
    try expectRewrite(
        allocator,
        "/{one}/{two}",
        "/{two}/{one}",
        "/cat/dog",
        "/dog/cat",
    );
}

test "URI template captures a multi-segment pattern" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try expectMatch(
        allocator,
        "/videos/{language=lang/*}/*",
        "/videos/lang/en/video.m4s",
        &.{.{ .name = "language", .value = "lang/en" }},
    );
    try expectRewrite(
        allocator,
        "/videos/{language=lang/*}/*",
        "/{language}",
        "/videos/lang/en/video.m4s",
        "/lang/en",
    );
}

test "URI template captures an embedded filename suffix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try expectMatch(
        allocator,
        "/content/{format}/{lang}/{id}/{file}.vtt",
        "/content/hls/en-us/12345/en_193913.vtt",
        &.{
            .{ .name = "format", .value = "hls" },
            .{ .name = "lang", .value = "en-us" },
            .{ .name = "id", .value = "12345" },
            .{ .name = "file", .value = "en_193913" },
        },
    );
    try expectRewrite(
        allocator,
        "/content/{format}/{lang}/{id}/{file}.vtt",
        "/{lang}/{format}/{file}.vtt",
        "/content/hls/en-us/12345/en_193913.vtt",
        "/en-us/hls/en_193913.vtt",
    );
}

test "URI template matches suffixes and strips query and fragment" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try expectMatch(allocator, "/files/**", "/files/a/b/c?x=1#f", &.{});
    try expectMatch(allocator, "/files/{rest=**}", "/files/a/b/c", &.{
        .{ .name = "rest", .value = "a/b/c" },
    });
    try expectMatch(allocator, "/{one}/{two}", "/cat/dog?x=1#f", &.{
        .{ .name = "one", .value = "cat" },
        .{ .name = "two", .value = "dog" },
    });
}

test "URI template rejects malformed patterns and rewrites" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try std.testing.expectError(
        error.InvalidTemplate,
        template.Match.compile(allocator, "/**/x", .{}),
    );
    try std.testing.expectError(
        error.InvalidTemplate,
        template.Match.compile(allocator, "/{a}/{a}", .{}),
    );
    const match = try template.Match.compile(allocator, "/{a}", .{});
    try std.testing.expectError(
        error.InvalidTemplate,
        template.Rewrite.compile(allocator, "/{missing}", match.variables, .{}),
    );
    try std.testing.expectError(
        error.InvalidTemplate,
        template.Match.compile(allocator, "relative", .{}),
    );
}

test "URI template matching is case sensitive and matches the root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const match = try template.Match.compile(allocator, "/Cat", .{});
    var captures: template.Captures = .{};
    try std.testing.expect(!try match.match("/cat", &captures));
    const root = try template.Match.compile(allocator, "/", .{});
    try std.testing.expect(try root.match("/", &captures));
}
