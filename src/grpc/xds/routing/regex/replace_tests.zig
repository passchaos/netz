const std = @import("std");
const regex = @import("../regex.zig");

fn expectReplace(
    pattern: []const u8,
    substitution: []const u8,
    input: []const u8,
    expected: []const u8,
) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const program = try regex.compile(allocator, pattern, .{});
    var workspace = try regex.ReplaceWorkspace.init(allocator, program, .{});
    defer workspace.deinit();
    const actual = try workspace.replaceAll(input, substitution);
    try std.testing.expectEqualStrings(expected, actual);
}

test "regex replacement expands numbered capture groups" {
    try expectReplace(
        "^/service/([^/]+)(/.*)$",
        "\\2/instance/\\1",
        "/service/foo/v1/api",
        "/v1/api/instance/foo",
    );
}

test "regex replacement replaces every non-overlapping match" {
    try expectReplace(
        "one",
        "two",
        "/xxx/one/yyy/one/zzz",
        "/xxx/two/yyy/two/zzz",
    );
}

test "regex replacement honors lazy quantifiers" {
    try expectReplace(
        "^(.*?)one(.*)$",
        "\\1two\\2",
        "/xxx/one/yyy/one/zzz",
        "/xxx/two/yyy/one/zzz",
    );
}

test "regex replacement honors inline case folding" {
    try expectReplace(
        "(?i)/xxx/",
        "/yyy/",
        "/aaa/XxX/bbb",
        "/aaa/yyy/bbb",
    );
}

test "regex replacement supports whole match and escaped backslash" {
    try expectReplace("a+", "[\\0]", "baaac", "b[aaa]c");
    try expectReplace("a", "\\\\", "a", "\\");
}

test "regex replacement leaves unmatched groups empty" {
    try expectReplace("(a)|(b)", "<\\1\\2>", "ab", "<a><b>");
}

test "regex replacement leaves unmatched input unchanged" {
    try expectReplace("zzz", "x", "/a/b/c", "/a/b/c");
}

test "regex replacement rejects unknown capture references" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const program = try regex.compile(allocator, "(a)", .{});
    var workspace = try regex.ReplaceWorkspace.init(allocator, program, .{});
    defer workspace.deinit();
    try std.testing.expectError(
        error.InvalidRegex,
        workspace.replaceAll("a", "\\2"),
    );
}

test "regex replacement handles Unicode captures" {
    try expectReplace(
        "(猫+)",
        "<\\1>",
        "a猫猫b",
        "a<猫猫>b",
    );
}

test "regex replacement enforces the backtracking budget" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const program = try regex.compile(allocator, "(a|aa)*b", .{});
    var workspace = try regex.ReplaceWorkspace.init(
        allocator,
        program,
        .{ .max_execution_steps = 32 },
    );
    defer workspace.deinit();
    try std.testing.expectError(
        error.RegexLimitExceeded,
        workspace.replaceAll("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "x"),
    );
}
