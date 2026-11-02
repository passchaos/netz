const std = @import("std");
const regex = @import("../regex.zig");
const gpa = std.testing.allocator;
test "gRPC xDS safe regex supports full match RE2 operators Unicode and byte escapes" {
    const Case = struct { pattern: []const u8, yes: []const []const u8, no: []const []const u8 };
    for ([_]Case{
        .{ .pattern = "/(?:demo|test)\\.[A-Z][A-Za-z]+/(Get|List)", .yes = &.{ "/demo.Service/Get", "/test.Backend/List" }, .no = &.{ "prefix/demo.Service/Get", "/demo.Service/Put" } },
        .{ .pattern = "[a-z]{2,4}[0-9]+?", .yes = &.{ "ab1", "abcd1234" }, .no = &.{ "a1", "abcde1" } },
        .{ .pattern = "(?:ab){2,}(c|)", .yes = &.{ "abab", "abababc" }, .no = &.{ "ab", "ababd" } },
        .{ .pattern = "(?i:k|s|σ|ß)", .yes = &.{ "K", "K", "ſ", "ς", "Σ", "ẞ" }, .no = &.{ "SS", "x" } },
        .{ .pattern = "\\p{Greek}+\\p{Nd}", .yes = &.{ "Δσ2", "Σ٣" }, .no = &.{ "abc2", "Σx" } },
        .{ .pattern = "[[:alpha:]_][[:^digit:]]*", .yes = &.{ "abc", "xé_" }, .no = &.{ "1abc", "a2" } },
        .{ .pattern = "(?m:^a$)\\n(?s:.)", .yes = &.{ "a\nb", "a\n\n" }, .no = &.{ "a\n", "b\nx" } },
        .{ .pattern = "\\A\\bword\\b\\z", .yes = &.{"word"}, .no = &.{ "words", " word" } },
        .{ .pattern = "\\Q(a+b)[x]\\E*", .yes = &.{ "(a+b)[x", "(a+b)[x]]]" }, .no = &.{ "aaaabx", "(a+b)(a+b)" } },
        .{ .pattern = "\\C\\C", .yes = &.{ "é", "ab", "\xff\x80" }, .no = &.{ "a", "猫" } },
        .{ .pattern = "\\C猫\\C", .yes = &.{ "x猫y", "\xff猫\xff" }, .no = &.{ "猫", "é猫é" } },
        .{ .pattern = ".", .yes = &.{ "猫", "é" }, .no = &.{ "\n", "\xff", "ab" } },
        .{ .pattern = "^+", .yes = &.{""}, .no = &.{"a"} },
        .{ .pattern = "[^é]+", .yes = &.{"猫abc"}, .no = &.{ "é", "猫é" } },
        .{ .pattern = "\\x{d800}", .yes = &.{}, .no = &.{ "猫", "x", "\xed\xa0\x80" } },
    }) |case| {
        var value = try regex.Regex.init(gpa, case.pattern, .{});
        defer value.deinit();
        for (case.yes) |input| try std.testing.expect(try value.matches(gpa, input));
        for (case.no) |input| try std.testing.expect(!try value.matches(gpa, input));
    }
}
test "gRPC xDS safe regex rejects invalid syntax and bounds nested repetitions" {
    for ([_][]const u8{ "(", "[a-z", "[z-a]", "a**", "a++", "(?=a)", "(a)\\1", "(?x)a", "(?i-)a", "(?i)*", "{1}", "a{1}{2}", "\\p{Unknown}", "\\x{110000}", "a{2,1}", "a{1001}", "[a-\\d]", "[\\b]", "\\" }) |pattern| try std.testing.expectError(error.InvalidRegex, regex.Regex.init(gpa, pattern, .{}));
    try std.testing.expectError(error.RegexLimitExceeded, regex.Regex.init(gpa, "abcdef", .{ .max_pattern_bytes = 5 }));
    try std.testing.expectError(error.RegexLimitExceeded, regex.Regex.init(gpa, "a{5}", .{ .max_repeat = 4 }));
    try std.testing.expectError(error.RegexLimitExceeded, regex.Regex.init(gpa, "(a{100}){100}", .{ .max_instructions = 64 }));
    try std.testing.expectError(error.RegexLimitExceeded, regex.Regex.init(gpa, "(((a)))", .{ .max_depth = 2 }));
}
test "gRPC xDS safe regex keeps adversarial matching linear and rolls back allocation failures" {
    const pattern = "(?:a|aa)*b";
    var value = try regex.Regex.init(gpa, pattern, .{});
    defer value.deinit();
    var workspace = try regex.Workspace.init(gpa, value.program);
    defer workspace.deinit();
    const input = try gpa.alloc(u8, 8192);
    defer gpa.free(input);
    @memset(input, 'a');
    try std.testing.expect(!workspace.matches(value.program, input));
    try std.testing.expect(workspace.stats.states_visited <= value.program.instructions.len * (input.len + 1));
    input[input.len - 1] = 'b';
    try std.testing.expect(workspace.matches(value.program, input));
    const Harness = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var compiled = try regex.Regex.init(allocator, "(?i:[a-z]+)|\\p{Greek}{1,3}", .{});
            defer compiled.deinit();
            try std.testing.expect(try compiled.matches(allocator, "K"));
        }
    };
    try std.testing.checkAllAllocationFailures(gpa, Harness.run, .{});
}
