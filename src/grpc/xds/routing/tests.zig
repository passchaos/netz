const std = @import("std");
const String = @import("string.zig").Match;
const header = @import("header.zig");
const domain = @import("domain.zig");
const gpa = std.testing.allocator;
test "gRPC xDS routing header matching joins duplicates and preserves missing binary semantics" {
    const request = header.Request{ .path = "/demo.Service/Get", .authority = "backend.test", .metadata = &.{ .{ .name = "x-key", .value = "a" }, .{ .name = "x-key", .value = "b" }, .{ .name = "x-empty", .value = "" }, .{ .name = "x-empty", .value = "a" } } };
    var joined = try request.header(gpa, "x-key");
    defer joined.deinit();
    try std.testing.expectEqualStrings("a,b", joined.value.?);
    var empty = try request.header(gpa, "x-empty");
    defer empty.deinit();
    try std.testing.expectEqualStrings(",a", empty.value.?);
    var content = try request.header(gpa, "content-type");
    defer content.deinit();
    try std.testing.expectEqualStrings("application/grpc", content.value.?);
    try std.testing.expect(try (header.Match{ .name = "x-key", .condition = .{ .string = .{ .exact = .{ .text = "a,b" } } } }).matches(gpa, request));
    try std.testing.expect(!try (header.Match{ .name = "missing", .invert = true, .condition = .{ .string = .{ .exact = .{ .text = "a" } } } }).matches(gpa, request));
    try std.testing.expect(try (header.Match{ .name = "missing", .condition = .{ .present = false } }).matches(gpa, request));
    try std.testing.expect(!try (header.Match{ .name = "x-data-bin", .condition = .{ .present = true } }).matches(gpa, request));
    var limited = request;
    limited.max_header_bytes = 2;
    try std.testing.expectError(error.RouteMetadataLimitExceeded, limited.header(gpa, "x-key"));
}
test "gRPC xDS routing decoded missing headers use empty values before inversion" {
    const Case = struct { bytes: []const u8, as_empty: bool = false, missing: bool, empty: bool, value: bool };
    const cases = [_]Case{
        .{ .bytes = "\x0a\x01x\x22\x00", .missing = false, .empty = true, .value = false },
        .{ .bytes = "\x0a\x01x\x22\x00\x70\x00", .missing = false, .empty = true, .value = false },
        .{ .bytes = "\x0a\x01x\x22\x00\x70\x01", .as_empty = true, .missing = true, .empty = true, .value = false },
        .{ .bytes = "\x0a\x01x\x22\x00\x40\x01", .missing = false, .empty = false, .value = true },
        .{ .bytes = "\x0a\x01x\x22\x00\x40\x01\x70\x00", .missing = false, .empty = false, .value = true },
        .{ .bytes = "\x0a\x01x\x22\x00\x40\x01\x70\x01", .as_empty = true, .missing = false, .empty = false, .value = true },
        .{ .bytes = "\x0a\x01x\x22\x01a", .missing = false, .empty = false, .value = true },
        .{ .bytes = "\x0a\x01x\x22\x01a\x70\x01", .as_empty = true, .missing = false, .empty = false, .value = true },
        .{ .bytes = "\x0a\x01x\x22\x01a\x40\x01", .missing = false, .empty = true, .value = false },
        .{ .bytes = "\x0a\x01x\x22\x01a\x40\x01\x70\x01", .as_empty = true, .missing = true, .empty = true, .value = false },
    };
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    for (cases) |case| {
        const matcher = try header.decode(arena.allocator(), case.bytes, .{});
        try std.testing.expectEqual(case.as_empty, matcher.treat_missing_header_as_empty);
        try std.testing.expectEqual(case.missing, try matcher.matches(gpa, .{ .path = "/s/m", .authority = "host" }));
        try std.testing.expectEqual(case.empty, try matcher.matches(gpa, .{ .path = "/s/m", .authority = "host", .metadata = &.{.{ .name = "x", .value = "" }} }));
        try std.testing.expectEqual(case.value, try matcher.matches(gpa, .{ .path = "/s/m", .authority = "host", .metadata = &.{.{ .name = "x", .value = "a" }} }));
    }
}
test "gRPC xDS routing decoded presence treats missing headers as present when configured" {
    // Envoy HeaderDataPresentMatch counts the substituted empty value as
    // present, so the flag affects present_match as well as string matching.
    const Case = struct { bytes: []const u8, missing: bool, present: bool };
    const cases = [_]Case{
        .{ .bytes = "\x0a\x01x\x38\x01", .missing = false, .present = true },
        .{ .bytes = "\x0a\x01x\x38\x01\x40\x01", .missing = true, .present = false },
        .{ .bytes = "\x0a\x01x\x38\x00", .missing = true, .present = false },
        .{ .bytes = "\x0a\x01x\x38\x00\x40\x01", .missing = false, .present = true },
        .{ .bytes = "\x0a\x01x\x38\x01\x70\x00", .missing = false, .present = true },
        .{ .bytes = "\x0a\x01x\x38\x01\x40\x01\x70\x00", .missing = true, .present = false },
        .{ .bytes = "\x0a\x01x\x38\x00\x70\x00", .missing = true, .present = false },
        .{ .bytes = "\x0a\x01x\x38\x00\x40\x01\x70\x00", .missing = false, .present = true },
        .{ .bytes = "\x0a\x01x\x38\x01\x70\x01", .missing = true, .present = true },
        .{ .bytes = "\x0a\x01x\x38\x01\x40\x01\x70\x01", .missing = false, .present = false },
        .{ .bytes = "\x0a\x01x\x38\x00\x70\x01", .missing = false, .present = false },
        .{ .bytes = "\x0a\x01x\x38\x00\x40\x01\x70\x01", .missing = true, .present = true },
    };
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    for (cases) |case| {
        const matcher = try header.decode(arena.allocator(), case.bytes, .{});
        try std.testing.expectEqual(case.missing, try matcher.matches(gpa, .{ .path = "/s/m", .authority = "host" }));
        for ([_][]const u8{ "", "a" }) |value| {
            try std.testing.expectEqual(case.present, try matcher.matches(gpa, .{ .path = "/s/m", .authority = "host", .metadata = &.{.{ .name = "x", .value = value }} }));
        }
    }
}
test "gRPC xDS routing missing header regex and range matching retain budgets and limits" {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const regex_bytes = "\x0a\x01x\x5a\x04\x12\x02^$\x70\x01";
    const regex = try header.decode(arena.allocator(), regex_bytes, .{});
    const request = header.Request{ .path = "/s/m", .authority = "host" };
    try std.testing.expect(try regex.matches(gpa, request));
    const range = try header.decode(arena.allocator(), "\x0a\x01x\x32\x04\x08\x00\x10\x0a\x40\x01\x70\x01", .{});
    try std.testing.expect(try range.matches(gpa, request));
    const missing_range = try header.decode(arena.allocator(), "\x0a\x01x\x32\x04\x08\x00\x10\x0a\x40\x01", .{});
    try std.testing.expect(!try missing_range.matches(gpa, request));
    try std.testing.expectError(error.HeaderMatcherLimitExceeded, header.decode(arena.allocator(), regex_bytes, .{ .max_text_bytes = 1 }));
    try std.testing.expectError(error.RegexLimitExceeded, header.decode(arena.allocator(), regex_bytes, .{ .regex = .{ .max_instructions = 1 } }));
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var limited = request;
    limited.budget = .{ .io = threaded.io(), .deadline = .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromNanoseconds(-1) }) };
    try std.testing.expectError(error.Timeout, regex.matches(gpa, limited));
    limited = request;
    limited.metadata = &.{.{ .name = "x", .value = "too long" }};
    limited.max_header_bytes = 1;
    try std.testing.expectError(error.RouteMetadataLimitExceeded, regex.matches(gpa, limited));
}
test "gRPC xDS routing range matching is exact int64 and upper bound exclusive" {
    const matcher = header.Match{ .name = "x-number", .condition = .{ .range = .{ .start = -2, .end = 10 } } };
    for ([_][]const u8{ "-2", "0", "9", " +2 ", "0002" }) |value| try std.testing.expect(try matcher.matches(gpa, .{ .path = "/s/m", .authority = "host", .metadata = &.{.{ .name = "x-number", .value = value }} }));
    for ([_][]const u8{ "-3", "10", "1_2", "0x2", "9223372036854775808", "", "  ", "+" }) |value| try std.testing.expect(!try matcher.matches(gpa, .{ .path = "/s/m", .authority = "host", .metadata = &.{.{ .name = "x-number", .value = value }} }));
}
test "gRPC xDS routing domain precedence uses exact suffix prefix universal and longest match" {
    const Host = struct { domains: []const []const u8 };
    const hosts = [_]Host{
        .{ .domains = &.{"*"} },
        .{ .domains = &.{"api*"} },
        .{ .domains = &.{"*.test"} },
        .{ .domains = &.{"*backend.test"} },
        .{ .domains = &.{"api.backend.test"} },
        .{ .domains = &.{"API.BACKEND.TEST"} },
    };
    try std.testing.expectEqual(@as(?usize, 4), domain.select(&hosts, "API.BACKEND.TEST"));
    try std.testing.expectEqual(@as(?usize, 3), domain.select(&hosts, "other.backend.test"));
    try std.testing.expectEqual(@as(?usize, 2), domain.select(&hosts, "api.other.test"));
    try std.testing.expectEqual(@as(?usize, 1), domain.select(&hosts, "api.example"));
    try std.testing.expectEqual(@as(?usize, 0), domain.select(&hosts, "elsewhere"));
    try std.testing.expect(!domain.matches("*.test", ".test"));
    for ([_][]const u8{ "", "a*b", "**", "*a*" }) |value| try std.testing.expect(domain.kind(value) == null);
}
test "gRPC xDS routing strings use ASCII case folding and bounded RE2 full matches" {
    try std.testing.expect(try (String{ .exact = .{ .text = "backend", .ignore_case = true } }).matches(gpa, "BACKEND"));
    try std.testing.expect(!try (String{ .exact = .{ .text = "k", .ignore_case = true } }).matches(gpa, "K"));
    try std.testing.expect(try (String{ .prefix = .{ .text = "/demo.", .ignore_case = true } }).matches(gpa, "/DEMO.Service/Get"));
    try std.testing.expect(try (String{ .suffix = .{ .text = "/Get" } }).matches(gpa, "/demo.Service/Get"));
    try std.testing.expect(try (String{ .contains = .{ .text = "service", .ignore_case = true } }).matches(gpa, "/demo.Service/Get"));
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const matcher = try String.compileRegex(arena.allocator(), "/demo\\.[A-Za-z]+/(Get|List)", .{});
    try std.testing.expect(try matcher.matches(gpa, "/demo.Service/Get"));
    try std.testing.expect(!try matcher.matches(gpa, "prefix/demo.Service/Get"));
}
test "gRPC xDS routing path-separated prefixes stop at segment boundaries" {
    const matcher = String{ .path_separated_prefix = .{ .text = "/api/dev" } };
    for ([_][]const u8{
        "/api/dev",
        "/api/dev/",
        "/api/dev/v1",
        "/api/dev?x=1",
        "/api/dev#frag",
    }) |value| {
        try std.testing.expect(try matcher.matches(gpa, value));
    }
    for ([_][]const u8{ "/api/developer", "/api/de", "/api/devx" }) |value| {
        try std.testing.expect(!try matcher.matches(gpa, value));
    }
    const folded = String{ .path_separated_prefix = .{
        .text = "/API/DEV",
        .ignore_case = true,
    } };
    try std.testing.expect(try folded.matches(gpa, "/api/dev/v1"));
}
