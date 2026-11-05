const std = @import("std");
const grpc = @import("../../mod.zig");
const inputs = @import("request_inputs.zig");
const path_rewrite = @import("../../path_rewrite.zig");
const regex = @import("../../xds/routing/regex.zig");

test "shared request inputs apply regex path rewrites before copying metadata" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const program = try regex.compile(
        allocator,
        "^/service/([^/]+)(/.*)$",
        .{},
    );
    var rewrite = path_rewrite.RegexRewrite{
        .program = program,
        .substitution = "\\2/instance/\\1",
        .limits = .{},
    };
    const input = "/service/foo/v1/api";
    const output_len = try path_rewrite.outputLen(allocator, &rewrite, input);
    const source: grpc.call.UnaryCallOptions = .{
        .path = input,
        .authority = "backend.test",
        .message = "m",
        .xds_path_rewrite = .{ .regex = .{
            .rewrite = &rewrite,
            .output_len = output_len,
        } },
        .xds_request_header_mutations = &.{.{
            .name = "x-route",
            .value = "rewritten",
            .action = .overwrite,
        }},
    };
    var cloned = try inputs.clone(std.testing.allocator, source);
    defer cloned.inputs.deinit();
    try std.testing.expectEqualStrings(
        "/v1/api/instance/foo",
        cloned.options.path,
    );
    try std.testing.expectEqualStrings(
        "backend.test",
        cloned.options.authority.?,
    );
    try std.testing.expect(cloned.options.xds_path_rewrite == null);
    try std.testing.expectEqual(@as(usize, 1), cloned.options.metadata.len);
    try std.testing.expectEqualStrings(
        "x-route",
        cloned.options.metadata[0].name,
    );
    try std.testing.expectEqualStrings(
        "rewritten",
        cloned.options.metadata[0].value,
    );
}
