//! Capture-aware regex and URI-template path rewriting shared by xDS and gRPC.
const std = @import("std");
const regex = @import("xds/routing/regex.zig");
const template = @import("xds/routing/template.zig");

pub const Error = std.mem.Allocator.Error || error{
    RegexLimitExceeded,
    InvalidTemplate,
    TemplateLimitExceeded,
};

pub const RegexRewrite = struct {
    program: regex.Program,
    substitution: []const u8,
    limits: regex.Limits,
};

pub const TemplateRewrite = struct {
    match: *const template.Match,
    rewrite: *const template.Rewrite,
};

/// Envoy's `host_rewrite_path_regex` evaluates the path with query and
/// fragment removed.
pub fn stripQueryAndFragment(input: []const u8) []const u8 {
    const end = std.mem.indexOfAny(u8, input, "?#") orelse input.len;
    return input[0..end];
}

/// Compute the exact rewritten length for `input`. A bounded-work failure is
/// reported separately so route selection can reject the request locally.
pub fn outputLen(
    allocator: std.mem.Allocator,
    rewrite: *const RegexRewrite,
    input: []const u8,
) Error!usize {
    var workspace = try regex.ReplaceWorkspace.init(
        allocator,
        rewrite.program,
        rewrite.limits,
    );
    defer workspace.deinit();
    return workspace.replaceAllLen(input, rewrite.substitution) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.RegexLimitExceeded,
    };
}

/// Write the rewritten path into caller storage. Selection has already
/// validated the same input and length, so a budget failure here can only mean
/// the workspace could not be allocated.
pub fn apply(
    allocator: std.mem.Allocator,
    rewrite: *const RegexRewrite,
    input: []const u8,
    output: []u8,
) std.mem.Allocator.Error![]const u8 {
    var workspace = try regex.ReplaceWorkspace.init(
        allocator,
        rewrite.program,
        rewrite.limits,
    );
    defer workspace.deinit();
    return workspace.replaceAllInto(input, rewrite.substitution, output) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.OutOfMemory,
    };
}

/// Compute the exact URI-template rewrite length. The route matcher has
/// already accepted the same path, so a non-match here is an invalid template.
pub fn templateOutputLen(
    allocator: std.mem.Allocator,
    rewrite: *const TemplateRewrite,
    input: []const u8,
) Error!usize {
    _ = allocator;
    var captures: template.Captures = .{};
    if (!try rewrite.match.match(input, &captures)) return error.InvalidTemplate;
    return rewrite.rewrite.outputLen(&captures);
}

/// Write a URI-template rewrite into caller storage. Selection has already
/// matched the same input and computed the exact length.
pub fn templateApply(
    allocator: std.mem.Allocator,
    rewrite: *const TemplateRewrite,
    input: []const u8,
    output: []u8,
) std.mem.Allocator.Error![]const u8 {
    _ = allocator;
    var captures: template.Captures = .{};
    const matched = rewrite.match.match(input, &captures) catch return error.OutOfMemory;
    if (!matched) return error.OutOfMemory;
    return rewrite.rewrite.write(&captures, output) catch return error.OutOfMemory;
}
