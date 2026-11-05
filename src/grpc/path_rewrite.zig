//! Capture-aware regex path rewriting shared by xDS resources and gRPC inputs.
const std = @import("std");
const regex = @import("xds/routing/regex.zig");

pub const Error = std.mem.Allocator.Error || error{RegexLimitExceeded};

pub const RegexRewrite = struct {
    program: regex.Program,
    substitution: []const u8,
    limits: regex.Limits,
};

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
