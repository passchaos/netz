//! Owned system trust loading under the connection startup budget.
const std = @import("std");
const Store = @import("vail").x509.trust.SystemStore;
const completion = @import("trust_completion.zig");
pub const checkpoint = completion.checkpoint;
pub const complete = completion.complete;

pub const Error = @typeInfo(@typeInfo(@TypeOf(systemRaw)).@"fn".return_type.?).error_union.error_set || std.Io.Cancelable;
pub const BeforeError = Error || std.Io.Timeout.Error || std.Io.ConcurrentError;

fn systemRaw(allocator: std.mem.Allocator, io: std.Io, now: std.Io.Timestamp, environ: ?std.process.Environ) !Store {
    return if (environ) |value|
        Store.initWithEnviron(allocator, io, now, value)
    else
        Store.init(allocator, io, now);
}

pub fn system(allocator: std.mem.Allocator, io: std.Io, now: std.Io.Timestamp, environ: ?std.process.Environ) Error!Store {
    try io.checkCancel();
    var store = systemRaw(allocator, io, now, environ) catch |err| {
        try io.checkCancel();
        return err;
    };
    errdefer store.deinit();
    try io.checkCancel();
    return store;
}

pub fn systemBefore(allocator: std.mem.Allocator, io: std.Io, now: std.Io.Timestamp, environ: ?std.process.Environ, deadline: ?std.Io.Clock.Timestamp) BeforeError!Store {
    const until = deadline orelse return system(allocator, io, now, environ);
    return before(io, until, systemRaw, .{ allocator, io, now, environ });
}

/// Join canceled loading and destroy every unselected successful store.
/// The shared owned-result helper admits the timer before work.
pub const before = @import("../internal/owned_result_deadline.zig").before;
