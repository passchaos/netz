//! Owned system trust loading under the connection startup budget.
const std = @import("std");
const Store = @import("vail").x509.trust.SystemStore;
const deadline_policy = @import("../internal/deadline.zig");
const completion = @import("trust_completion.zig");
pub const checkpoint = completion.checkpoint;
pub const complete = completion.complete;

pub const Error = @typeInfo(@typeInfo(@TypeOf(systemRaw)).@"fn".return_type.?).error_union.error_set || std.Io.Cancelable;
pub const BeforeError = Error || std.Io.Timeout.Error || std.Io.ConcurrentError;

fn ResultOf(comptime load: anytype) type {
    const info = @typeInfo(@typeInfo(@TypeOf(load)).@"fn".return_type.?).error_union;
    return (info.error_set || std.Io.Cancelable || std.Io.Timeout.Error || std.Io.ConcurrentError)!Store;
}

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
/// A timer is admitted first; bounded loading must never fall back inline.
pub fn before(io: std.Io, deadline: std.Io.Clock.Timestamp, comptime load: anytype, args: std.meta.ArgsTuple(@TypeOf(load))) ResultOf(load) {
    try checkpoint(io, deadline);
    const Result = ResultOf(load);
    const Wake = union(enum) {
        loaded: Result,
        timeout: std.Io.Cancelable!void,
    };
    const Worker = struct {
        fn run(run_io: std.Io, until: std.Io.Clock.Timestamp, run_args: @TypeOf(args)) Result {
            try checkpoint(run_io, until);
            return complete(run_io, until, @call(.auto, load, run_args));
        }
    };
    var storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &storage);
    defer while (select.cancel()) |wake| switch (wake) {
        .loaded => |result| if (result) |value| {
            var store = value;
            store.deinit();
        } else |_| {},
        .timeout => {},
    };
    select.concurrent(.timeout, deadline_policy.waitUntil, .{ io, deadline }) catch |err| {
        try checkpoint(io, deadline);
        return err;
    };
    select.concurrent(.loaded, Worker.run, .{ io, deadline, args }) catch |err| {
        try checkpoint(io, deadline);
        return err;
    };
    return switch (try select.await()) {
        .loaded => |result| try complete(io, deadline, result),
        .timeout => |result| {
            try result;
            return error.Timeout;
        },
    };
}
