//! QUIC trust-loading error policy over the shared TLS operation owner.
const std = @import("std");
const loading = @import("../../tls/trust_loading.zig");
const Store = @import("../mod.zig").tls.trust.SystemStore;

pub const Error = error{ OutOfMemory, NativeTrustStoreUnavailable } || std.Io.Cancelable || std.Io.ConcurrentError;
pub const BeforeError = Error || std.Io.Timeout.Error;
pub const checkpoint = loading.checkpoint;
pub const before = loading.before;

pub fn failure(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.ConcurrencyUnavailable => error.ConcurrencyUnavailable,
        else => error.NativeTrustStoreUnavailable,
    };
}

pub fn system(allocator: std.mem.Allocator, io: std.Io, now: std.Io.Timestamp, environ: ?std.process.Environ) Error!Store {
    return loading.system(allocator, io, now, environ) catch |err| return failure(err);
}

pub fn systemBefore(allocator: std.mem.Allocator, io: std.Io, now: std.Io.Timestamp, environ: ?std.process.Environ, deadline: ?std.Io.Clock.Timestamp) BeforeError!Store {
    return loading.systemBefore(allocator, io, now, environ, deadline) catch |err| {
        if (err == error.Timeout) return error.Timeout;
        return failure(err);
    };
}
