//! Protocol-independent asynchronous address resolution contract.

const std = @import("std");

const net = std.Io.net;

pub const Error = std.mem.Allocator.Error || net.HostName.LookupError ||
    std.Io.Timeout.Error;

pub const Resolver = struct {
    pub const ResolveError = Error;

    context: *anyopaque,
    /// Calls may overlap for independent routes. Implementations must be
    /// thread-safe, honor cancellation and the optional absolute deadline via
    /// `io`, and return a slice owned by `allocator`.
    resolve: *const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error![]net.IpAddress,
};
