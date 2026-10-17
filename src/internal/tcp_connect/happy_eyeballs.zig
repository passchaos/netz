//! Explicit RFC 8305-style staggered TCP connection racing.
//!
//! The caller supplies already-resolved addresses plus one connection
//! operation. Results are published into caller-owned slots before a
//! resource-free index reaches `std.Io.Select`, so cancellation racing a
//! successful connect cannot discard the returned socket.

const std = @import("std");
const policy = @import("../happy_eyeballs.zig");

const net = std.Io.net;

pub const Options = policy.Options;
pub const Policy = policy.Policy;

pub const Error = policy.Error;

pub fn validate(options: Options) error{InvalidAddressConnectPolicy}!void {
    return policy.validate(options);
}

pub fn connect(
    comptime ConnectError: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    options: Options,
    deadline: ?std.Io.Clock.Timestamp,
    context: anytype,
    comptime connect_one: anytype,
    comptime should_try_next: *const fn (anyerror) bool,
) (ConnectError || Error)!net.Stream {
    const ConnectContext = @TypeOf(context);
    const RaceContext = struct {
        io: std.Io,
        deadline: ?std.Io.Clock.Timestamp,
        connect_context: ConnectContext,

        fn connect(
            self: @This(),
            io_value: std.Io,
            address: net.IpAddress,
            _: usize,
        ) ConnectError!net.Stream {
            return connect_one(
                self.connect_context,
                io_value,
                address,
                self.deadline,
            );
        }

        fn deinitConnected(self: @This(), stream: *net.Stream) void {
            stream.close(self.io);
        }
    };
    const deadline_error: ?ConnectError = if (deadline != null)
        error.Timeout
    else
        null;
    return policy.race(
        ConnectError,
        net.Stream,
        allocator,
        io,
        addresses,
        options,
        deadline,
        deadline_error,
        RaceContext{
            .io = io,
            .deadline = deadline,
            .connect_context = context,
        },
        RaceContext.connect,
        RaceContext.deinitConnected,
        should_try_next,
    );
}
