//! Ordered TCP attempts over an incrementally consumed DNS answer.
const std = @import("std");
const Reader = @import("../address_resolver/reader.zig").Reader;
const net = std.Io.net;

pub fn connect(
    comptime ConnectError: type,
    io: std.Io,
    host: net.HostName,
    options: net.HostName.LookupOptions,
    context: anytype,
    comptime connect_one: anytype,
    comptime should_try_next: anytype,
) (ConnectError || net.HostName.LookupError)!net.Stream {
    var reader: Reader = undefined;
    // Native socket connection APIs expose task admission failure through
    // SystemResources, matching the enclosing TCP deadline race.
    reader.start(io, host, options) catch return error.SystemResources;
    defer reader.deinit();
    var last_error: ?ConnectError = null;
    while (try reader.next()) |address| {
        return connect_one(context, io, address) catch |err| {
            if (!should_try_next(err)) return err;
            last_error = err;
            continue;
        };
    }
    return last_error orelse error.UnknownHostName;
}
