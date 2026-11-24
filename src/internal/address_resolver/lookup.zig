//! Concurrent DNS production with one bounded result-queue consumer.
const std = @import("std");
const Collector = @import("collector.zig").Collector;
const reader_module = @import("reader.zig");
const Reader = reader_module.Reader;
const net = std.Io.net;

pub const Error = std.mem.Allocator.Error || net.HostName.LookupError || std.Io.ConcurrentError;
pub const CollectError = std.mem.Allocator.Error || std.Io.Cancelable;

pub fn all(allocator: std.mem.Allocator, io: std.Io, host: net.HostName, port: u16) Error![]net.IpAddress {
    var reader: Reader = undefined;
    try reader.start(io, host, .{ .port = port });
    defer reader.deinit();
    const addresses = try collect(allocator, io, &reader.queue);
    errdefer allocator.free(addresses);
    try reader.finish();
    if (addresses.len == 0) return error.NoAddressReturned;
    return addresses;
}

pub fn first(io: std.Io, host: net.HostName, port: u16) Error!net.IpAddress {
    var reader: Reader = undefined;
    try reader.start(io, host, .{ .port = port });
    defer reader.deinit();
    return (try reader.next()) orelse error.NoAddressReturned;
}

pub fn collect(allocator: std.mem.Allocator, io: std.Io, queue: *std.Io.Queue(net.HostName.LookupResult)) CollectError![]net.IpAddress {
    var collector = Collector.init(allocator);
    defer collector.deinit();
    while (queue.getOne(io)) |result| switch (result) {
        .address => |address| try collector.appendUnique(address),
        .canonical_name => {},
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => {},
    }
    return collector.toOwnedSlice();
}

pub const drain = reader_module.drain;
