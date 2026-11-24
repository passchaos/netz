//! Concurrent DNS production with one bounded result-queue consumer.
const std = @import("std");
const Collector = @import("collector.zig").Collector;
const net = std.Io.net;

pub const Error = std.mem.Allocator.Error || net.HostName.LookupError || std.Io.ConcurrentError;
pub const CollectError = std.mem.Allocator.Error || std.Io.Cancelable;

pub fn all(allocator: std.mem.Allocator, io: std.Io, host: net.HostName, port: u16) Error![]net.IpAddress {
    var storage: [16]net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(net.HostName.LookupResult) = .init(&storage);
    var producer = try std.Io.concurrent(io, net.HostName.lookup, .{ host, io, &queue, .{ .port = port } });
    defer {
        producer.cancel(io) catch {};
        drain(io, &queue);
    }
    const addresses = try collect(allocator, io, &queue);
    errdefer allocator.free(addresses);
    try producer.await(io);
    if (addresses.len == 0) return error.NoAddressReturned;
    return addresses;
}

pub fn first(io: std.Io, host: net.HostName, port: u16) Error!net.IpAddress {
    var storage: [16]net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(net.HostName.LookupResult) = .init(&storage);
    var producer = try std.Io.concurrent(io, net.HostName.lookup, .{ host, io, &queue, .{ .port = port } });
    defer {
        producer.cancel(io) catch {};
        drain(io, &queue);
    }
    while (queue.getOne(io)) |result| switch (result) {
        .address => |address| return address,
        .canonical_name => {},
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => try producer.await(io),
    }
    return error.NoAddressReturned;
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

pub fn drain(io: std.Io, queue: *std.Io.Queue(net.HostName.LookupResult)) void {
    while (queue.getOneUncancelable(io)) |_| {} else |err| switch (err) {
        error.Closed => {},
    }
}
