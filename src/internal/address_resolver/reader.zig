//! Caller-stable DNS queue ownership for incremental address consumers.
const std = @import("std");
const net = std.Io.net;

pub const Reader = struct {
    io: std.Io,
    storage: [16]net.HostName.LookupResult = undefined,
    queue: std.Io.Queue(net.HostName.LookupResult) = undefined,
    producer: std.Io.Future(net.HostName.LookupError!void) = undefined,
    active: bool = false,
    completion_error: ?net.HostName.LookupError = null,

    /// The reader must remain at this address until deinit joins its producer.
    pub fn start(self: *Reader, io: std.Io, host: net.HostName, options: net.HostName.LookupOptions) std.Io.ConcurrentError!void {
        self.* = .{ .io = io };
        self.queue = .init(&self.storage);
        self.producer = try std.Io.concurrent(io, net.HostName.lookup, .{ host, io, &self.queue, options });
        self.active = true;
    }

    pub fn next(self: *Reader) net.HostName.LookupError!?net.IpAddress {
        while (self.queue.getOne(self.io)) |result| switch (result) {
            .address => |address| return address,
            .canonical_name => {},
        } else |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => try self.finish(),
        }
        return null;
    }

    pub fn finish(self: *Reader) net.HostName.LookupError!void {
        if (self.active) {
            const result = self.producer.await(self.io);
            self.active = false;
            result catch |err| {
                self.completion_error = err;
            };
        }
        if (self.completion_error) |err| return err;
    }

    pub fn deinit(self: *Reader) void {
        if (self.active) self.producer.cancel(self.io) catch {};
        drain(self.io, &self.queue);
        self.* = undefined;
    }
};

pub fn drain(io: std.Io, queue: *std.Io.Queue(net.HostName.LookupResult)) void {
    while (queue.getOneUncancelable(io)) |_| {} else |err| switch (err) {
        error.Closed => {},
    }
}
