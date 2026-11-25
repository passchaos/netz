//! Caller-owned trust bundle contention belongs to the handshake budget.
const std = @import("std");
const clients = @import("mod.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const support = @import("../../internal/testing/timed_rwlock.zig");

fn waitBefore(event: *std.Io.Event, io: std.Io, duration: std.Io.Duration) !void {
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = duration });
    while (true) {
        event.waitTimeout(io, .{ .deadline = deadline }) catch |err| switch (err) {
            error.Canceled => return err,
            error.Timeout => {
                _ = try deadline_policy.usableAwake(io, deadline);
                continue;
            },
        };
        return;
    }
}

fn streamPair(io: std.Io) ![2]std.Io.net.Stream {
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const first = try listener.socket.address.connect(io, .{ .mode = .stream });
    errdefer first.close(io);
    const second = try listener.accept(io);
    return .{ first, second };
}

fn heldWriter(comptime Client: type, comptime relative: bool) !void {
    const Options = if (Client == clients.ClientConnection) clients.ClientVerifiedOptions else clients.Tls13ClientVerifiedOptions;
    var backend = try @import("zio").Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const sockets = try streamPair(io);
    defer for (sockets) |socket| socket.close(io);
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    var lock: std.Io.RwLock = .init;
    lock.lockUncancelable(io);
    defer lock.unlock(io);

    const Worker = struct {
        io: std.Io,
        socket: std.Io.net.Stream,
        bundle: *std.crypto.Certificate.Bundle,
        lock: *std.Io.RwLock,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            defer self.done.set(self.io);
            const options: Options = .{
                .server_name = "bundle-lock.test",
                .ca_bundle = .{ .bundle = self.bundle, .lock = self.lock },
                .handshake_timeout = if (relative) std.Io.Duration.fromSeconds(1) else null,
            };
            const result = if (relative)
                Client.initVerified(std.testing.allocator, self.io, self.socket, options)
            else
                Client.initVerifiedWithDeadline(std.testing.allocator, self.io, self.socket, options, .fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
            if (result) |connection| {
                connection.deinit();
                self.err = error.TestExpectedError;
            } else |err| self.err = err;
        }
    };
    var worker: Worker = .{ .io = io, .socket = sockets[0], .bundle = &bundle, .lock = &lock };
    var future = try std.Io.concurrent(io, Worker.run, .{&worker});
    defer future.cancel(io);
    // The writer stays held until after completion or canceled fixture cleanup.
    try waitBefore(&worker.done, io, .fromSeconds(3));
    future.await(io);
    try std.testing.expectEqual(@as(?anyerror, error.Timeout), worker.err);
    try std.testing.expect(!lock.tryLockShared(io));
}

test "TLS CA bundle lock caller deadline expires while the writer stays held" {
    inline for (.{ clients.ClientConnection, clients.Tls13ClientConnection }) |Client| try heldWriter(Client, false);
}

test "TLS CA bundle lock handshake timeout expires while the writer stays held" {
    inline for (.{ clients.ClientConnection, clients.Tls13ClientConnection }) |Client| try heldWriter(Client, true);
}

test "TLS CA bundle lock interrupted fast-path admission releases the reader" {
    try support.fastPath();
}

test "TLS CA bundle lock canceled waiter preserves the next reader" {
    try support.canceledWaiter();
}
