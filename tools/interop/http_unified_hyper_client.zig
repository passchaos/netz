//! Unified H1/H2 ALPN client against the independent Hyper/rustls fixture.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const expected: netz.http.Protocol = if (std.mem.eql(u8, args[2], "h1"))
        .http1
    else if (std.mem.eql(u8, args[2], "h2"))
        .http2
    else
        return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var pool = try netz.http.Pool.init(allocator, io, .{
        .client = .{ .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } } },
    });
    defer pool.deinit();
    const first_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/one",
        .{port},
    );
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/two",
        .{port},
    );
    defer allocator.free(second_uri);
    const label = if (expected == .http2) "h2" else "h1";
    var first = try pool.requestUriWithTimeout(
        first_uri,
        .{ .headers = &.{.{
            .name = "x-netz-unified",
            .value = label,
        }} },
        .fromSeconds(5),
    );
    defer first.deinit();
    try verifyAdmissionTimeout(&pool, io, second_uri);
    try verifyQueuedTimeout(&pool, io, second_uri);
    var second = try pool.requestUriWithTimeout(
        second_uri,
        .{ .headers = &.{.{
            .name = "x-netz-unified",
            .value = label,
        }} },
        .fromSeconds(5),
    );
    defer second.deinit();
    var first_expected: [4]u8 = undefined;
    var second_expected: [4]u8 = undefined;
    const first_body = try std.fmt.bufPrint(&first_expected, "{s}-1", .{label});
    const second_body = try std.fmt.bufPrint(&second_expected, "{s}-2", .{label});
    if (!std.mem.eql(u8, first.body(), first_body) or
        !std.mem.eql(u8, second.body(), second_body))
    {
        return error.InvalidResponse;
    }
    if (first.protocol() != expected or second.protocol() != expected) {
        return error.InvalidProtocol;
    }
    const stats = pool.stats();
    if (pool.connectionCount() != 1 or pool.idleCount() != 1 or
        stats.total_reused != 2 or stats.total_misses != 2)
    {
        return error.InvalidPoolState;
    }
    std.debug.print(
        "netz unified HTTP pool selected Hyper protocol={s} alpn={s} requests=2 connections=1 reusable=true admission_timeout=isolated queued_timeout=isolated client_io=zio-std-io server_io=hyper-tokio\n",
        .{ label, if (expected == .http2) "h2" else "http/1.1" },
    );
}

fn verifyAdmissionTimeout(pool: *netz.http.Pool, io: std.Io, uri: []const u8) !void {
    pool.mutex.lockUncancelable(io);
    defer pool.mutex.unlock(io);
    const started = std.Io.Clock.awake.now(io);
    if (pool.requestUriWithTimeout(uri, .{}, .fromMilliseconds(10))) |value| {
        var response = value;
        response.deinit();
        return error.AdmittedWhileMutexHeld;
    } else |err| {
        if (err != error.Timeout) return err;
    }
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    if (elapsed.nanoseconds > std.Io.Duration.fromSeconds(1).nanoseconds) {
        return error.AdmissionDeadlineOverrun;
    }
    if (pool.mutex.tryLock()) return error.PoolMutexReleased;
    if (pool.connections != 1 or pool.idle.idleCount() != 1 or
        pool.capacity_waiters.count(io) != 0)
    {
        return error.InvalidPoolState;
    }
}

const QueuedGate = struct {
    pool: *netz.http.Pool,
    base: std.Io,
    held: bool = false,
    var active: ?*QueuedGate = null;

    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (!self.held) {
            self.pool.mutex.lockUncancelable(self.base);
            self.held = true;
        }
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }
};

fn verifyQueuedTimeout(pool: *netz.http.Pool, io: std.Io, uri: []const u8) !void {
    const previous_limit = pool.options.max_connections;
    pool.options.max_connections = 1;
    defer pool.options.max_connections = previous_limit;
    // Keep the sole authenticated connection leased so the next request
    // actually enters capacity waiting instead of creating another socket.
    var lease = try pool.acquireUriWithTimeout(uri, .fromSeconds(5));
    defer lease.release();
    var gate = QueuedGate{ .pool = pool, .base = io };
    var table = io.vtable.*;
    table.futexWait = QueuedGate.wait;
    QueuedGate.active = &gate;
    pool.io = .{ .userdata = io.userdata, .vtable = &table };
    defer {
        pool.io = io;
        QueuedGate.active = null;
        if (gate.held) pool.mutex.unlock(io);
    }
    const started = std.Io.Clock.awake.now(io);
    if (pool.requestUriWithTimeout(uri, .{}, .fromMilliseconds(10))) |value| {
        var response = value;
        response.deinit();
        return error.AdmittedWhileCapacityLeased;
    } else |err| {
        if (err != error.Timeout) return err;
    }
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    if (elapsed.nanoseconds > std.Io.Duration.fromSeconds(1).nanoseconds) return error.QueuedDeadlineOverrun;
    if (!gate.held or pool.mutex.tryLock()) return error.PoolMutexReleased;
    if (pool.connections != 1 or pool.idle.idleCount() != 0 or pool.capacity_waiters.len != 1) return error.InvalidPoolState;
    const node = pool.capacity_waiters.head.?;
    if (node.state.load(.acquire) != .abandoned or node.references.load(.acquire) != 1) return error.InvalidWaiterOwnership;
    pool.io = io;
    QueuedGate.active = null;
    pool.mutex.unlock(io);
    gate.held = false;
    if (pool.waitingCount() != 0) return error.WaiterNotRetired;
}
