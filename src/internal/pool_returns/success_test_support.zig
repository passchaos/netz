//! A complete response must return while its pool return mutex is occupied.
const std = @import("std");
const http = @import("../../http/mod.zig");
const http1 = @import("../../http1/runtime.zig");
const http2 = @import("../../http2/runtime.zig");
const tls_testing = @import("../../tls/testing.zig");
const tls = @import("../../tls/stream/mod.zig");

const Probe = struct {
    base: std.Io,
    mutex: *std.Io.Mutex = undefined,
    armed: std.atomic.Value(bool) = .init(true),
    held: std.atomic.Value(bool) = .init(false),
    unbounded_waits: usize = 0,
    canceled: bool = false,
    refuse_connect: bool = false,
    outbound_calls: std.atomic.Value(usize) = .init(0),
    var active: ?*Probe = null;

    fn connect(userdata: ?*anyopaque, address: *const std.Io.net.IpAddress, options: std.Io.net.IpAddress.ConnectOptions) std.Io.net.IpAddress.ConnectError!std.Io.net.Socket {
        const self = active.?;
        if (self.refuse_connect) return error.NetworkUnreachable;
        return self.base.vtable.netConnectIp(userdata, address, options);
    }

    fn write(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, header: []const u8, parts: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.?;
        _ = self.outbound_calls.fetchAdd(1, .monotonic);
        return self.base.vtable.netWrite(userdata, socket, header, parts, splat);
    }

    fn waitBounded(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        const target: *const u32 = @ptrCast(&self.mutex.state.raw);
        if (pointer == target and self.canceled) return error.Canceled;
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }

    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = active.?;
        const target: *const u32 = @ptrCast(&self.mutex.state.raw);
        if (pointer != target) return self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
        self.unbounded_waits += 1;
        self.mutex.state.store(.unlocked, .release);
    }
};

pub fn exercise(comptime Pool: type, comptime h2: bool) !void {
    return exerciseShape(Pool, h2, false, false, false, false, false, false);
}

pub fn exerciseTls(comptime Pool: type, comptime h2: bool, comptime ticket_lock: bool) !void {
    return exerciseShape(Pool, h2, true, ticket_lock, false, false, false, false);
}

pub fn exerciseClosed(comptime Pool: type, comptime h2: bool) !void {
    return exerciseShape(Pool, h2, true, false, true, false, false, false);
}

pub fn exerciseCollector(comptime Pool: type, comptime h2: bool, comptime canceled: bool) !void {
    return exerciseShape(Pool, h2, true, true, false, true, canceled, false);
}

fn returnedTlsConnection(comptime Pool: type, pool: *Pool) *tls.ClientConnection {
    const node = pool.returns.head.load(.acquire).?;
    if (comptime Pool == http.Pool) {
        return switch (node.value.connection_value.value) {
            .http1 => |*value| value.tls_vail_conn.?,
            .http2 => |*value| value.transport.?.tls_client,
        };
    } else if (@hasField(@TypeOf(node.value.slot), "client")) {
        return node.value.slot.client.tls_vail_conn.?;
    } else return node.value.slot.connection.transport.?.tls_client;
}

pub fn exerciseCollectorRetirement(comptime Pool: type, comptime h2: bool) !void {
    return exerciseShape(Pool, h2, true, false, false, false, false, true);
}

fn exerciseShape(comptime Pool: type, comptime h2: bool, comptime secure: bool, comptime ticket_lock: bool, comptime late_closed: bool, comptime collect: bool, comptime canceled: bool, comptime retire: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var probe = Probe{ .base = base, .canceled = canceled };
    var table = base.vtable.*;
    table.futexWaitUncancelable = Probe.wait;
    table.futexWait = Probe.waitBounded;
    table.netWrite = Probe.write;
    table.netConnectIp = Probe.connect;
    Probe.active = &probe;
    defer Probe.active = null;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var pool = if (comptime Pool == http.Pool)
        try Pool.init(allocator, io, .{ .client = .{
            .cleartext_protocol = if (h2) .http2_prior_knowledge else .http1,
            .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = public_key } },
        } })
    else if (h2)
        try Pool.init(allocator, io, .{ .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = public_key } } })
    else
        try Pool.init(allocator, io, .{ .vail_tls = if (secure) .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = public_key } } else null });
    defer pool.deinit();
    probe.mutex = if (ticket_lock)
        if (comptime Pool == http.Pool) &pool.tickets.tls13.mutex else &pool.tls13_tickets.mutex
    else
        &pool.mutex;
    defer if (probe.held.load(.acquire)) {
        _ = probe.mutex.tryLock();
        probe.mutex.unlock(base);
    };
    const Protocol = if (h2) http2 else http1;
    const Server = if (secure) Protocol.TlsServer else Protocol.Server;
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate_der, tls_testing.certificate_base64);
    var keyring = try tls.Tls13TicketKeyring.init(.{ .id = 63, .secret = [_]u8{0x63} ** tls.tls13_ticket_key_len });
    defer keyring.deinit();
    var server = if (secure)
        try Server.listen(allocator, base, .{ .ip4 = .loopback(0) }, .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        }, .tls13_session_tickets = if (collect) .{ .keyring = &keyring, .server_id = "localhost", .lifetime_seconds = 3600 } else null })
    else
        try Server.listen(allocator, base, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Worker = struct {
        server: *Server,
        probe: *Probe,
        error_result: ?anyerror = null,
        requests: usize = 0,
        fn run(self: *@This()) void {
            self.execute() catch |err| {
                self.error_result = err;
            };
        }
        fn execute(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            for (0..if (late_closed or retire) 1 else 2) |index| {
                var request = if (h2) try connection.readRequest() else try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                self.requests += 1;
                if (index == 0) {
                    self.probe.mutex.lockUncancelable(self.probe.base);
                    self.probe.held.store(true, .release);
                    self.probe.armed.store(false, .release);
                }
                if (h2) {
                    try connection.writeResponse(request.stream_id, .{ .body = "ready" });
                } else {
                    try connection.writeResponse(.{ .body = "ready", .request_method = request.request.method });
                }
            }
        }
    };
    var worker = Worker{ .server = &server, .probe = &probe };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        if (probe.held.load(.acquire)) {
            _ = probe.mutex.tryLock();
            probe.mutex.unlock(base);
            probe.held.store(false, .release);
        }
        pool.close();
        thread.join();
    };
    const uri = try std.fmt.allocPrint(allocator, "{s}://localhost:{d}/", .{ if (secure) "https" else "http", server.address().ip4.port });
    defer allocator.free(uri);
    const Lease = @typeInfo(@typeInfo(@TypeOf(Pool.acquireUriWithTimeout)).@"fn".return_type.?).error_union.payload;
    var closed_lease: Lease = if (late_closed) try pool.acquireUriWithTimeout(uri, .fromSeconds(1)) else undefined;
    if (late_closed) pool.close();
    var first = if (late_closed)
        if (comptime Pool == http.Pool) try closed_lease.connection().requestWithDeadline("/", .{}, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })) else if (h2) try closed_lease.connection().requestWithDeadline(.{}, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })) else try closed_lease.client().requestWithDeadline(.{}, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }))
    else
        try pool.requestUriWithTimeout(uri, .{}, .fromSeconds(1));
    defer if (comptime Pool == http.Pool) first.deinit() else first.deinit(allocator);
    try std.testing.expectEqualStrings("ready", if (comptime Pool == http.Pool) first.body() else if (h2) first.body else first.response.body);
    if (late_closed) {
        const output_calls = probe.outbound_calls.load(.acquire);
        closed_lease.release();
        closed_lease.release();
        closed_lease.discard();
        try std.testing.expectEqual(output_calls, probe.outbound_calls.load(.acquire));
    }
    try std.testing.expect(!probe.armed.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
    try std.testing.expect(!probe.mutex.tryLock());
    if (collect) {
        // Retain the actual authenticated server ticket in connection state.
        // The collector must not take/lose it before acquiring the cache lock.
        const connection = returnedTlsConnection(Pool, &pool);
        const ticket = (try connection.takeTls13SessionTicket()) orelse blk: {
            // H2 bootstrap may already have captured the server's ticket.
            // The test owns this occupied cache lock; transfer its exact
            // authenticated ticket back to connection-owned pending storage.
            const cache = if (comptime Pool == http.Pool) &pool.tickets.tls13 else &pool.tls13_tickets;
            const entry = cache.entries.pop() orelse return error.ExpectedIssuedTicket;
            allocator.free(entry.server_identity);
            break :blk entry.ticket;
        };
        connection.tls13_session_ticket = ticket;
        const original_node = pool.returns.head.load(.acquire).?;
        const ticket_identity = ticket.identity.ptr;
        const Result = pool.acquireUriWithTimeout(uri, .fromMilliseconds(10));
        if (Result) |value| {
            var lease = value;
            lease.release();
            return error.UnexpectedAdmissionAfterCollectorLock;
        } else |err| try std.testing.expectEqual(if (canceled) error.Canceled else error.Timeout, err);
        try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
        try std.testing.expect(!probe.mutex.tryLock());
        try std.testing.expect(connection.tls13_session_ticket != null);
        try std.testing.expect(connection.tls13_session_ticket.?.identity.ptr == ticket_identity);
        try std.testing.expect(pool.returns.deferred == original_node);
        try std.testing.expect(pool.mutex.tryLock());
        pool.mutex.unlock(base);
        try std.testing.expectEqual(@as(usize, 1), pool.connections);
    }
    probe.mutex.unlock(base);
    probe.held.store(false, .release);
    if (late_closed) {
        try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
        try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
        thread.join();
        joined = true;
        if (worker.error_result) |err| return err;
        try std.testing.expectEqual(@as(usize, 1), worker.requests);
        return;
    }
    if (retire) {
        if (comptime Pool == http.Pool) {
            pool.idle.config.max_idle_total = 0;
            pool.idle.config.max_idle_per_origin = 0;
        } else {
            pool.options.max_idle_connections = 0;
            pool.options.max_idle_per_authority = 0;
        }
        probe.refuse_connect = true;
        const output_calls = probe.outbound_calls.load(.acquire);
        try std.testing.expectError(error.NetworkUnreachable, pool.acquireUriWithTimeout("http://127.0.0.1:1/collector", .fromSeconds(1)));
        try std.testing.expectEqual(output_calls, probe.outbound_calls.load(.acquire));
        try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
        try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
        thread.join();
        joined = true;
        if (worker.error_result) |err| return err;
        try std.testing.expectEqual(@as(usize, 1), worker.requests);
        return;
    }
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    if (collect) {
        const cache = if (comptime Pool == http.Pool) &pool.tickets.tls13 else &pool.tls13_tickets;
        try std.testing.expectEqual(@as(usize, 1), cache.count());
    }
    var second = try pool.requestUriWithTimeout(uri, .{}, .fromSeconds(1));
    defer if (comptime Pool == http.Pool) second.deinit() else second.deinit(allocator);
    try std.testing.expectEqualStrings("ready", if (comptime Pool == http.Pool) second.body() else if (h2) second.body else second.response.body);
    thread.join();
    joined = true;
    if (worker.error_result) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), worker.requests);
    pool.close();
}
