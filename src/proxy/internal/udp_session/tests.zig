//! Actual datagram I/O, immutable queue ownership and joined retirement.
const std = @import("std");
const Session = @import("../udp_session.zig").Session;
const native = @import("../../../internal/testing/native_protocol_io.zig");
const forwarded = @import("../../../internal/testing/forwarded_io.zig");
const Native = @import("../../../internal/testing/deadline_send_io.zig").Native;
const net = std.Io.net;
const allocator = std.testing.allocator;

const Gate = struct {
    delegate: std.Io,
    entered: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    borrowed: []const u8 = &.{},
    maximum: usize = 4096,
    positive_error: bool = false,
    reject: bool = false,
    positive_receive_error: std.atomic.Value(bool) = .init(false),
    receive_calls: std.atomic.Value(usize) = .init(0),
    receive_entered: std.Io.Event = .unset,
    fail_receive_after_packet: std.atomic.Value(bool) = .init(false),
    fail_next_receive: std.atomic.Value(bool) = .init(false),
    lookup_blocked: bool = false,
    lookup_entered: std.Io.Event = .unset,
    lookup_release: std.Io.Event = .unset,
    lookup_canceled: std.atomic.Value(usize) = .init(0),
    fn lookup(context: ?*anyopaque, host: net.HostName, resolved: *std.Io.Queue(net.HostName.LookupResult), options: net.HostName.LookupOptions) net.HostName.LookupError!void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        if (self.lookup_blocked) {
            self.lookup_entered.set(self.delegate);
            self.lookup_release.wait(self.delegate) catch |err| {
                resolved.close(self.delegate);
                _ = self.lookup_canceled.fetchAdd(1, .acq_rel);
                return err;
            };
        }
        return self.delegate.vtable.netLookup(self.delegate.userdata, host, resolved, options);
    }
    fn operate(context: ?*anyopaque, operation: std.Io.Operation) std.Io.Cancelable!std.Io.Operation.Result {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        const delegate = self.delegate;
        if (operation == .net_receive) {
            _ = self.receive_calls.fetchAdd(1, .acq_rel);
            self.receive_entered.set(delegate);
            if (self.fail_next_receive.swap(false, .acq_rel)) return .{ .net_receive = .{ error.NetworkDown, 0 } };
        }
        const result = try delegate.operate(operation);
        if (result == .net_receive and result.net_receive[1] == 1 and self.fail_receive_after_packet.load(.acquire)) self.fail_next_receive.store(true, .release);
        if (result == .net_receive and result.net_receive[1] == 1 and self.positive_receive_error.load(.acquire)) {
            return .{ .net_receive = .{ error.NetworkDown, 1 } };
        }
        return result;
    }
    fn send(context: ?*anyopaque, handle: net.Socket.Handle, messages: []net.OutgoingMessage, flags: net.SendFlags) struct { ?net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.borrowed = messages[0].data_ptr[0..messages[0].data_len];
        self.entered.set(self.delegate);
        self.release.wait(self.delegate) catch return .{ error.Canceled, 0 };
        if (self.reject) return .{ error.NetworkDown, 0 };
        messages[0].data_len = @min(self.maximum, messages[0].data_len);
        const err, const count = self.delegate.vtable.netSend(self.delegate.userdata, handle, messages, flags);
        return .{ if (self.positive_error and count == 1) error.Canceled else err, count };
    }
};

pub const Fixture = struct {
    base: std.Io,
    socket: net.Socket,
    peer: net.Socket,
    owns_socket: bool = true,
    gate: Gate,
    session: Session = .{},
    changed: std.Io.Event = .unset,
    pub fn init(self: *@This(), base: std.Io, limit: usize) !void {
        const socket = try (net.IpAddress{ .ip4 = .loopback(0) }).bind(base, .{ .mode = .dgram, .protocol = .udp });
        errdefer socket.close(base);
        const peer = try (net.IpAddress{ .ip4 = .loopback(0) }).bind(base, .{ .mode = .dgram, .protocol = .udp });
        errdefer peer.close(base);
        self.* = .{ .base = base, .socket = socket, .peer = peer, .gate = .{ .delegate = base } };
        try self.session.init(allocator, self.observed(), socket, .{ .maximum_datagram_bytes = limit, .resolve_timeout = .fromSeconds(1), .notify_context = self, .notify = notify });
    }
    pub fn observed(self: *@This()) std.Io {
        return forwarded.observer(&self.gate, .{ .netSend = Gate.send, .operate = Gate.operate, .netLookup = Gate.lookup });
    }
    fn notify(context: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.changed.set(self.base);
    }
    pub fn entered(self: *@This()) !void {
        try self.gate.entered.waitTimeout(self.base, timeout);
    }
    pub fn sent(self: *@This()) !Session.Completion {
        const deadline = std.Io.Clock.Timestamp.fromNow(self.base, .{ .clock = .awake, .raw = .fromSeconds(2) });
        while (true) {
            self.changed.reset();
            if (self.session.takeSent()) |result| return result;
            try self.changed.waitTimeout(self.base, .{ .deadline = deadline });
        }
    }
    fn received(self: *@This()) !Session.Packet {
        const deadline = std.Io.Clock.Timestamp.fromNow(self.base, .{ .clock = .awake, .raw = .fromSeconds(2) });
        while (true) {
            self.changed.reset();
            if (self.session.takeReceived()) |result| return result;
            if (self.session.receive_failed.load(.acquire)) return error.ReceiveFailed;
            try self.changed.waitTimeout(self.base, .{ .deadline = deadline });
        }
    }
    pub fn readExact(self: *@This(), expected: []const u8) !void {
        var bytes: [4096]u8 = undefined;
        const message = try self.peer.receiveTimeout(self.base, &bytes, timeout);
        try std.testing.expectEqualSlices(u8, expected, message.data);
        try std.testing.expectEqual(self.socket.address.getPort(), message.from.getPort());
    }
    pub fn deinit(self: *@This()) void {
        self.session.deinit();
        if (self.owns_socket) self.socket.close(self.base);
        self.peer.close(self.base);
    }
};
const timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } };

fn boundedSends(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 64);
    defer fixture.deinit();
    var payload = [_]u8{'a'} ** 6;
    try std.testing.expect(try fixture.session.enqueue(.{ .ip = fixture.peer.address }, &payload));
    try fixture.entered();
    payload[0] = 'X';
    try std.testing.expectEqualSlices(u8, "aaaaaa", fixture.gate.borrowed);
    for (1..Session.send_capacity) |i| {
        payload[0] = @intCast(i);
        try std.testing.expect(try fixture.session.enqueue(.{ .ip = fixture.peer.address }, &payload));
    }
    try std.testing.expect(!try fixture.session.enqueue(.{ .ip = fixture.peer.address }, "full"));
    fixture.gate.release.set(base);
    for (0..Session.send_capacity) |i| {
        payload[0] = if (i == 0) 'a' else @intCast(i);
        try fixture.readExact(&payload);
        const result = try fixture.sent();
        try std.testing.expectEqual(@as(usize, 6), result.reserved_bytes);
        try std.testing.expectEqual(@as(usize, 6), result.committed_bytes);
        try std.testing.expect(result.failure == null);
    }
    try std.testing.expect(fixture.session.takeSent() == null);
    try std.testing.expect(try fixture.session.enqueue(.{ .ip = fixture.peer.address }, "reuse"));
    try fixture.readExact("reuse");
    _ = try fixture.sent();
}
test "proxy UDP session bounded FIFO copies input and recycles slots" {
    try native.run(boundedSends);
}

fn cancelSends(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 64);
    defer fixture.deinit();
    for (0..Session.send_capacity) |_| try std.testing.expect(try fixture.session.enqueue(.{ .ip = fixture.peer.address }, "cancel"));
    try fixture.entered();
    fixture.session.stop();
    var count: usize = 0;
    while (fixture.session.takeSent()) |result| {
        count += 1;
        try std.testing.expectEqual(@as(usize, 6), result.reserved_bytes);
        try std.testing.expectEqual(@as(usize, 0), result.committed_bytes);
        try std.testing.expectEqual(error.Canceled, result.failure.?);
    }
    try std.testing.expectEqual(Session.send_capacity, count);
    try std.testing.expect(!try fixture.session.enqueue(.{ .ip = fixture.peer.address }, "late"));
    try std.testing.expect(fixture.session.takeReceived() == null);
    fixture.session.stop();
}
test "proxy UDP session stop joins blocked send and refunds queued ownership once" {
    try native.run(cancelSends);
}

fn sendProgress(base: std.Io) !void {
    inline for (.{ .{ 6, true, false }, .{ 3, true, false }, .{ 6, false, true } }) |mode| {
        var fixture: Fixture = undefined;
        try fixture.init(base, 64);
        defer fixture.deinit();
        fixture.gate.maximum = mode[0];
        fixture.gate.positive_error = mode[1];
        fixture.gate.reject = mode[2];
        fixture.gate.release.set(base);
        try std.testing.expect(try fixture.session.enqueue(.{ .ip = fixture.peer.address }, "abcdef"));
        const result = try fixture.sent();
        const committed: usize = if (mode[2]) 0 else mode[0];
        try std.testing.expectEqual(@as(usize, 6), result.reserved_bytes);
        try std.testing.expectEqual(committed, result.committed_bytes);
        if (mode[2]) try std.testing.expectEqual(error.NetworkDown, result.failure.?) else if (mode[0] == 3) try std.testing.expectEqual(error.MessageOversize, result.failure.?) else try std.testing.expect(result.failure == null);
        if (committed != 0) try fixture.readExact("abcdef"[0..committed]);
    }
}
test "proxy UDP session positive send count preserves exact committed bytes with error" {
    try native.run(sendProgress);
}

fn receiveLeases(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 8);
    defer fixture.deinit();
    var leases: [Session.receive_capacity]Session.Packet = undefined;
    var held: usize = 0;
    defer for (leases[0..held]) |*packet| packet.release();
    for (0..Session.receive_capacity) |i| {
        try fixture.peer.send(base, &fixture.socket.address, &.{@intCast(i)});
        leases[i] = try fixture.received();
        held += 1;
        try std.testing.expectEqualSlices(u8, &.{@intCast(i)}, leases[i].bytes);
        try std.testing.expect(!leases[i].truncated);
    }
    try fixture.peer.send(base, &fixture.socket.address, "ninth");
    try std.testing.expect(fixture.session.takeReceived() == null);
    for (&leases, 0..) |*lease, i| try std.testing.expectEqualSlices(u8, &.{@intCast(i)}, lease.bytes);
    leases[0].release();
    var ninth = try fixture.received();
    defer ninth.release();
    try std.testing.expectEqualSlices(u8, "ninth", ninth.bytes);
    try std.testing.expectEqual(fixture.peer.address.getPort(), ninth.from.getPort());
    fixture.session.stop();
    try std.testing.expectEqualSlices(u8, "ninth", ninth.bytes);
    for (leases[1..], 1..) |*lease, i| try std.testing.expectEqualSlices(u8, &.{@intCast(i)}, lease.bytes);
}
test "proxy UDP session receive leases survive full queue and joined stop" {
    try native.run(receiveLeases);
}

fn receiveEdges(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 8);
    defer fixture.deinit();
    fixture.gate.positive_receive_error.store(true, .release);
    try fixture.peer.send(base, &fixture.socket.address, "");
    var empty = try fixture.received();
    try std.testing.expectEqual(@as(usize, 0), empty.bytes.len);
    try std.testing.expect(!empty.truncated);
    empty.release();
    try fixture.peer.send(base, &fixture.socket.address, "0123456789");
    var truncated = try fixture.received();
    defer truncated.release();
    try std.testing.expect(truncated.truncated);
    try std.testing.expectEqualSlices(u8, "01234567", truncated.bytes);
    try std.testing.expectError(error.DatagramTooLarge, fixture.session.enqueue(.{ .ip = fixture.peer.address }, "0123456789"));
}
test "proxy UDP session retains zero datagrams and reports truncation" {
    try native.run(receiveEdges);
}

fn domainOwnership(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 64);
    defer fixture.deinit();
    try std.testing.expect(try fixture.session.enqueue(.{ .ip = fixture.peer.address }, "first"));
    try fixture.entered();
    fixture.session.options.policy = .{ .default_action = .allow };
    var host = "127.0.0.1".*;
    try std.testing.expect(try fixture.session.enqueue(.{ .domain = .{ .host = &host, .port = fixture.peer.address.getPort() } }, "domain"));
    @memset(&host, 'X');
    fixture.gate.release.set(base);
    try fixture.readExact("first");
    _ = try fixture.sent();
    try fixture.readExact("domain");
    const result = try fixture.sent();
    try std.testing.expectEqual(@as(usize, 6), result.committed_bytes);
    try std.testing.expect(result.failure == null);
}
test "proxy UDP session owns queued host until bounded resolution completes" {
    try native.run(domainOwnership);
}

fn allocationFailure(base: std.Io) !void {
    const socket = try (net.IpAddress{ .ip4 = .loopback(0) }).bind(base, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(base);
    var storage: [0]u8 = .{};
    var failing = std.heap.FixedBufferAllocator.init(&storage);
    var session: Session = .{};
    try session.init(failing.allocator(), base, socket, .{ .maximum_datagram_bytes = 8, .resolve_timeout = .fromSeconds(1) });
    defer session.deinit();
    try std.testing.expectError(error.OutOfMemory, session.enqueue(.{ .ip = socket.address }, "oom"));
    var indices: [Session.send_capacity]usize = undefined;
    const count = try session.send_free.get(base, &indices, 0);
    try std.testing.expectEqual(Session.send_capacity, count);
    for (&session.send_slots) |*slot| try std.testing.expect(!slot.active);
    session.stop();
    try std.testing.expect(session.takeSent() == null);
}
test "proxy UDP session allocation rejection returns its unpublished slot" {
    try native.run(allocationFailure);
}

fn blockedLookup(base: std.Io) !void {
    inline for (.{ false, true }) |expire| {
        var clock: Native = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .delegate_io = base };
        defer clock.backend.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(base, 64);
        defer fixture.deinit();
        try fixture.gate.receive_entered.waitTimeout(base, timeout);
        fixture.gate.delegate = clock.io();
        fixture.gate.lookup_blocked = true;
        fixture.session.options.policy = .{ .default_action = .allow };
        try std.testing.expect(try fixture.session.enqueue(.{ .domain = .{ .host = "localhost", .port = fixture.peer.address.getPort() } }, "lookup"));
        try fixture.gate.lookup_entered.waitTimeout(base, timeout);
        // An independently scheduled target continues while DNS owns the first.
        var sibling: Fixture = undefined;
        try sibling.init(base, 64);
        defer sibling.deinit();
        sibling.gate.release.set(base);
        try std.testing.expect(try sibling.session.enqueue(.{ .ip = sibling.peer.address }, "healthy"));
        try sibling.readExact("healthy");
        try std.testing.expectEqual(@as(usize, 7), (try sibling.sent()).committed_bytes);
        const result = if (expire) blk: {
            clock.setNow(std.time.ns_per_s);
            break :blk try fixture.sent();
        } else blk: {
            fixture.session.stop();
            break :blk fixture.session.takeSent().?;
        };
        try std.testing.expectEqual(@as(usize, 6), result.reserved_bytes);
        try std.testing.expectEqual(@as(usize, 0), result.committed_bytes);
        try std.testing.expectEqual(if (expire) error.Timeout else error.Canceled, result.failure.?);
        try std.testing.expectEqual(@as(usize, 1), fixture.gate.lookup_canceled.load(.acquire));
        try std.testing.expect(fixture.session.takeSent() == null);
    }
}
test "proxy UDP session blocked DNS keeps sibling live and joins deadline or cancellation" {
    try native.run(blockedLookup);
}
