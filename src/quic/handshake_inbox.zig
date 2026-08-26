//! Bounded datagram inbox for one pending QUIC server handshake.
//!
//! The endpoint dispatcher remains the only UDP receiver. It transfers packets
//! addressed to a pending server CID into this queue, while the handshake task
//! waits on an event and consumes owned datagrams through the same shape as an
//! endpoint receive. Capacity is fixed at initialization so an attacker cannot
//! grow memory by flooding one unfinished handshake.

const std = @import("std");
const quic = @import("mod.zig");

pub const Error = quic.connection_router.Error || error{
    InvalidCapacity,
    Closed,
    Full,
    PeerMismatch,
    ConnectionIdMismatch,
};

pub const Inbox = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    connection_ids: []quic.connection_router.ConnectionIdKey,
    peer: std.Io.net.IpAddress,
    mutex: std.Io.Mutex = .init,
    available: std.Io.Event = .unset,
    slots: []?quic.runtime.OwnedBytes,
    head: usize = 0,
    len: usize = 0,
    application_slots: []?quic.runtime.OwnedBytes,
    application_head: usize = 0,
    application_len: usize = 0,
    closed: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        connection_ids: []const []const u8,
        peer: std.Io.net.IpAddress,
        capacity: usize,
    ) Error!Inbox {
        if (capacity == 0) return error.InvalidCapacity;
        if (connection_ids.len == 0 or
            connection_ids.len > quic.connection_id.max_pool_size)
        {
            return error.InvalidConnectionId;
        }
        const owned_connection_ids = try allocator.alloc(
            quic.connection_router.ConnectionIdKey,
            connection_ids.len,
        );
        errdefer allocator.free(owned_connection_ids);
        for (connection_ids, 0..) |connection_id, index| {
            const key = try quic.connection_router.ConnectionIdKey.init(
                connection_id,
            );
            for (owned_connection_ids[0..index]) |existing| {
                if (quic.connection_router.Context.eql(.{}, existing, key)) {
                    return error.DuplicateConnectionId;
                }
            }
            owned_connection_ids[index] = key;
        }
        const slots = try allocator.alloc(?quic.runtime.OwnedBytes, capacity);
        errdefer allocator.free(slots);
        @memset(slots, null);
        const application_slots = try allocator.alloc(
            ?quic.runtime.OwnedBytes,
            capacity,
        );
        errdefer allocator.free(application_slots);
        @memset(application_slots, null);
        return .{
            .allocator = allocator,
            .io = io,
            .connection_ids = owned_connection_ids,
            .peer = peer,
            .slots = slots,
            .application_slots = application_slots,
        };
    }

    pub fn deinit(self: *Inbox) void {
        self.mutex.lockUncancelable(self.io);
        for (0..self.len) |offset| {
            const index = (self.head + offset) % self.slots.len;
            if (self.slots[index]) |*datagram| {
                datagram.deinit(self.allocator);
            }
        }
        for (0..self.application_len) |offset| {
            const index = (self.application_head + offset) %
                self.application_slots.len;
            if (self.application_slots[index]) |*datagram| {
                datagram.deinit(self.allocator);
            }
        }
        self.allocator.free(self.slots);
        self.allocator.free(self.application_slots);
        self.allocator.free(self.connection_ids);
        self.mutex.unlock(self.io);
        self.* = undefined;
    }

    /// CIDs are immutable for the lifetime of an inbox, so a dispatcher can
    /// safely register this borrowed slice while the caller retains ownership
    /// of the inbox itself. Typically these are the client's original DCID
    /// (for fragmented/retransmitted Initials) and the server-selected CID
    /// (for Handshake and 0-RTT packets sent after the server flight).
    pub fn connectionIds(
        self: *const Inbox,
    ) []const quic.connection_router.ConnectionIdKey {
        return self.connection_ids;
    }

    /// Transfer one datagram into the inbox. Rejected datagrams remain owned
    /// by the caller, allowing dispatcher policy to drop or reroute them.
    pub fn push(
        self: *Inbox,
        datagram: quic.runtime.OwnedBytes,
    ) Error!void {
        const destination_connection_id =
            try destinationConnectionId(datagram.bytes);
        if (!self.acceptsConnectionId(destination_connection_id)) {
            return error.ConnectionIdMismatch;
        }
        if (!sameAddress(self.peer, datagram.from)) return error.PeerMismatch;

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.closed) return error.Closed;
        if (self.len + self.application_len == self.slots.len) {
            return error.Full;
        }
        const index = (self.head + self.len) % self.slots.len;
        self.slots[index] = datagram;
        self.len += 1;
        self.available.set(self.io);
    }

    pub fn close(self: *Inbox) void {
        self.mutex.lockUncancelable(self.io);
        self.closed = true;
        self.available.set(self.io);
        self.mutex.unlock(self.io);
    }

    /// Retain a short-header packet that arrived after Client Finished but
    /// before the dispatcher observed handshake completion. The dispatcher
    /// has already matched its DCID; this method keeps a separate queue so the
    /// handshake worker cannot consume and discard application data.
    pub fn pushApplicationRouted(
        self: *Inbox,
        datagram: quic.runtime.OwnedBytes,
    ) Error!void {
        if (datagram.bytes.len == 0 or (datagram.bytes[0] & 0x80) != 0) {
            return error.ConnectionIdMismatch;
        }
        if (!sameAddress(self.peer, datagram.from)) return error.PeerMismatch;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.closed) return error.Closed;
        if (self.len + self.application_len == self.slots.len) {
            return error.Full;
        }
        const index = (self.application_head + self.application_len) %
            self.application_slots.len;
        self.application_slots[index] = datagram;
        self.application_len += 1;
    }

    pub fn applicationCount(self: *Inbox) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.application_len;
    }

    pub fn takeApplication(self: *Inbox) ?quic.runtime.OwnedBytes {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.application_len == 0) return null;
        const datagram = self.application_slots[self.application_head].?;
        self.application_slots[self.application_head] = null;
        self.application_head =
            (self.application_head + 1) % self.application_slots.len;
        self.application_len -= 1;
        return datagram;
    }

    pub fn count(self: *Inbox) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.len;
    }

    pub fn receive(
        self: *Inbox,
    ) (Error || std.Io.Cancelable)!quic.runtime.OwnedBytes {
        return self.receiveTimeoutInternal(.none) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return other,
        };
    }

    pub fn receiveTimeout(
        self: *Inbox,
        timeout: std.Io.Timeout,
    ) (Error || std.Io.Event.WaitTimeoutError)!quic.runtime.OwnedBytes {
        return self.receiveTimeoutInternal(timeout);
    }

    pub fn datagramSource(self: *Inbox) quic.runtime.DatagramSource {
        return .{
            .context = self,
            .receive_timeout_fn = receiveForSource,
        };
    }

    fn receiveForSource(
        context: *anyopaque,
        timeout: std.Io.Timeout,
    ) quic.runtime.ReceiveTimeoutError!quic.runtime.OwnedBytes {
        const self: *Inbox = @ptrCast(@alignCast(context));
        return self.receiveTimeoutInternal(timeout) catch |err| switch (err) {
            error.Closed => error.SocketUnconnected,
            error.Timeout, error.Canceled => |other| return other,
            else => unreachable,
        };
    }

    fn receiveTimeoutInternal(
        self: *Inbox,
        timeout: std.Io.Timeout,
    ) (error{ Closed, Timeout } || std.Io.Cancelable)!quic.runtime.OwnedBytes {
        const deadline = timeout.toDeadline(self.io);
        while (true) {
            self.mutex.lockUncancelable(self.io);
            if (self.len != 0) {
                const datagram = self.slots[self.head].?;
                self.slots[self.head] = null;
                self.head = (self.head + 1) % self.slots.len;
                self.len -= 1;
                if (self.len == 0 and !self.closed) self.available.reset();
                self.mutex.unlock(self.io);
                return datagram;
            }
            const closed = self.closed;
            if (!closed) self.available.reset();
            self.mutex.unlock(self.io);
            if (closed) return error.Closed;
            try self.available.waitTimeout(self.io, deadline);
        }
    }

    fn acceptsConnectionId(
        self: *const Inbox,
        connection_id: []const u8,
    ) bool {
        for (self.connection_ids) |candidate| {
            if (std.mem.eql(u8, candidate.slice(), connection_id)) return true;
        }
        return false;
    }
};

fn destinationConnectionId(bytes: []const u8) Error![]const u8 {
    if (bytes.len < 6 or (bytes[0] & 0x80) == 0) {
        return error.ConnectionIdMismatch;
    }
    const length = bytes[5];
    if (length == 0 or length > quic.connection_router.max_connection_id_len or
        bytes.len < 6 + @as(usize, length))
    {
        return error.ConnectionIdMismatch;
    }
    return bytes[6 .. 6 + @as(usize, length)];
}

fn sameAddress(a: std.Io.net.IpAddress, b: std.Io.net.IpAddress) bool {
    return a.eql(&b);
}

test "QUIC pending handshake inbox is bounded filtered and FIFO" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const peer = std.Io.net.IpAddress{ .ip4 = .loopback(4433) };
    var inbox = try Inbox.init(
        allocator,
        io,
        &.{ "original", "server" },
        peer,
        2,
    );
    defer inbox.deinit();

    const first = try makeLongDatagram(allocator, "server", 'a');
    try inbox.push(.{ .from = peer, .bytes = first });
    const second = try makeLongDatagram(allocator, "original", 'b');
    try inbox.push(.{ .from = peer, .bytes = second });
    try std.testing.expectEqual(@as(usize, 2), inbox.count());

    const extra = try makeLongDatagram(allocator, "server", 'c');
    var extra_owned = quic.runtime.OwnedBytes{ .from = peer, .bytes = extra };
    defer extra_owned.deinit(allocator);
    try std.testing.expectError(error.Full, inbox.push(extra_owned));

    var received_first = try inbox.receive();
    defer received_first.deinit(allocator);
    var received_second = try inbox.receive();
    defer received_second.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 'a'),
        received_first.bytes[6 + "server".len],
    );
    try std.testing.expectEqual(
        @as(u8, 'b'),
        received_second.bytes[6 + "original".len],
    );

    const wrong_cid = try makeLongDatagram(allocator, "other", 'd');
    var wrong_cid_owned = quic.runtime.OwnedBytes{
        .from = peer,
        .bytes = wrong_cid,
    };
    defer wrong_cid_owned.deinit(allocator);
    try std.testing.expectError(
        error.ConnectionIdMismatch,
        inbox.push(wrong_cid_owned),
    );

    const wrong_peer = try makeLongDatagram(allocator, "server", 'e');
    var wrong_peer_owned = quic.runtime.OwnedBytes{
        .from = .{ .ip4 = .loopback(4434) },
        .bytes = wrong_peer,
    };
    defer wrong_peer_owned.deinit(allocator);
    try std.testing.expectError(error.PeerMismatch, inbox.push(wrong_peer_owned));
}

test "QUIC pending handshake inbox wakes and closes waiters" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const peer = std.Io.net.IpAddress{ .ip4 = .loopback(4433) };
    var inbox = try Inbox.init(allocator, io, &.{"server"}, peer, 1);
    defer inbox.deinit();

    try std.testing.expectError(error.Timeout, inbox.receiveTimeout(.{
        .duration = .{
            .clock = .awake,
            .raw = .fromMilliseconds(1),
        },
    }));
    inbox.close();
    try std.testing.expectError(error.Closed, inbox.receive());
}

test "QUIC pending handshake datagram source maps close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var inbox = try Inbox.init(
        allocator,
        io,
        &.{"server"},
        .{ .ip4 = .loopback(4433) },
        1,
    );
    defer inbox.deinit();
    inbox.close();
    try std.testing.expectError(
        error.SocketUnconnected,
        inbox.datagramSource().receive(),
    );
}

fn makeLongDatagram(
    allocator: std.mem.Allocator,
    connection_id: []const u8,
    marker: u8,
) ![]u8 {
    const bytes = try allocator.alloc(u8, 6 + connection_id.len + 1);
    bytes[0] = 0xc0;
    std.mem.writeInt(u32, bytes[1..5], 1, .big);
    bytes[5] = @intCast(connection_id.len);
    @memcpy(bytes[6..][0..connection_id.len], connection_id);
    bytes[6 + connection_id.len] = marker;
    return bytes;
}
