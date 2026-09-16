//! Reusable receive storage for one integrated QUIC handshake.
//!
//! Direct endpoint sources can receive into caller storage, following the
//! allocate-once receive-loop pattern used by Quinn and tquic. Routed inboxes
//! retain their existing owned-datagram contract. If a caller holds one
//! borrowed datagram across a nested receive, the nested operation safely
//! falls back to the source's owning path.

const std = @import("std");
const quic = @import("../mod.zig");

pub const Reader = struct {
    allocator: std.mem.Allocator,
    upstream: quic.runtime.DatagramSource,
    storage: []u8 = &.{},
    borrowed: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        upstream: quic.runtime.DatagramSource,
    ) Reader {
        return .{
            .allocator = allocator,
            .upstream = upstream,
        };
    }

    pub fn deinit(self: *Reader) void {
        std.debug.assert(!self.borrowed);
        if (self.storage.len != 0) self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn datagramSource(self: *Reader) quic.runtime.DatagramSource {
        if (self.upstream.receiveIntoCapacity() == 0) return self.upstream;
        return .{
            .context = self,
            .receive_timeout_fn = receiveForSource,
        };
    }

    pub fn storageCapacity(self: Reader) usize {
        return self.storage.len;
    }

    /// Move the receive allocation into established connection state.
    pub fn takeStorage(self: *Reader) ?[]u8 {
        std.debug.assert(!self.borrowed);
        if (self.storage.len == 0) return null;
        const storage = self.storage;
        self.storage = &.{};
        return storage;
    }

    fn receiveForSource(
        context: *anyopaque,
        timeout: std.Io.Timeout,
    ) quic.runtime.ReceiveTimeoutError!quic.runtime.OwnedBytes {
        const self: *Reader = @ptrCast(@alignCast(context));
        const receive_capacity = self.upstream.receiveIntoCapacity();
        if (!self.borrowed and receive_capacity != 0) {
            if (self.storage.len == 0) {
                self.storage = try self.allocator.alloc(
                    u8,
                    receive_capacity,
                );
            }
            if (try self.upstream.receiveIntoTimeout(
                self.storage,
                timeout,
            )) |received| {
                self.borrowed = true;
                return .{
                    .from = received.from,
                    .received_on = received.received_on,
                    .bytes = received.bytes,
                    .ecn = received.ecn,
                    .borrowed_release = .{
                        .context = self,
                        .release_fn = releaseBorrow,
                    },
                };
            }
        }
        return self.upstream.receiveTimeout(timeout);
    }

    fn releaseBorrow(context: *anyopaque) void {
        const self: *Reader = @ptrCast(@alignCast(context));
        std.debug.assert(self.borrowed);
        self.borrowed = false;
    }
};

test "QUIC handshake reader reuses endpoint receive storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer sender.deinit();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer receiver.deinit();

    var reader = Reader.init(
        allocator,
        .fromEndpoint(&receiver),
    );
    defer reader.deinit();
    const source = reader.datagramSource();

    try sender.sendBytes(receiver.address(), "first");
    var first = try source.receive();
    const storage = first.bytes.ptr;
    try std.testing.expectEqualStrings("first", first.bytes);
    first.deinit(allocator);

    try sender.sendBytes(receiver.address(), "second");
    var second = try source.receive();
    defer second.deinit(allocator);
    try std.testing.expectEqual(storage, second.bytes.ptr);
    try std.testing.expectEqualStrings("second", second.bytes);
    try std.testing.expectEqual(@as(usize, 1400), reader.storageCapacity());
}

test "QUIC handshake reader preserves an outstanding borrow" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer sender.deinit();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer receiver.deinit();

    var reader = Reader.init(allocator, .fromEndpoint(&receiver));
    defer reader.deinit();
    const source = reader.datagramSource();
    try sender.sendBytes(receiver.address(), "held");
    var held = try source.receive();
    defer held.deinit(allocator);
    try sender.sendBytes(receiver.address(), "nested");
    var nested = try source.receive();
    defer nested.deinit(allocator);

    try std.testing.expectEqualStrings("held", held.bytes);
    try std.testing.expectEqualStrings("nested", nested.bytes);
    try std.testing.expect(held.bytes.ptr != nested.bytes.ptr);
}

test "QUIC handshake reader preserves owning source semantics" {
    const OwnedSource = struct {
        allocator: std.mem.Allocator,
        emitted: bool = false,

        fn receive(
            context: *anyopaque,
            _: std.Io.Timeout,
        ) quic.runtime.ReceiveTimeoutError!quic.runtime.OwnedBytes {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.emitted) return error.Timeout;
            self.emitted = true;
            return .{
                .from = .{ .ip4 = .loopback(443) },
                .bytes = try self.allocator.dupe(u8, "owned"),
            };
        }
    };

    const allocator = std.testing.allocator;
    var upstream = OwnedSource{ .allocator = allocator };
    var reader = Reader.init(allocator, .{
        .context = &upstream,
        .receive_timeout_fn = OwnedSource.receive,
    });
    defer reader.deinit();

    var datagram = try reader.datagramSource().receive();
    defer datagram.deinit(allocator);
    try std.testing.expectEqualStrings("owned", datagram.bytes);
    try std.testing.expectEqual(@as(usize, 0), reader.storageCapacity());
    try std.testing.expect(reader.takeStorage() == null);
}

test "QUIC handshake reader transfers storage to established receive scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer sender.deinit();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer receiver.deinit();

    var reader = Reader.init(allocator, .fromEndpoint(&receiver));
    defer reader.deinit();
    try sender.sendBytes(receiver.address(), "handshake");
    var datagram = try reader.datagramSource().receive();
    const storage_ptr = datagram.bytes.ptr;
    datagram.deinit(allocator);

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x4d} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection
        .initWithReceivePacketStorage(
        &receiver,
        .{
            .peer = sender.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "local",
            .peer_connection_id = "peer",
            .max_datagram_size = 1400,
        },
        reader.takeStorage(),
    );
    defer connection.deinit();
    try std.testing.expectEqual(
        storage_ptr,
        connection.scratch.receive_packet.allocatedSlice().ptr,
    );
}
