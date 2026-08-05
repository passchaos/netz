const std = @import("std");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.Error || error{
    EmptyDatagram,
    DatagramTooLarge,
    TrailingBytes,
    NoConnectionRoute,
} || quic.connection_router.Error || net.IpAddress.BindError || net.Socket.SendError || net.Socket.ReceiveError || std.Io.Cancelable;

pub const Limits = struct {
    max_datagram_size: usize = 65_535,
    max_frames_per_datagram: usize = 256,
};

pub const Server = struct {
    endpoint: Endpoint,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{ .endpoint = try .bind(allocator, io, bind_address, limits) };
    }

    pub fn deinit(self: *Server) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn receive(self: *Server) Error!OwnedDatagram {
        return self.endpoint.receive();
    }

    pub fn sendFrames(self: *Server, to: net.IpAddress, frames: []const quic.Frame) Error!void {
        try self.endpoint.sendFrames(to, frames);
    }
};

pub const Client = struct {
    endpoint: Endpoint,
    peer: net.IpAddress,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, peer: net.IpAddress, limits: Limits) Error!Client {
        return .{
            .endpoint = try .bind(allocator, io, local_address, limits),
            .peer = peer,
        };
    }

    pub fn deinit(self: *Client) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: Client) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn sendFrames(self: *Client, frames: []const quic.Frame) Error!void {
        try self.endpoint.sendFrames(self.peer, frames);
    }

    pub fn receive(self: *Client) Error!OwnedDatagram {
        return self.endpoint.receive();
    }
};

pub const Endpoint = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    socket: net.Socket,
    limits: Limits = .{},

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Endpoint {
        return .{
            .io = io,
            .allocator = allocator,
            .socket = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *Endpoint) void {
        self.socket.close(self.io);
        self.* = undefined;
    }

    pub fn address(self: Endpoint) net.IpAddress {
        return self.socket.address;
    }

    pub fn sendBytes(self: *Endpoint, to: net.IpAddress, bytes: []const u8) Error!void {
        if (bytes.len == 0) return error.EmptyDatagram;
        if (bytes.len > self.limits.max_datagram_size) return error.DatagramTooLarge;
        try self.socket.send(self.io, &to, bytes);
    }

    pub fn sendFrames(self: *Endpoint, to: net.IpAddress, frames: []const quic.Frame) Error!void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);
        for (frames) |frame| try frame.write(&payload, self.allocator);
        try self.sendBytes(to, payload.items);
    }

    pub fn receive(self: *Endpoint) Error!OwnedDatagram {
        var raw = try self.receiveBytes();
        errdefer raw.deinit(self.allocator);
        if (raw.bytes.len == 0) return error.EmptyDatagram;

        var frames: std.ArrayList(quic.Frame) = .empty;
        errdefer {
            quic.deinitOwnedFrameSlice(frames.items, self.allocator);
            frames.deinit(self.allocator);
        }

        var pos: usize = 0;
        while (pos < raw.bytes.len) {
            if (frames.items.len >= self.limits.max_frames_per_datagram) return error.DatagramTooLarge;
            var parsed = try quic.parseFrameOwned(self.allocator, raw.bytes[pos..]);
            var appended = false;
            defer if (!appended) parsed.deinitOwned(self.allocator);
            if (parsed.consumed == 0) return error.TrailingBytes;
            try frames.append(self.allocator, parsed.frame);
            appended = true;
            pos += parsed.consumed;
        }

        const owned_frames = try frames.toOwnedSlice(self.allocator);
        return .{ .from = raw.from, .bytes = raw.bytes, .frames = owned_frames };
    }

    pub fn receiveBytes(self: *Endpoint) Error!OwnedBytes {
        const buffer = try self.allocator.alloc(u8, self.limits.max_datagram_size);
        defer self.allocator.free(buffer);
        const incoming = try self.socket.receive(self.io, buffer);
        if (incoming.data.len == 0) return error.EmptyDatagram;

        const bytes = try self.allocator.dupe(u8, incoming.data);
        return .{ .from = incoming.from, .bytes = bytes };
    }

    pub fn receiveRoutedBytes(self: *Endpoint, router: quic.connection_router.Router) Error!RoutedBytes {
        var raw = try self.receiveBytes();
        errdefer raw.deinit(self.allocator);
        const routed = (try router.routeDatagram(raw.bytes)) orelse return error.NoConnectionRoute;
        return .{ .datagram = raw, .route = routed.route, .destination_connection_id = routed.destination_connection_id };
    }

    pub fn receiveManyConcurrent(self: *Endpoint, count: usize) Error!OwnedDatagramBatch {
        var group: std.Io.Group = .init;
        const datagrams = try self.allocator.alloc(?OwnedDatagram, count);
        errdefer self.allocator.free(datagrams);
        @memset(datagrams, null);
        const errors = try self.allocator.alloc(?anyerror, count);
        errdefer self.allocator.free(errors);
        @memset(errors, null);

        for (datagrams, errors) |*datagram, *err_slot| {
            const task = ReceiveTask{
                .endpoint = self,
                .datagram = datagram,
                .err = err_slot,
            };
            group.async(self.io, ReceiveTask.run, .{task});
        }

        try group.await(self.io);
        return .{ .allocator = self.allocator, .datagrams = datagrams, .errors = errors };
    }
};

const ReceiveTask = struct {
    endpoint: *Endpoint,
    datagram: *?OwnedDatagram,
    err: *?anyerror,

    fn run(task: ReceiveTask) std.Io.Cancelable!void {
        task.datagram.* = task.endpoint.receive() catch |err| {
            task.err.* = err;
            return;
        };
        task.err.* = null;
    }
};

pub const OwnedBytes = struct {
    from: net.IpAddress,
    bytes: []u8,

    pub fn deinit(self: *OwnedBytes, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const RoutedBytes = struct {
    datagram: OwnedBytes,
    route: quic.connection_router.Route,
    destination_connection_id: []const u8,

    pub fn deinit(self: *RoutedBytes, allocator: std.mem.Allocator) void {
        self.datagram.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,
    frames: []quic.Frame,

    pub fn deinit(self: *OwnedDatagram, allocator: std.mem.Allocator) void {
        quic.deinitOwnedFrameSlice(self.frames, allocator);
        allocator.free(self.frames);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const OwnedDatagramBatch = struct {
    allocator: std.mem.Allocator,
    datagrams: []?OwnedDatagram,
    errors: []?anyerror,

    pub fn deinit(self: *OwnedDatagramBatch) void {
        for (self.datagrams) |*datagram| {
            if (datagram.*) |*owned| owned.deinit(self.allocator);
        }
        self.allocator.free(self.datagrams);
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: OwnedDatagramBatch) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn receivedCount(self: OwnedDatagramBatch) usize {
        var count: usize = 0;
        for (self.datagrams) |datagram| {
            if (datagram != null) count += 1;
        }
        return count;
    }
};

test "QUIC UDP endpoint sends and receives frame datagrams" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer server.deinit();

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client.deinit();

    const outbound = [_]quic.Frame{
        .{ .ping = {} },
        .{ .datagram = .{ .data = "hello", .length_present = true } },
    };
    try client.sendFrames(&outbound);

    var received = try server.receive();
    defer received.deinit(allocator);
    try std.testing.expect(received.from.eql(&client.address()));
    try std.testing.expectEqual(@as(usize, 2), received.frames.len);
    try std.testing.expectEqualStrings("hello", received.frames[1].datagram.data);

    const response = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = "world", .fin = true } },
    };
    try server.sendFrames(received.from, &response);

    var client_received = try client.receive();
    defer client_received.deinit(allocator);
    try std.testing.expect(client_received.from.eql(&server.address()));
    try std.testing.expectEqual(@as(usize, 1), client_received.frames.len);
    try std.testing.expectEqualStrings("world", client_received.frames[0].stream.data);
}

test "QUIC UDP endpoint receives many datagrams with std.Io async" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer server.deinit();

    var client_a = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client_a.deinit();
    var client_b = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client_b.deinit();

    const Shared = struct {
        endpoint: *Endpoint,
        batch: ?OwnedDatagramBatch = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.batch = shared.endpoint.receiveManyConcurrent(2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .endpoint = &server.endpoint };
    const receiver = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const frames_a = [_]quic.Frame{.{ .datagram = .{ .data = "a", .length_present = true } }};
    const frames_b = [_]quic.Frame{.{ .datagram = .{ .data = "b", .length_present = true } }};
    try client_a.sendFrames(&frames_a);
    try client_b.sendFrames(&frames_b);

    receiver.join();
    if (shared.err) |err| return err;
    var batch = shared.batch.?;
    defer batch.deinit();
    if (batch.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), batch.receivedCount());

    var saw_a = false;
    var saw_b = false;
    for (batch.datagrams) |maybe_datagram| {
        const datagram = maybe_datagram.?;
        try std.testing.expectEqual(@as(usize, 1), datagram.frames.len);
        const payload = datagram.frames[0].datagram.data;
        if (std.mem.eql(u8, payload, "a")) saw_a = true;
        if (std.mem.eql(u8, payload, "b")) saw_b = true;
    }
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
}

test "QUIC UDP endpoint routes protected short datagrams by DCID" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer server.deinit();

    var client_a = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client_a.deinit();
    var client_b = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client_b.deinit();

    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register("conn-a", .{ .connection_index = 10, .sequence_number = 1 });
    try router.register("conn-b", .{ .connection_index = 11, .sequence_number = 2 });

    const keys = quic.protection.deriveAes128Keys([_]u8{0x5a} ** quic.protection.secret_len);
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try (quic.Frame{ .ping = {} }).write(&payload, allocator);

    const packet_a = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "conn-a",
        .packet_number = 0,
        .payload = payload.items,
    });
    defer allocator.free(packet_a);
    const packet_b = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "conn-b",
        .packet_number = 0,
        .payload = payload.items,
    });
    defer allocator.free(packet_b);

    try client_a.endpoint.sendBytes(server.address(), packet_a);
    try client_b.endpoint.sendBytes(server.address(), packet_b);

    var first = try server.endpoint.receiveRoutedBytes(router);
    defer first.deinit(allocator);
    var second = try server.endpoint.receiveRoutedBytes(router);
    defer second.deinit(allocator);

    const first_idx = first.route.connection_index;
    const second_idx = second.route.connection_index;
    try std.testing.expect((first_idx == 10 and second_idx == 11) or (first_idx == 11 and second_idx == 10));
    if (first_idx == 10) {
        try std.testing.expectEqualStrings("conn-a", first.destination_connection_id);
        try std.testing.expectEqualStrings("conn-b", second.destination_connection_id);
    } else {
        try std.testing.expectEqualStrings("conn-b", first.destination_connection_id);
        try std.testing.expectEqualStrings("conn-a", second.destination_connection_id);
    }
}
