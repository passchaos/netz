const std = @import("std");
const socks5 = @import("../socks5.zig");

const net = std.Io.net;

test "SOCKS5 UDP association relays domains and owns control lifetime" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const relay_address = net.IpAddress{ .ip4 = .loopback(0) };
    const relay = try relay_address.bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer relay.close(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        relay: net.Socket,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const control = try self.listener.accept(self.io);
            defer control.close(self.io);

            var greeting: [3]u8 = undefined;
            try readExact(self.io, control, &greeting);
            try std.testing.expectEqualSlices(u8, &.{ 5, 1, 0 }, &greeting);
            try writeAll(self.io, control, &.{ 5, 0 });

            var request: [10]u8 = undefined;
            try readExact(self.io, control, &request);
            try std.testing.expectEqualSlices(
                u8,
                &.{ 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 },
                &request,
            );
            const relay_port = self.relay.address.getPort();
            var reply = [_]u8{ 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 };
            std.mem.writeInt(u16, reply[8..10], relay_port, .big);
            try writeAll(self.io, control, &reply);

            var request_storage: [256]u8 = undefined;
            const message = try self.relay.receiveTimeout(
                self.io,
                &request_storage,
                awakeTimeout(.fromSeconds(2)),
            );
            const datagram = try socks5.udp.decodeDatagram(message.data);
            try std.testing.expectEqualStrings("origin.example", datagram.source.domain.host);
            try std.testing.expectEqual(@as(u16, 443), datagram.source.domain.port);
            try std.testing.expectEqualStrings("client payload", datagram.payload);

            var response_storage: [256]u8 = undefined;
            const response = try socks5.udp.encodeDatagram(
                &response_storage,
                .{ .ip = try net.IpAddress.parse("203.0.113.9", 443) },
                "relay payload",
            );
            try self.relay.send(self.io, &message.from, response);

            var eof: [1]u8 = undefined;
            try std.testing.expectEqual(
                @as(usize, 0),
                try readSome(self.io, control, &eof),
            );
        }
    };
    var shared = Shared{
        .io = io,
        .listener = &listener,
        .relay = relay,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var association = try socks5.associateUdpHost(
        allocator,
        io,
        "127.0.0.1",
        listener.socket.address.getPort(),
        .{ .socks5 = .{ .connect_timeout = .fromSeconds(2) } },
    );
    var closed = false;
    defer if (!closed) association.deinit();
    try std.testing.expect(association.relayAddress().eql(&relay.address));

    const attacker_address = net.IpAddress{ .ip4 = .loopback(0) };
    const attacker = try attacker_address.bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer attacker.close(io);
    var forged_storage: [64]u8 = undefined;
    const forged = try socks5.udp.encodeDatagram(
        &forged_storage,
        .{ .ip = try net.IpAddress.parse("198.51.100.1", 53) },
        "forged",
    );
    const association_address = association.address();
    try attacker.send(io, &association_address, forged);
    var receive_storage: [256]u8 = undefined;
    try std.testing.expectError(
        error.UnexpectedRelaySource,
        association.receiveIntoTimeout(
            &receive_storage,
            awakeTimeout(.fromSeconds(2)),
        ),
    );

    var send_storage: [256]u8 = undefined;
    try association.sendTo(
        try .fromHost("origin.example", 443),
        "client payload",
        &send_storage,
    );
    const received = try association.receiveIntoTimeout(
        &receive_storage,
        awakeTimeout(.fromSeconds(2)),
    );
    const expected_source = try net.IpAddress.parse("203.0.113.9", 443);
    try std.testing.expect(received.source.ip.eql(&expected_source));
    try std.testing.expectEqualStrings("relay payload", received.payload);

    association.deinit();
    closed = true;
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (count == 0) return error.EndOfStream;
        written += count;
    }
}

fn readExact(io: std.Io, stream: net.Stream, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try readSome(io, stream, output[offset..]);
        if (count == 0) return error.EndOfStream;
        offset += count;
    }
}

fn readSome(io: std.Io, stream: net.Stream, output: []u8) !usize {
    var parts = [_][]u8{output};
    return io.vtable.netRead(io.userdata, stream.socket.handle, &parts);
}

fn awakeTimeout(duration: std.Io.Duration) std.Io.Timeout {
    return .{ .duration = .{ .raw = duration, .clock = .awake } };
}
