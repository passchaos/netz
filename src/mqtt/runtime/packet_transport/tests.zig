const std = @import("std");
const packet_transport_root = @import("../packet_transport.zig");

const mqtt = @import("../../mod.zig");
const net = std.Io.net;

const Error = packet_transport_root.Error;
const StreamPacketReader = packet_transport_root.StreamPacketReader;
const StreamPacketState = packet_transport_root.StreamPacketState;
const TcpTransport = packet_transport_root.TcpTransport;
const Transport = packet_transport_root.Transport;
const WebSocketTransport = packet_transport_root.WebSocketTransport;
const discardPacketPrefix = packet_transport_root.discardPacketPrefix;
const parsePacketFraming = packet_transport_root.parsePacketFraming;
const readTcpPacket = packet_transport_root.readTcpPacket;
const tcp_read_ahead_capacity = packet_transport_root.tcp_read_ahead_capacity;
const websocket_runtime = packet_transport_root.websocket_runtime;
const writeAll = packet_transport_root.writeAll;

test "MQTT TLS packet cursor retains every accepted byte across local interruptions" {
    try @import("../transport/stream_receive_tests.zig").cursor(StreamPacketReader, StreamPacketState, Error);
}

test "MQTT packet transport keeps WebSocket state out of line" {
    try std.testing.expect(
        @sizeOf(Transport) < @sizeOf(WebSocketTransport),
    );
}

test "MQTT WebSocket transport allocation failure closes its stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);
    const server = try listener.accept(io);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        Transport.initWebSocket(
            failing.allocator(),
            websocket_runtime.testing.initDirectConnection(
                allocator,
                io,
                server,
                .server,
                .{},
            ),
        ),
    );
    var byte: [1]u8 = undefined;
    var buffers = [_][]u8{&byte};
    try std.testing.expectEqual(
        @as(usize, 0),
        try io.vtable.netRead(
            io.userdata,
            client.socket.handle,
            &buffers,
        ),
    );
}

test "TLS record-boundary EOF is an MQTT connection close" {
    const FakeConnection = struct {
        io: std.Io,
        failure: Error,

        pub fn read(self: *@This(), _: []u8) Error!usize {
            return self.failure;
        }

        pub fn readWithDeadline(
            self: *@This(),
            _: []u8,
            _: std.Io.Clock.Timestamp,
        ) Error!usize {
            return self.failure;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var byte: [1]u8 = undefined;

    var eof = FakeConnection{
        .io = io,
        .failure = error.UnexpectedEof,
    };
    try std.testing.expectError(
        error.ConnectionClosed,
        StreamPacketReader.readSome(&eof, &byte, null),
    );

    var truncated = FakeConnection{
        .io = io,
        .failure = error.TruncatedRecord,
    };
    try std.testing.expectError(
        error.TruncatedRecord,
        StreamPacketReader.readSome(&truncated, &byte, null),
    );
}

test "packet framing waits for a complete MQTT remaining length" {
    try std.testing.expect((try parsePacketFraming(&.{})) == null);
    try std.testing.expect((try parsePacketFraming(&.{0x30})) == null);
    try std.testing.expect((try parsePacketFraming(&.{ 0x30, 0x80 })) == null);

    const ping = (try parsePacketFraming(&.{ 0xc0, 0x00 })).?;
    try std.testing.expectEqual(@as(usize, 2), ping.packet_len);
    try std.testing.expectEqual(mqtt.PacketType.pingreq, ping.fixed.packet_type);
    try std.testing.expectEqual(@as(u4, 0), ping.fixed.flags);
    try std.testing.expectEqual(@as(usize, 0), ping.fixed.remaining_len);
    try std.testing.expectEqual(@as(usize, 2), ping.fixed.header_len);

    const publish = (try parsePacketFraming(&.{ 0x3d, 0x82, 0x01 })).?;
    try std.testing.expectEqual(@as(usize, 133), publish.packet_len);
    try std.testing.expectEqual(mqtt.PacketType.publish, publish.fixed.packet_type);
    try std.testing.expectEqual(@as(u4, 0x0d), publish.fixed.flags);
    try std.testing.expectEqual(@as(usize, 130), publish.fixed.remaining_len);
    try std.testing.expectEqual(@as(usize, 3), publish.fixed.header_len);
}

test "packet prefix discard retains following packet bytes" {
    const allocator = std.testing.allocator;
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(allocator);
    try input.appendSlice(
        allocator,
        &.{ 0xc0, 0x00, 0xd0, 0x00 },
    );

    discardPacketPrefix(&input, 2);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xd0, 0x00 },
        input.items,
    );
    discardPacketPrefix(&input, 2);
    try std.testing.expectEqual(@as(usize, 0), input.items.len);
}

test "packet length rejects reserved type before malformed length" {
    try std.testing.expectError(
        error.ReservedPacketType,
        parsePacketFraming(&.{ 0x00, 0x80, 0x80, 0x80, 0x80 }),
    );
}

test "TCP packet receive allocates the owned packet exactly once" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer sender.close(io);
    const receiver = try listener.accept(io);
    defer receiver.close(io);

    var wire_bytes: [1027]u8 = @splat(0x5a);
    wire_bytes[0] = 0x30;
    wire_bytes[1] = 0x80;
    wire_bytes[2] = 0x08;
    try writeAll(io, sender, &wire_bytes);

    // Allow exactly the allocation that owns the returned packet. The former
    // incremental ArrayList path needed additional allocation/remap activity
    // while collecting the five-byte fixed header.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1, .resize_fail_index = 0 },
    );
    var transport = Transport.initTcp(io, receiver);
    var packet = try transport.readPacket(
        failing.allocator(),
        wire_bytes.len,
    );
    defer packet.deinit(failing.allocator());
    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expectEqual(@as(usize, 0), failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqualSlices(u8, &wire_bytes, packet.bytes);
    try std.testing.expectEqual(@as(usize, 1024), packet.fixed.remaining_len);
    try std.testing.expectEqual(@as(usize, 3), packet.fixed.header_len);
}

test "TCP packet receive resumes after a split initial header timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer sender.close(io);
    const receiver = try listener.accept(io);
    var transport = Transport.initTcp(io, receiver);
    defer transport.close(allocator);

    try writeAll(io, sender, &.{0xc0});
    try std.testing.expectError(
        error.Timeout,
        transport.readPacketWithDeadline(
            allocator,
            mqtt.ping_packet_len,
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), transport.tcp.buffered().len);

    try writeAll(io, sender, &.{0x00});
    var packet = try transport.readPacketWithDeadline(
        allocator,
        mqtt.ping_packet_len,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    defer packet.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00 }, packet.bytes);
}

test "TCP externally managed inactivity renews for large packet progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer sender.close(io);
    const receiver = try listener.accept(io);
    var transport = Transport.initTcp(io, receiver);
    defer transport.close(allocator);

    var encoded: [1500]u8 = @splat(0x5a);
    encoded[0] = 0x30;
    const remaining_len = encoded.len - 3;
    encoded[1] = @as(u8, @truncate(remaining_len)) | 0x80;
    encoded[2] = @intCast(remaining_len >> 7);
    try writeAll(io, sender, &encoded);

    const Counter = struct {
        value: usize = 0,

        fn renew(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.value += 1;
        }
    };
    var counter: Counter = .{};
    var storage: [128]u8 = undefined;
    var packet = try transport
        .readPacketWithInactivityObserverIntoWithPrefix(
        allocator,
        encoded.len,
        .{ .context = &counter, .renew_fn = Counter.renew },
        &storage,
        32,
    );
    defer packet.deinit(allocator);
    try std.testing.expect(counter.value != 0);
    try std.testing.expectEqualSlices(u8, &encoded, packet.bytes);
}

test "TCP packet receive retains a coalesced following packet" {
    const allocator = std.testing.allocator;
    var tcp = TcpTransport{
        .io = undefined,
        .stream = undefined,
    };
    const coalesced = [4]u8{ 0xc0, 0x00, 0xc0, 0x00 };
    @memcpy(tcp.input[0..coalesced.len], &coalesced);
    tcp.input_end = 4;

    var first = try readTcpPacket(
        allocator,
        &tcp,
        mqtt.ping_packet_len,
    );
    defer first.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00 }, first.bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00 }, tcp.buffered());

    var second = try readTcpPacket(
        allocator,
        &tcp,
        mqtt.ping_packet_len,
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00 }, second.bytes);
    try std.testing.expectEqual(@as(usize, 0), tcp.buffered().len);
}

test "TCP packet receive borrows caller storage for complete read-ahead packets" {
    const allocator = std.testing.allocator;
    var transport = Transport{ .tcp = .{
        .io = undefined,
        .stream = undefined,
    } };
    const encoded = [4]u8{ 0x40, 0x02, 0x00, 0x07 };
    @memcpy(transport.tcp.input[0..encoded.len], &encoded);
    transport.tcp.input_end = encoded.len;
    var storage: [4]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    var packet = try transport.readPacketInto(
        failing.allocator(),
        storage.len,
        &storage,
    );
    try std.testing.expect(!packet.owns_bytes);
    try std.testing.expectEqual(storage[0..].ptr, packet.bytes.ptr);
    try std.testing.expectEqualSlices(u8, &encoded, packet.bytes);
    try std.testing.expectEqual(@as(usize, 0), transport.tcp.buffered().len);
    packet.deinit(failing.allocator());
    try std.testing.expect(!failing.has_induced_failure);
}

test "TCP packet receive borrows an exact read-ahead-capacity packet" {
    const allocator = std.testing.allocator;
    var transport = Transport{ .tcp = .{
        .io = undefined,
        .stream = undefined,
    } };
    var encoded: [tcp_read_ahead_capacity]u8 = @splat(0x5a);
    encoded[0] = 0x30;
    const remaining_len = encoded.len - 3;
    encoded[1] = @as(u8, @truncate(remaining_len)) | 0x80;
    encoded[2] = @intCast(remaining_len >> 7);
    @memcpy(transport.tcp.input[0..], &encoded);
    transport.tcp.input_end = encoded.len;
    var storage: [tcp_read_ahead_capacity]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    var packet = try transport.readPacketInto(
        failing.allocator(),
        encoded.len,
        &storage,
    );
    defer packet.deinit(failing.allocator());
    try std.testing.expect(!packet.owns_bytes);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqualSlices(u8, &encoded, packet.bytes);
    try std.testing.expectEqual(
        @as(usize, 0),
        transport.tcp.buffered().len,
    );
}

test "TCP packet receive preserves an aligned prefix on owned fallback" {
    const allocator = std.testing.allocator;
    var transport = Transport{ .tcp = .{
        .io = undefined,
        .stream = undefined,
    } };
    var encoded: [131]u8 = @splat(0x5a);
    encoded[0] = 0x30;
    encoded[1] = 0x80;
    encoded[2] = 0x01;
    @memcpy(transport.tcp.input[0..encoded.len], &encoded);
    transport.tcp.input_end = encoded.len;
    var storage: [4]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1 },
    );
    const prefix_len = 128;

    var packet = try transport.readPacketIntoWithPrefix(
        failing.allocator(),
        encoded.len,
        &storage,
        prefix_len,
    );
    defer packet.deinit(failing.allocator());

    const allocation = packet.prefixedAllocation().?;
    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(
        @intFromPtr(allocation.ptr) + prefix_len,
        @intFromPtr(packet.bytes.ptr),
    );
    try std.testing.expectEqualSlices(u8, &encoded, packet.bytes);
    try std.testing.expectEqual(@as(usize, 0), transport.tcp.buffered().len);
}

test "TCP prefixed packet allocation survives timeout and resume" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer sender.close(io);
    const receiver = try listener.accept(io);
    var transport = Transport.initTcp(io, receiver);
    defer transport.close(allocator);

    var encoded: [131]u8 = @splat(0x5a);
    encoded[0] = 0x30;
    encoded[1] = 0x80;
    encoded[2] = 0x01;
    var storage: [4]u8 = undefined;
    const prefix_len = 128;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1 },
    );

    try writeAll(io, sender, encoded[0..7]);
    try std.testing.expectError(
        error.Timeout,
        transport.readPacketWithInactivityTimeoutIntoWithPrefix(
            failing.allocator(),
            encoded.len,
            .{ .raw = .fromMilliseconds(20), .clock = .awake },
            &storage,
            prefix_len,
        ),
    );
    try std.testing.expectEqual(
        @as(u16, prefix_len),
        transport.tcp.packet_prefix_len,
    );
    try std.testing.expectEqual(@as(usize, 1), failing.allocations);

    try writeAll(io, sender, encoded[7..]);
    var packet = try transport
        .readPacketWithInactivityTimeoutIntoWithPrefix(
        failing.allocator(),
        encoded.len,
        .{ .raw = .fromSeconds(1), .clock = .awake },
        &storage,
        prefix_len,
    );
    defer packet.deinit(failing.allocator());

    try std.testing.expect(packet.prefixedAllocation() != null);
    try std.testing.expectEqualSlices(u8, &encoded, packet.bytes);
    try std.testing.expect(!failing.has_induced_failure);
}

test "TCP packet receive resumes a fragmented caller-storage packet without allocation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer sender.close(io);
    const receiver = try listener.accept(io);
    var transport = Transport.initTcp(io, receiver);
    defer transport.close(allocator);
    var storage: [4]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    try writeAll(io, sender, &.{ 0x40, 0x02, 0x00 });
    try std.testing.expectError(
        error.Timeout,
        transport.readPacketWithInactivityTimeoutInto(
            failing.allocator(),
            storage.len,
            .{ .raw = .fromMilliseconds(20), .clock = .awake },
            &storage,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x40, 0x02, 0x00 },
        transport.tcp.buffered(),
    );
    try std.testing.expect(!failing.has_induced_failure);

    try writeAll(io, sender, &.{0x07});
    var packet = try transport.readPacketWithInactivityTimeoutInto(
        failing.allocator(),
        storage.len,
        .{ .raw = .fromSeconds(1), .clock = .awake },
        &storage,
    );
    defer packet.deinit(failing.allocator());
    try std.testing.expect(!packet.owns_bytes);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x40, 0x02, 0x00, 0x07 },
        packet.bytes,
    );
    try std.testing.expectEqual(@as(usize, 0), transport.tcp.buffered().len);
    try std.testing.expect(!failing.has_induced_failure);
}

test "TCP packet allocation failure retains read-ahead bytes" {
    const allocator = std.testing.allocator;
    var transport = Transport{ .tcp = .{
        .io = undefined,
        .stream = undefined,
    } };
    const encoded = [2]u8{ 0xc0, 0x00 };
    @memcpy(transport.tcp.input[0..encoded.len], &encoded);
    transport.tcp.input_end = 2;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var insufficient_storage: [1]u8 = undefined;

    try std.testing.expectError(
        error.OutOfMemory,
        transport.readPacketInto(
            failing.allocator(),
            mqtt.ping_packet_len,
            &insufficient_storage,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xc0, 0x00 },
        transport.tcp.buffered(),
    );

    var packet = try transport.readPacket(
        allocator,
        mqtt.ping_packet_len,
    );
    defer packet.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00 }, packet.bytes);
    try std.testing.expectEqual(
        @as(usize, 0),
        transport.tcp.buffered().len,
    );
}

test "TCP packet receive rejects oversize before allocating" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer sender.close(io);
    const receiver = try listener.accept(io);
    defer receiver.close(io);

    // Only the three-byte header is needed to prove that the complete packet
    // exceeds the configured limit; its body deliberately never arrives.
    try writeAll(io, sender, &.{ 0x30, 0x82, 0x01 });
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var transport = Transport.initTcp(io, receiver);
    try std.testing.expectError(
        error.PacketTooLarge,
        transport.readPacket(fail_first.allocator(), 132),
    );
    try std.testing.expect(!fail_first.has_induced_failure);
}
