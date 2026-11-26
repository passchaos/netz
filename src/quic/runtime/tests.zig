const std = @import("std");
const quic_runtime_root = @import("../runtime.zig");
const net = std.Io.net;
const quic = @import("../mod.zig");

const AcceptFirstBatchDatagram = quic_runtime_root.AcceptFirstBatchDatagram;
const AddressedDatagram = quic_runtime_root.AddressedDatagram;
const Client = quic_runtime_root.Client;
const DatagramSource = quic_runtime_root.DatagramSource;
const EcnCmsgHdr = quic_runtime_root.EcnCmsgHdr;
const Endpoint = quic_runtime_root.Endpoint;
const OwnedBytes = quic_runtime_root.OwnedBytes;
const OwnedDatagramBatch = quic_runtime_root.OwnedDatagramBatch;
const ObservedBatchSend = @import("../one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;
const ReceivedBytesView = quic_runtime_root.ReceivedBytesView;
const RejectFirstGsoSend = quic_runtime_root.RejectFirstGsoSend;
const RejectMessageOversizeReceives = quic_runtime_root.RejectMessageOversizeReceives;
const Server = quic_runtime_root.Server;
const SocketTrafficCounters = quic_runtime_root.SocketTrafficCounters;
const SocketTrafficStats = quic_runtime_root.SocketTrafficStats;
const cmsgSpace = quic_runtime_root.cmsgSpace;
const ecnCodepointBits = quic_runtime_root.ecnCodepointBits;
const emptyIncomingFlags = quic_runtime_root.emptyIncomingFlags;
const encodeUdpGsoControl = quic_runtime_root.encodeUdpGsoControl;
const gsoPlan = quic_runtime_root.gsoPlan;
const ip_tos_cmsg_type = quic_runtime_root.ip_tos_cmsg_type;
const ipproto_ip = quic_runtime_root.ipproto_ip;
const max_gro_receive_bytes = quic_runtime_root.max_gro_receive_bytes;
const peekUnsupportedVersionConnectionIds = quic_runtime_root.peekUnsupportedVersionConnectionIds;
const receiveControlFromBytes = quic_runtime_root.receiveControlFromBytes;
const receive_control_buffer_len = quic_runtime_root.receive_control_buffer_len;
const socketEcnSupported = quic_runtime_root.socketEcnSupported;
const testing = quic_runtime_root.testing;
const udpGroSupported = quic_runtime_root.udpGroSupported;
const udpGsoSupported = quic_runtime_root.udpGsoSupported;
const udp_gro_segment = quic_runtime_root.udp_gro_segment;
const udp_gso_control_len = quic_runtime_root.udp_gso_control_len;
const udp_gso_level = quic_runtime_root.udp_gso_level;
const udp_gso_segment = quic_runtime_root.udp_gso_segment;

test "QUIC parsed datagram receive honors timeout and deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        server.receiveWithTimeout(.{ .duration = .{
            .raw = .fromMilliseconds(20),
            .clock = .awake,
        } }),
    );

    try client.sendFrames(&.{.{ .ping = {} }});
    var datagram = try server.receiveWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer datagram.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), datagram.frames.len);
    try std.testing.expect(datagram.frames[0] == .ping);
}

test "QUIC raw endpoint deadline receives validate and deliver" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer sender.deinit();
    const invalid: std.Io.Clock.Timestamp = .{
        .clock = .real,
        .raw = .zero,
    };
    var buffer: [16]u8 = undefined;
    var batch_buffer: [max_gro_receive_bytes]u8 = undefined;

    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesIntoWithDeadline(&buffer, invalid),
    );
    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesWithDeadline(invalid),
    );
    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesBatchWithDeadline(invalid),
    );
    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesBatchIntoWithDeadline(
            &batch_buffer,
            invalid,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        DatagramSource.fromEndpoint(&receiver).receiveWithDeadline(invalid),
    );
    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesIntoWithTimeout(&buffer, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesBatchWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesBatchIntoWithTimeout(
            &batch_buffer,
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        DatagramSource.fromEndpoint(&receiver).receiveWithTimeout(.zero),
    );

    try sender.sendBytes(receiver.address(), "caller-buffer");
    const view = try receiver.receiveBytesIntoWithDeadline(
        &buffer,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expectEqualStrings("caller-buffer", view.bytes);
    try std.testing.expectEqual(&receiver, view.received_on.?);

    try sender.sendBytes(receiver.address(), "owned");
    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesWithDeadline(.fromNow(io, .{
            .clock = .awake,
            .raw = .zero,
        })),
    );
    // Deadline validation precedes the socket read, so an expired attempt
    // cannot consume a datagram that a later call still owns.
    var owned = try DatagramSource.fromEndpoint(&receiver)
        .receiveWithDeadline(.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(1),
    }));
    defer owned.deinit(allocator);
    try std.testing.expectEqualStrings("owned", owned.bytes);
    try std.testing.expectEqual(&receiver, owned.received_on.?);

    try sender.sendBytes(receiver.address(), "batch");
    var batch = try receiver.receiveBytesBatchWithDeadline(.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(1),
    }));
    defer batch.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), batch.segment_count);
    try std.testing.expectEqualStrings(
        "batch",
        batch.datagramAt(0).?,
    );
    try std.testing.expectEqual(&receiver, batch.received_on.?);

    try sender.sendBytes(receiver.address(), "batch-into");
    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesBatchIntoWithDeadline(
            &batch_buffer,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .zero,
            }),
        ),
    );
    const batch_view = try receiver.receiveBytesBatchIntoWithDeadline(
        &batch_buffer,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expectEqual(@as(usize, 1), batch_view.segment_count);
    try std.testing.expectEqualStrings(
        "batch-into",
        batch_view.datagramAt(0).?,
    );
    try std.testing.expectEqual(&receiver, batch_view.received_on.?);
}

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

test "QUIC UDP endpoint round-trips ECN marks" {
    if (!socketEcnSupported()) return error.SkipZigTest;

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
    if (!server.endpoint.receive_ecn_enabled) return error.SkipZigTest;

    client.endpoint.sendBytesWithEcn(server.address(), "ect0", .ect0) catch |err| switch (err) {
        error.EcnUnavailable => return error.SkipZigTest,
        else => return err,
    };
    var ect0 = try server.endpoint.receiveBytesWithEcn();
    defer ect0.deinit(allocator);
    try std.testing.expectEqual(quic.packet_space.EcnCodepoint.ect0, ect0.ecn);
    try std.testing.expectEqualSlices(u8, "ect0", ect0.bytes);

    try client.endpoint.sendBytesWithEcn(server.address(), "ect1", .ect1);
    var ect1 = try server.endpoint.receiveBytesWithEcn();
    defer ect1.deinit(allocator);
    try std.testing.expectEqual(quic.packet_space.EcnCodepoint.ect1, ect1.ecn);
    try std.testing.expectEqualSlices(u8, "ect1", ect1.bytes);

    try client.endpoint.sendBytesWithEcn(server.address(), "ce", .ce);
    var ce = try server.endpoint.receiveBytesWithEcn();
    defer ce.deinit(allocator);
    try std.testing.expectEqual(quic.packet_space.EcnCodepoint.ce, ce.ecn);
    try std.testing.expectEqualSlices(u8, "ce", ce.bytes);

    // A normal send after ECT traffic must clear the cached TOS/TCLASS mark so
    // callers that are not probing ECN do not accidentally keep marking packets.
    try client.endpoint.sendBytes(server.address(), "plain");
    var plain = try server.endpoint.receiveBytesWithEcn();
    defer plain.deinit(allocator);
    try std.testing.expectEqual(quic.packet_space.EcnCodepoint.not_ect, plain.ecn);
    try std.testing.expectEqualSlices(u8, "plain", plain.bytes);
}

test "QUIC UDP endpoint builds Version Negotiation for unsupported versions" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();

    const supported_versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    const datagram = [_]u8{
        0xc0,
        0xfa,
        0xce,
        0xb0,
        0x0c,
        0x02,
        0xaa,
        0xbb,
        0x03,
        0x11,
        0x22,
        0x33,
        0x00,
    };

    const response = (try endpoint.versionNegotiationResponse(&datagram, &supported_versions)) orelse return error.TestUnexpectedResult;
    defer allocator.free(response);

    var parsed = try quic.parseVersionNegotiationPacket(allocator, response);
    defer parsed.deinit(allocator);
    try std.testing.expect((parsed.first_byte & 0x80) != 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33 }, parsed.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb }, parsed.source_connection_id);
    try std.testing.expectEqualSlices(u32, &supported_versions, parsed.versions);

    const ids = peekUnsupportedVersionConnectionIds(
        &datagram,
        &supported_versions,
    ).?;
    const direct_options: quic.VersionNegotiationPacketOptions = .{
        .first_byte = 0x80,
        .destination_connection_id = ids.source_connection_id,
        .source_connection_id = ids.destination_connection_id,
        .versions = &supported_versions,
    };
    var direct_storage: [64]u8 = undefined;
    const direct = try quic.writeVersionNegotiationPacketInto(
        &direct_storage,
        direct_options,
    );
    var direct_parsed = try quic.parseVersionNegotiationPacket(
        allocator,
        direct,
    );
    defer direct_parsed.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x11, 0x22, 0x33 },
        direct_parsed.destination_connection_id,
    );
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xaa, 0xbb },
        direct_parsed.source_connection_id,
    );
    try std.testing.expectEqualSlices(
        u32,
        &supported_versions,
        direct_parsed.versions,
    );

    const supported_with_grease = [_]u32{
        quic.Version.version_1.wireValue(),
        0x0a0a0a0a,
    };
    var reserved_trigger = datagram;
    std.mem.writeInt(u32, reserved_trigger[1..5], 0x0a0a0a0a, .big);
    const greased_response = (try endpoint.versionNegotiationResponse(&reserved_trigger, &supported_with_grease)) orelse return error.TestUnexpectedResult;
    defer allocator.free(greased_response);

    var parsed_greased = try quic.parseVersionNegotiationPacket(allocator, greased_response);
    defer parsed_greased.deinit(allocator);
    try std.testing.expectEqualSlices(u32, &supported_with_grease, parsed_greased.versions);
}

test "QUIC UDP endpoint ignores non-triggering Version Negotiation inputs" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();

    const supported_versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    const supported = [_]u8{
        0xc0,
        0x00,
        0x00,
        0x00,
        0x01,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0x00,
    };
    const version_negotiation = [_]u8{
        0xc0,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0x00,
        0x00,
        0x00,
        0x01,
    };
    const fixed_bit_clear = [_]u8{
        0x80,
        0xfa,
        0xce,
        0xb0,
        0x0c,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0x00,
    };
    const short_header = [_]u8{ 0x40, 0xaa, 0xbb };
    const truncated = [_]u8{ 0xc0, 0xfa, 0xce, 0xb0, 0x0c, 0x04, 0xaa };
    const too_long_cid = [_]u8{
        0xc0,
        0xfa,
        0xce,
        0xb0,
        0x0c,
        21,
    } ++ ([_]u8{0xaa} ** 21);

    try std.testing.expect((try endpoint.versionNegotiationResponse(&supported, &supported_versions)) == null);
    try std.testing.expect((try endpoint.versionNegotiationResponse(&version_negotiation, &supported_versions)) == null);
    try std.testing.expect((try endpoint.versionNegotiationResponse(&fixed_bit_clear, &supported_versions)) == null);
    try std.testing.expect((try endpoint.versionNegotiationResponse(&short_header, &supported_versions)) == null);
    try std.testing.expect((try endpoint.versionNegotiationResponse(&truncated, &supported_versions)) == null);
    try std.testing.expect((try endpoint.versionNegotiationResponse(&too_long_cid, &supported_versions)) == null);

    try std.testing.expectError(error.InvalidVersionNegotiation, endpoint.versionNegotiationResponse(&supported, &.{}));
    try std.testing.expectError(error.InvalidVersionNegotiation, endpoint.versionNegotiationResponse(
        &supported,
        &.{quic.Version.negotiation.wireValue()},
    ));
    try std.testing.expectError(error.InvalidVersionNegotiation, endpoint.versionNegotiationResponse(
        &supported,
        &.{0x0a0a0a0a},
    ));
}

test "QUIC UDP endpoint sends Version Negotiation before returning next datagram" {
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

    const supported_versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    const unsupported = [_]u8{
        0xc0,
        0xfa,
        0xce,
        0xb0,
        0x0c,
        0x03,
        's',
        'r',
        'v',
        0x03,
        'c',
        'l',
        'i',
        0x00,
    };
    const supported = [_]u8{
        0xc0,
        0x00,
        0x00,
        0x00,
        0x01,
        0x03,
        's',
        'r',
        'v',
        0x03,
        'c',
        'l',
        'i',
        0x00,
    };

    const Shared = struct {
        endpoint: *Endpoint,
        supported_versions: []const u32,
        received: ?OwnedBytes = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.received = shared.endpoint.receiveBytesHandlingVersionNegotiation(shared.supported_versions) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{
        .endpoint = &server.endpoint,
        .supported_versions = &supported_versions,
    };
    const receiver = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try client.endpoint.sendBytes(server.address(), &unsupported);
    var response = try client.endpoint.receiveBytes();
    defer response.deinit(allocator);
    try std.testing.expect(response.from.eql(&server.address()));

    var parsed = try quic.parseVersionNegotiationPacket(allocator, response.bytes);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, "cli", parsed.destination_connection_id);
    try std.testing.expectEqualSlices(u8, "srv", parsed.source_connection_id);
    try std.testing.expectEqualSlices(u32, &supported_versions, parsed.versions);

    try client.endpoint.sendBytes(server.address(), &supported);
    receiver.join();
    if (shared.err) |err| return err;
    var accepted = shared.received.?;
    defer accepted.deinit(allocator);
    try std.testing.expect(accepted.from.eql(&client.address()));
    try std.testing.expectEqualSlices(u8, &supported, accepted.bytes);
}

test "QUIC Version Negotiation receive keeps one absolute deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
    );
    defer client.deinit();

    const supported_versions = [_]u32{
        quic.Version.version_1.wireValue(),
    };
    const unsupported = [_]u8{
        0xc0, 0xfa, 0xce, 0xb0, 0x0c,
        3,    's',  'r',  'v',  3,
        'c',  'l',  'i',  0,
    };
    try client.endpoint.sendBytes(server.address(), &unsupported);
    try std.testing.expectError(
        error.Timeout,
        server.receiveBytesHandlingVersionNegotiationWithDeadline(
            &supported_versions,
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );

    var response = try client.endpoint.receiveBytesTimeout(.{
        .duration = .{ .raw = .fromSeconds(1), .clock = .awake },
    });
    defer response.deinit(allocator);
    var parsed = try quic.parseVersionNegotiationPacket(
        allocator,
        response.bytes,
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqualSlices(
        u32,
        &supported_versions,
        parsed.versions,
    );

    const supported = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x03, 's',  'r',  'v',  0x03,
        'c',  'l',  'i',  0x00,
    };
    try client.endpoint.sendBytes(server.address(), &supported);
    var accepted = try server
        .receiveBytesHandlingVersionNegotiationWithTimeout(
        &supported_versions,
        .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } },
    );
    defer accepted.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &supported, accepted.bytes);
}

test "QUIC UDP endpoint sends common Version Negotiation without allocation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
    );
    defer client.deinit();

    const unsupported = [_]u8{
        0xc0, 0xfa, 0xce, 0xb0, 0x0c,
        3,    's',  'r',  'v',  3,
        'c',  'l',  'i',  0,
    };
    const supported_versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const original_allocator = server.endpoint.allocator;
    server.endpoint.allocator = fail_first.allocator();
    defer server.endpoint.allocator = original_allocator;
    try std.testing.expect(try server.endpoint.sendVersionNegotiationIfUnsupported(
        client.address(),
        &unsupported,
        &supported_versions,
    ));
    try std.testing.expect(!fail_first.has_induced_failure);

    var response = try client.endpoint.receiveBytes();
    defer response.deinit(allocator);
    var parsed = try quic.parseVersionNegotiationPacket(
        allocator,
        response.bytes,
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, "cli", parsed.destination_connection_id);
    try std.testing.expectEqualSlices(u8, "srv", parsed.source_connection_id);
    try std.testing.expectEqualSlices(u32, &supported_versions, parsed.versions);
}

test "QUIC UDP endpoint sends bounded stateless reset without allocation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
    );
    defer client.deinit();

    const reset_key = [_]u8{0x42} ** quic.stateless_reset.static_key_len;
    const retired_cid = "retired-cid";
    const expected_token = quic.stateless_reset.tokenForConnectionId(
        reset_key,
        retired_cid,
    );
    const trigger = [_]u8{0x40} ** 64;
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const original_allocator = server.endpoint.allocator;
    server.endpoint.allocator = fail_first.allocator();
    defer server.endpoint.allocator = original_allocator;
    try std.testing.expect(try server.endpoint.sendStatelessResetForConnectionId(
        client.address(),
        &trigger,
        reset_key,
        retired_cid,
    ));
    try std.testing.expect(!fail_first.has_induced_failure);

    var response = try client.endpoint.receiveBytes();
    defer response.deinit(allocator);
    try std.testing.expectEqual(trigger.len - 1, response.bytes.len);
    try std.testing.expect(response.bytes.len < trigger.len);
    try std.testing.expect(quic.stateless_reset.matches(
        response.bytes,
        expected_token,
    ));
    try std.testing.expect(!try server.endpoint.sendStatelessResetForConnectionId(
        client.address(),
        &([_]u8{0x40} ** quic.stateless_reset.min_datagram_len),
        reset_key,
        retired_cid,
    ));
    try std.testing.expectError(
        error.InvalidConnectionId,
        server.endpoint.sendStatelessResetForConnectionId(
            client.address(),
            &trigger,
            reset_key,
            &.{},
        ),
    );
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

test "QUIC UDP endpoint sends many datagrams in one batch" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer receiver.deinit();
    var sender = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer sender.deinit();

    const datagrams = [_][]const u8{ "first", "second", "third" };
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    sender.allocator = no_alloc.allocator();
    try sender.sendManyBytes(receiver.address(), &datagrams);
    try std.testing.expect(!no_alloc.has_induced_failure);
    for (datagrams) |expected| {
        var received = try receiver.receiveBytes();
        defer received.deinit(allocator);
        try std.testing.expectEqualStrings(expected, received.bytes);
    }

    const invalid = [_][]const u8{ "valid-but-must-not-send", "" };
    try std.testing.expectError(error.EmptyDatagram, sender.sendManyBytes(receiver.address(), &invalid));
}

test "QUIC UDP endpoint batches datagrams across destinations" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_traffic: SocketTrafficCounters = .{};
    var first = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer first.deinit();
    var second = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer second.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 128,
            .enable_gso_send = false,
            .socket_traffic_counters = &sender_traffic,
        },
    );
    defer sender.deinit();

    const datagrams = [_]AddressedDatagram{
        .{ .to = first.address(), .bytes = "a1" },
        .{ .to = second.address(), .bytes = "b1" },
        .{ .to = first.address(), .bytes = "a2" },
        .{ .to = second.address(), .bytes = "b2" },
    };
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    sender.allocator = no_alloc.allocator();
    const progress = try sender.sendManyAddressedBytesProgress(&datagrams);
    try std.testing.expectEqual(datagrams.len, progress.sent_count);
    try std.testing.expectEqual(
        @as(?net.Socket.SendError, null),
        progress.send_error,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);

    for ([_][]const u8{ "a1", "a2" }) |expected| {
        var received = try first.receiveBytes();
        defer received.deinit(allocator);
        try std.testing.expectEqualStrings(expected, received.bytes);
    }
    for ([_][]const u8{ "b1", "b2" }) |expected| {
        var received = try second.receiveBytes();
        defer received.deinit(allocator);
        try std.testing.expectEqualStrings(expected, received.bytes);
    }
    try std.testing.expectEqual(SocketTrafficStats{
        .sent_datagrams = 4,
        .sent_bytes = 8,
    }, sender_traffic.stats());

    const invalid = [_]AddressedDatagram{
        .{ .to = first.address(), .bytes = "must-not-send" },
        .{ .to = second.address(), .bytes = "" },
    };
    try std.testing.expectError(
        error.EmptyDatagram,
        sender.sendManyAddressedBytesProgress(&invalid),
    );
    try std.testing.expectEqual(SocketTrafficStats{
        .sent_datagrams = 4,
        .sent_bytes = 8,
    }, sender_traffic.stats());
}

test "QUIC UDP socket traffic counts successful single and batch I/O" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_traffic: SocketTrafficCounters = .{};
    var receiver_traffic: SocketTrafficCounters = .{};
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 128,
            .enable_gro_receive = false,
            .socket_traffic_counters = &receiver_traffic,
        },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 128,
            .enable_gso_send = false,
            .socket_traffic_counters = &sender_traffic,
        },
    );
    defer sender.deinit();

    try sender.sendBytes(receiver.address(), "one");
    try sender.sendManyBytes(receiver.address(), &.{ "two", "three" });
    var storage: [128]u8 = undefined;
    for ([_][]const u8{ "one", "two", "three" }) |expected| {
        const received = try receiver.receiveBytesInto(&storage);
        try std.testing.expectEqualStrings(expected, received.bytes);
    }

    try std.testing.expectEqual(SocketTrafficStats{
        .sent_datagrams = 3,
        .sent_bytes = 11,
    }, sender_traffic.stats());
    try std.testing.expectEqual(SocketTrafficStats{
        .received_datagrams = 3,
        .received_bytes = 11,
    }, receiver_traffic.stats());
    try std.testing.expectEqual(SocketTrafficStats{
        .sent_datagrams = 3,
        .sent_bytes = 11,
    }, sender_traffic.stats().since(.{}));
}

test "QUIC UDP single send treats a complete datagram as success despite a trailing error" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_traffic: SocketTrafficCounters = .{};
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 128,
            .enable_gso_send = false,
            .socket_traffic_counters = &sender_traffic,
        },
    );
    defer sender.deinit();

    // The wrapped backend reports the datagram as fully sent and then an
    // error. A single-datagram send must keep the success because the peer
    // already received those bytes.
    var observed = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 1,
    };
    sender.io = observed.io();
    defer sender.io = observed.delegate;

    try sender.sendBytes(receiver.address(), "complete");
    var storage: [128]u8 = undefined;
    const received = try receiver.receiveBytesInto(&storage);
    try std.testing.expectEqualStrings("complete", received.bytes);
    try std.testing.expectEqual(@as(usize, 1), observed.calls);
    try std.testing.expectEqual(@as(usize, 1), observed.last_message_count);
    try std.testing.expectEqual(SocketTrafficStats{
        .sent_datagrams = 1,
        .sent_bytes = "complete".len,
    }, sender_traffic.stats());
}

test "QUIC UDP endpoint receives into caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer sender.deinit();

    try sender.sendBytes(receiver.address(), "borrowed-datagram");
    var storage: [128]u8 = undefined;
    const received = try receiver.receiveBytesInto(&storage);
    try std.testing.expectEqualStrings(
        "borrowed-datagram",
        received.bytes,
    );
    try std.testing.expectEqual(
        @intFromPtr(&storage),
        @intFromPtr(received.bytes.ptr),
    );
    try std.testing.expect(received.from.eql(&sender.address()));
}

test "QUIC UDP endpoint receives plain batch into caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer sender.deinit();

    try sender.sendBytes(receiver.address(), "plain-batch");
    var too_short: [127]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        receiver.receiveBytesBatchInto(&too_short),
    );
    var storage: [128]u8 = undefined;
    const received = try receiver.receiveBytesBatchInto(&storage);
    try std.testing.expectEqual(@as(usize, 1), received.segment_count);
    try std.testing.expectEqual(@as(usize, 11), received.segment_size);
    try std.testing.expectEqualStrings(
        "plain-batch",
        received.datagramAt(0).?,
    );
    try std.testing.expectEqual(
        @intFromPtr(&storage),
        @intFromPtr(received.storage.ptr),
    );
    try std.testing.expect(received.from.eql(&sender.address()));
    try std.testing.expectEqual(&receiver, received.received_on.?);
}

test "QUIC UDP endpoint drains ready datagrams into caller storage" {
    const allocator = std.testing.allocator;
    var backend = try @import("../../runtime.zig").Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer sender.deinit();

    const expected = [_][]const u8{ "one", "message-two", "third" };
    for (expected) |bytes| try sender.sendBytes(receiver.address(), bytes);

    var short_storage: [3 * 128 - 1]u8 = undefined;
    var views: [3]ReceivedBytesView = undefined;
    var no_views: [0]ReceivedBytesView = .{};
    try std.testing.expectError(
        error.BufferTooShort,
        receiver.receiveManyBytesIntoWithDeadline(
            &short_storage,
            &no_views,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromSeconds(1),
            }),
        ),
    );
    try std.testing.expectError(
        error.BufferTooShort,
        receiver.receiveManyBytesIntoWithDeadline(
            &short_storage,
            &views,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromSeconds(1),
            }),
        ),
    );

    var storage: [3 * 128]u8 = undefined;
    const count = try receiver.receiveManyBytesIntoWithDeadline(
        &storage,
        &views,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    for (views[0..count]) |view| {
        try std.testing.expectEqual(&receiver, view.received_on.?);
    }
    try std.testing.expectEqual(expected.len, count);
    for (views[0..count], expected) |view, bytes| {
        try std.testing.expectEqualStrings(bytes, view.bytes);
        try std.testing.expect(view.from.eql(&sender.address()));
        try std.testing.expect(
            @intFromPtr(view.bytes.ptr) >= @intFromPtr(&storage) and
                @intFromPtr(view.bytes.ptr) <
                    @intFromPtr(&storage) + storage.len,
        );
    }
}

test "QUIC UDP endpoint batch preserves independent ECN control messages" {
    if (!socketEcnSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer sender.deinit();
    if (!receiver.receive_ecn_enabled) return error.SkipZigTest;

    const markings = [_]quic.packet_space.EcnCodepoint{
        .ect0,
        .ect1,
        .ce,
        .not_ect,
    };
    for (markings, 0..) |ecn, index| {
        const payload = [_]u8{@intCast(index + 1)};
        sender.sendBytesWithEcn(receiver.address(), &payload, ecn) catch |err|
            switch (err) {
                error.EcnUnavailable => return error.SkipZigTest,
                else => return err,
            };
    }

    var storage: [markings.len * 128]u8 = undefined;
    var views: [markings.len]ReceivedBytesView = undefined;
    const count = try receiver.receiveManyBytesIntoWithDeadline(
        &storage,
        &views,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expectEqual(markings.len, count);
    for (views[0..count], markings, 0..) |view, expected_ecn, index| {
        try std.testing.expectEqual(expected_ecn, view.ecn);
        try std.testing.expectEqualSlices(
            u8,
            &.{@as(u8, @intCast(index + 1))},
            view.bytes,
        );
    }
}

test "QUIC UDP endpoint receives GRO batch into caller storage" {
    if (!udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128, .enable_gro_receive = true },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer sender.deinit();
    if (!receiver.groReceiveEnabled() or !sender.gsoSendEnabled()) {
        return error.SkipZigTest;
    }
    var many_storage: [2 * 128]u8 = undefined;
    var many_views: [2]ReceivedBytesView = undefined;
    try std.testing.expectError(
        error.CallerBufferReceiveWithGro,
        receiver.receiveManyBytesIntoWithDeadline(
            &many_storage,
            &many_views,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromSeconds(1),
            }),
        ),
    );

    const wire = "aaaabbbbcc";
    const datagrams = [_][]const u8{
        wire[0..4],
        wire[4..8],
        wire[8..10],
    };
    try sender.sendManyBytes(receiver.address(), &datagrams);
    if (!sender.gsoSendEnabled()) return error.SkipZigTest;

    var too_short: [128]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        receiver.receiveBytesBatchInto(&too_short),
    );
    var storage: [max_gro_receive_bytes]u8 = undefined;
    const received = try receiver.receiveBytesBatchInto(&storage);
    try std.testing.expectEqual(@as(usize, 3), received.segment_count);
    try std.testing.expectEqual(@as(usize, 4), received.segment_size);
    try std.testing.expectEqual(
        @intFromPtr(&storage),
        @intFromPtr(received.storage.ptr),
    );
    for (datagrams, 0..) |expected, index| {
        try std.testing.expectEqualStrings(
            expected,
            received.datagramAt(index).?,
        );
    }
}

test "QUIC caller batch leaves pending GRO suffix queued on short buffer" {
    if (!udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128, .enable_gro_receive = true },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer sender.deinit();
    if (!receiver.groReceiveEnabled() or !sender.gsoSendEnabled()) {
        return error.SkipZigTest;
    }

    const wire = "aaaabbbbcc";
    const datagrams = [_][]const u8{
        wire[0..4],
        wire[4..8],
        wire[8..10],
    };
    try sender.sendManyBytes(receiver.address(), &datagrams);
    if (!sender.gsoSendEnabled()) return error.SkipZigTest;
    var first = try receiver.receiveBytes();
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("aaaa", first.bytes);
    try std.testing.expectEqual(@as(usize, 2), receiver.pendingReceivedCount());

    var storage: [max_gro_receive_bytes]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesBatchIntoWithTimeout(
            &storage,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), receiver.pendingReceivedCount());
    var too_short: [128]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        receiver.receiveBytesBatchInto(&too_short),
    );
    try std.testing.expectEqual(@as(usize, 2), receiver.pendingReceivedCount());

    try std.testing.expectError(error.Timeout, receiver.receiveBytesBatchIntoTimeout(&storage, .{
        .duration = .{ .clock = .awake, .raw = .zero },
    }));
    try std.testing.expectEqual(@as(usize, 2), receiver.pendingReceivedCount());
    const second = try receiver.receiveBytesBatchIntoTimeout(&storage, .{
        .duration = .{ .clock = .awake, .raw = .fromSeconds(1) },
    });
    try std.testing.expectEqual(@as(usize, 1), second.segment_count);
    try std.testing.expectEqualStrings("bbbb", second.datagramAt(0).?);
    try std.testing.expectEqual(@as(usize, 1), receiver.pendingReceivedCount());
    const third = try receiver.receiveBytesBatchInto(&storage);
    try std.testing.expectEqualStrings("cc", third.datagramAt(0).?);
    try std.testing.expectEqual(@as(usize, 0), receiver.pendingReceivedCount());
}

test "QUIC UDP GSO planner requires a contiguous equal-sized prefix" {
    if (!udpGsoSupported()) return error.SkipZigTest;

    const storage = "aaaabbbbcc";
    const valid = [_][]const u8{
        storage[0..4],
        storage[4..8],
        storage[8..10],
    };
    const plan = gsoPlan(&valid) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 3), plan.segment_count);
    try std.testing.expectEqual(@as(u16, 4), plan.segment_size);
    try std.testing.expectEqual(@as(usize, storage.len), plan.total_len);
    try std.testing.expectEqual(@intFromPtr(storage.ptr), @intFromPtr(plan.data_ptr));

    const discontiguous = [_][]const u8{ "aaaa", "bbbb" };
    try std.testing.expect(gsoPlan(&discontiguous) == null);
    const short_middle = [_][]const u8{
        storage[0..4],
        storage[4..6],
        storage[6..10],
    };
    try std.testing.expect(gsoPlan(&short_middle) == null);
}

test "QUIC UDP GSO control message encodes native segment size" {
    if (!udpGsoSupported()) return error.SkipZigTest;

    var control: [udp_gso_control_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
    const encoded = encodeUdpGsoControl(&control, 1200);
    try std.testing.expectEqual(@as(usize, udp_gso_control_len), encoded.len);
    const header: *const EcnCmsgHdr = @ptrCast(@alignCast(encoded.ptr));
    try std.testing.expectEqual(@as(usize, @sizeOf(EcnCmsgHdr) + @sizeOf(u16)), header.len);
    try std.testing.expectEqual(udp_gso_level, header.level);
    try std.testing.expectEqual(udp_gso_segment, header.type);
    try std.testing.expectEqual(
        @as(u16, 1200),
        std.mem.bytesToValue(u16, encoded[@sizeOf(EcnCmsgHdr)..][0..@sizeOf(u16)]),
    );
}

test "QUIC UDP receive control decodes ECN and GRO segment size" {
    if (!udpGroSupported()) return error.SkipZigTest;

    const ecn_len = cmsgSpace(@sizeOf(u32));
    var control: [cmsgSpace(@sizeOf(u32)) + cmsgSpace(@sizeOf(i32))]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
    @memset(&control, 0);

    const ecn_header: *EcnCmsgHdr = @ptrCast(@alignCast(control[0..].ptr));
    ecn_header.* = .{
        .len = @sizeOf(EcnCmsgHdr) + @sizeOf(u32),
        .level = ipproto_ip,
        .type = ip_tos_cmsg_type,
    };
    const ecn_value: u32 = ecnCodepointBits(.ect0);
    @memcpy(
        control[@sizeOf(EcnCmsgHdr)..][0..@sizeOf(u32)],
        std.mem.asBytes(&ecn_value),
    );

    const gro_header: *EcnCmsgHdr = @ptrCast(@alignCast(control[ecn_len..].ptr));
    gro_header.* = .{
        .len = @sizeOf(EcnCmsgHdr) + @sizeOf(i32),
        .level = udp_gso_level,
        .type = @intCast(udp_gro_segment),
    };
    const gro_value: i32 = 1200;
    @memcpy(
        control[ecn_len + @sizeOf(EcnCmsgHdr) ..][0..@sizeOf(i32)],
        std.mem.asBytes(&gro_value),
    );

    const decoded = receiveControlFromBytes(&control);
    try std.testing.expectEqual(quic.packet_space.EcnCodepoint.ect0, decoded.ecn);
    try std.testing.expectEqual(@as(?usize, 1200), decoded.gro_segment_size);
}

test "QUIC caller batch validates GRO metadata without ownership" {
    if (!udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200, .enable_gro_receive = true },
    );
    defer endpoint.deinit();
    if (!endpoint.groReceiveEnabled()) return error.SkipZigTest;

    var control: [receive_control_buffer_len]u8 align(@alignOf(EcnCmsgHdr)) =
        .{0} ** receive_control_buffer_len;
    const header: *EcnCmsgHdr = @ptrCast(@alignCast(control[0..].ptr));
    header.* = .{
        .len = @sizeOf(EcnCmsgHdr) + @sizeOf(i32),
        .level = udp_gso_level,
        .type = @intCast(udp_gro_segment),
    };
    const segment_size: i32 = 1200;
    @memcpy(
        control[@sizeOf(EcnCmsgHdr)..][0..@sizeOf(i32)],
        std.mem.asBytes(&segment_size),
    );
    var payload: [2401]u8 = undefined;
    const valid = try endpoint.finishKernelBytesBatchView(.{
        .from = endpoint.address(),
        .data = &payload,
        .control = &control,
        .flags = .{
            .eor = false,
            .trunc = false,
            .ctrunc = false,
            .oob = false,
            .errqueue = false,
        },
    });
    try std.testing.expectEqual(@as(usize, 1200), valid.segment_size);
    try std.testing.expectEqual(@as(usize, 3), valid.segment_count);
    try std.testing.expectEqual(@as(usize, 1), valid.datagramAt(2).?.len);

    endpoint.gro_receive_enabled = false;
    try std.testing.expectError(
        error.InvalidGroSegment,
        endpoint.finishKernelBytesBatchView(.{
            .from = endpoint.address(),
            .data = &payload,
            .control = &control,
            .flags = .{
                .eor = false,
                .trunc = false,
                .ctrunc = false,
                .oob = false,
                .errqueue = false,
            },
        }),
    );
    endpoint.gro_receive_enabled = true;
    try std.testing.expectError(
        error.InvalidGroSegment,
        endpoint.finishKernelBytesBatchView(.{
            .from = endpoint.address(),
            .data = payload[0..1200],
            .control = &control,
            .flags = .{
                .eor = false,
                .trunc = false,
                .ctrunc = false,
                .oob = false,
                .errqueue = false,
            },
        }),
    );

    const oversized_segment: i32 = 1201;
    @memcpy(
        control[@sizeOf(EcnCmsgHdr)..][0..@sizeOf(i32)],
        std.mem.asBytes(&oversized_segment),
    );
    try std.testing.expectError(
        error.InvalidGroSegment,
        endpoint.finishKernelBytesBatchView(.{
            .from = endpoint.address(),
            .data = &payload,
            .control = &control,
            .flags = emptyIncomingFlags(),
        }),
    );

    const tiny_segment: i32 = 32;
    @memcpy(
        control[@sizeOf(EcnCmsgHdr)..][0..@sizeOf(i32)],
        std.mem.asBytes(&tiny_segment),
    );
    try std.testing.expectError(
        error.InvalidGroSegment,
        endpoint.finishKernelBytesBatchView(.{
            .from = endpoint.address(),
            .data = &payload,
            .control = &control,
            .flags = emptyIncomingFlags(),
        }),
    );

    @memcpy(
        control[@sizeOf(EcnCmsgHdr)..][0..@sizeOf(i32)],
        std.mem.asBytes(&segment_size),
    );
    var truncated_flags = emptyIncomingFlags();
    truncated_flags.trunc = true;
    try std.testing.expectError(
        error.DatagramTooLarge,
        endpoint.finishKernelBytesBatchView(.{
            .from = endpoint.address(),
            .data = &payload,
            .control = &control,
            .flags = truncated_flags,
        }),
    );
}

test "QUIC UDP endpoint segments a contiguous GSO super-packet" {
    if (!udpGsoSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 128,
        .enable_gro_receive = true,
    });
    defer receiver.deinit();
    var sender = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer sender.deinit();

    const storage = "aaaabbbbcc";
    const datagrams = [_][]const u8{
        storage[0..4],
        storage[4..8],
        storage[8..10],
    };
    try sender.sendManyBytes(receiver.address(), &datagrams);
    if (!sender.gsoSendEnabled()) return error.SkipZigTest;
    if (!receiver.groReceiveEnabled()) return error.SkipZigTest;

    var received = try receiver.receiveBytesBatch();
    defer received.deinit(allocator);
    try std.testing.expectEqual(datagrams.len, received.segment_count);
    try std.testing.expectEqual(@as(usize, 4), received.segment_size);
    for (datagrams, 0..) |expected, index| {
        try std.testing.expectEqualStrings(expected, received.datagramAt(index).?);
    }
    try std.testing.expect(received.datagramAt(datagrams.len) == null);
}

test "QUIC UDP timed receive preserves one GRO owning batch" {
    if (!udpGsoSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 128,
            .enable_gro_receive = true,
        },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer sender.deinit();
    if (!receiver.groReceiveEnabled() or !sender.gsoSendEnabled()) {
        return error.SkipZigTest;
    }

    const storage = "aaaabbbbcc";
    const datagrams = [_][]const u8{
        storage[0..4],
        storage[4..8],
        storage[8..10],
    };
    try sender.sendManyBytes(receiver.address(), &datagrams);
    var received = try receiver.receiveBytesBatchTimeout(.{
        .duration = .{
            .clock = .awake,
            .raw = std.Io.Duration.fromSeconds(1),
        },
    });
    defer received.deinit(allocator);
    try std.testing.expectEqual(datagrams.len, received.segment_count);
    try std.testing.expectEqual(@as(usize, 4), received.segment_size);
    for (datagrams, 0..) |expected, index| {
        try std.testing.expectEqualStrings(
            expected,
            received.datagramAt(index).?,
        );
    }
}

test "QUIC UDP GRO shared storage survives frame-datagram ownership transfer" {
    if (!udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sender_traffic: SocketTrafficCounters = .{};
    var receiver_traffic: SocketTrafficCounters = .{};
    var receiver = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 128,
        .enable_gro_receive = true,
        .socket_traffic_counters = &receiver_traffic,
    });
    defer receiver.deinit();
    var sender = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 128,
        .socket_traffic_counters = &sender_traffic,
    });
    defer sender.deinit();
    if (!receiver.groReceiveEnabled()) return error.SkipZigTest;

    // Frame type 0x01 is PING and zero bytes are PADDING. Use realistic-sized
    // segments because some NIC/kernel combinations reject one-byte GSO
    // segments even though the payload is otherwise valid.
    const segment = [_]u8{0x01} ++ [_]u8{0x00} ** 15;
    const storage = segment ++ segment;
    const datagrams = [_][]const u8{ storage[0..segment.len], storage[segment.len..] };
    try sender.sendManyBytes(receiver.address(), &datagrams);
    if (!sender.gsoSendEnabled()) return error.SkipZigTest;

    var first = try receiver.receive();
    defer first.deinit(allocator);
    var second = try receiver.receive();
    defer second.deinit(allocator);
    try std.testing.expect(first.shared_buffer != null);
    try std.testing.expectEqual(first.shared_buffer, second.shared_buffer);
    // Consecutive PADDING bytes are represented as one parsed frame.
    try std.testing.expectEqual(@as(usize, 2), first.frames.len);
    try std.testing.expectEqual(@as(usize, 2), second.frames.len);
    try std.testing.expect(first.frames[0] == .ping);
    try std.testing.expect(second.frames[0] == .ping);
    try std.testing.expectEqual(SocketTrafficStats{
        .sent_datagrams = 2,
        .sent_bytes = 32,
    }, sender_traffic.stats());
    try std.testing.expectEqual(SocketTrafficStats{
        .received_datagrams = 2,
        .received_bytes = 32,
    }, receiver_traffic.stats());
}

test "QUIC UDP receive ignores asynchronous message oversize" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer sender.deinit();

    var rejecting = RejectMessageOversizeReceives{ .delegate = io };
    var vtable = io.vtable.*;
    vtable.operate = RejectMessageOversizeReceives.operate;
    receiver.io = .{ .userdata = &rejecting, .vtable = &vtable };
    defer receiver.io = io;

    try sender.sendBytes(receiver.address(), "owned");
    rejecting.arm(1);
    var owned = try receiver.receiveKernelBytesBatchWithEcn();
    defer owned.deinit(allocator);
    try std.testing.expectEqualStrings("owned", owned.datagramAt(0).?);
    try std.testing.expectEqual(@as(usize, 2), rejecting.receive_calls);

    try sender.sendBytes(receiver.address(), "caller");
    rejecting.arm(1);
    var storage: [128]u8 = undefined;
    const caller = try receiver.receiveKernelBytesInto(&storage);
    try std.testing.expectEqualStrings("caller", caller.bytes);
    try std.testing.expectEqual(@as(usize, 2), rejecting.receive_calls);

    var truncated_flags = emptyIncomingFlags();
    truncated_flags.trunc = true;
    try std.testing.expectError(
        error.DatagramTooLarge,
        receiver.finishKernelBytesInto(.{
            .from = sender.address(),
            .data = @constCast("truncated"),
            .control = &.{},
            .flags = truncated_flags,
        }),
    );
}

test "QUIC endpoint pending receive queue reuses consumed slots" {
    const allocator = std.testing.allocator;
    var endpoint = Endpoint{
        .io = undefined,
        .allocator = allocator,
        .socket = undefined,
    };
    defer endpoint.pending_received.deinit(allocator);

    try endpoint.pending_received.ensureTotalCapacityPrecise(allocator, 4);
    for (0..4) |index| {
        const byte = try allocator.alloc(u8, 1);
        byte[0] = @intCast(index);
        endpoint.pending_received.appendAssumeCapacity(.{
            .from = .{ .ip4 = .loopback(443) },
            .bytes = byte,
        });
    }

    endpoint.pending_received.items[0].deinit(allocator);
    endpoint.pending_receive_index = 1;
    try std.testing.expectEqual(@as(usize, 3), endpoint.pendingReceivedCount());

    try endpoint.ensurePendingReceivedCapacity(1);
    try std.testing.expectEqual(@as(usize, 0), endpoint.pending_receive_index);
    try std.testing.expectEqual(@as(usize, 3), endpoint.pending_received.items.len);
    try std.testing.expectEqual(@as(usize, 4), endpoint.pending_received.capacity);
    try std.testing.expectEqual(@as(u8, 1), endpoint.pending_received.items[0].bytes[0]);

    const replacement = try allocator.alloc(u8, 1);
    replacement[0] = 9;
    endpoint.pending_received.appendAssumeCapacity(.{
        .from = .{ .ip4 = .loopback(443) },
        .bytes = replacement,
    });
    try std.testing.expectEqual(@as(usize, 4), endpoint.pending_received.items.len);

    for (endpoint.pending_received.items) |*pending| pending.deinit(allocator);
    endpoint.pending_received.clearRetainingCapacity();
}

test "QUIC endpoint preserves a received batch prefix before socket error" {
    var endpoint = Endpoint{
        .io = undefined,
        .allocator = std.testing.allocator,
        .socket = undefined,
        .limits = .{ .max_datagram_size = 16 },
    };
    const source = net.IpAddress{ .ip4 = .loopback(443) };
    var messages = [_]net.IncomingMessage{
        .{
            .from = source,
            .data = @constCast("first"),
            .control = &.{},
            .flags = .{
                .eor = false,
                .trunc = false,
                .ctrunc = false,
                .oob = false,
                .errqueue = false,
            },
        },
        .{
            .from = source,
            .data = @constCast("second"),
            .control = &.{},
            .flags = .{
                .eor = false,
                .trunc = false,
                .ctrunc = false,
                .oob = false,
                .errqueue = false,
            },
        },
    };
    var views: [messages.len]ReceivedBytesView = undefined;
    const count = try endpoint.finishManyKernelBytesInto(
        &messages,
        &views,
        error.NetworkDown,
        messages.len,
    );
    try std.testing.expectEqual(messages.len, count);
    try std.testing.expectEqualStrings("first", views[0].bytes);
    try std.testing.expectEqualStrings("second", views[1].bytes);
    try std.testing.expectError(
        error.NetworkDown,
        endpoint.finishManyKernelBytesInto(
            &messages,
            &views,
            error.NetworkDown,
            0,
        ),
    );
}

test "QUIC UDP endpoint disables rejected GSO and retries send-many" {
    if (!udpGsoSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sender_traffic: SocketTrafficCounters = .{};
    var receiver_traffic: SocketTrafficCounters = .{};
    var receiver = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 128,
        .socket_traffic_counters = &receiver_traffic,
    });
    defer receiver.deinit();
    var sender = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 128,
        .socket_traffic_counters = &sender_traffic,
    });
    defer sender.deinit();

    var rejecting = RejectFirstGsoSend{ .delegate = sender.io };
    var rejecting_vtable = sender.io.vtable.*;
    rejecting_vtable.netSend = RejectFirstGsoSend.netSend;
    sender.io = .{ .userdata = &rejecting, .vtable = &rejecting_vtable };
    defer sender.io = rejecting.delegate;

    const storage = "aaaabbbb";
    const datagrams = [_][]const u8{ storage[0..4], storage[4..8] };
    try sender.sendManyBytes(receiver.address(), &datagrams);
    try std.testing.expect(!sender.gsoSendEnabled());
    try std.testing.expectEqual(@as(usize, 2), rejecting.calls);
    try std.testing.expectEqual(@as(usize, 1), rejecting.gso_calls);
    try std.testing.expectEqual(@as(usize, 1), rejecting.fallback_calls);

    for (datagrams) |expected| {
        var received = try receiver.receiveBytes();
        defer received.deinit(allocator);
        try std.testing.expectEqualStrings(expected, received.bytes);
    }

    try sender.sendManyBytes(receiver.address(), &datagrams);
    try std.testing.expectEqual(@as(usize, 3), rejecting.calls);
    try std.testing.expectEqual(@as(usize, 1), rejecting.gso_calls);
    try std.testing.expectEqual(@as(usize, 2), rejecting.fallback_calls);
    for (datagrams) |expected| {
        var received = try receiver.receiveBytes();
        defer received.deinit(allocator);
        try std.testing.expectEqualStrings(expected, received.bytes);
    }
    try std.testing.expectEqual(SocketTrafficStats{
        .sent_datagrams = 4,
        .sent_bytes = 16,
    }, sender_traffic.stats());
    try std.testing.expectEqual(SocketTrafficStats{
        .received_datagrams = 4,
        .received_bytes = 16,
    }, receiver_traffic.stats());
}

test "QUIC UDP socket traffic commits only a partially sent batch prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_traffic: SocketTrafficCounters = .{};
    var receiver_traffic: SocketTrafficCounters = .{};
    var receiver = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 64,
        .socket_traffic_counters = &receiver_traffic,
    });
    defer receiver.deinit();
    var sender = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 64,
        .enable_gso_send = false,
        .socket_traffic_counters = &sender_traffic,
    });
    defer sender.deinit();

    var partial = AcceptFirstBatchDatagram{ .delegate = sender.io };
    var partial_vtable = sender.io.vtable.*;
    partial_vtable.netSend = AcceptFirstBatchDatagram.netSend;
    sender.io = .{ .userdata = &partial, .vtable = &partial_vtable };
    defer sender.io = partial.delegate;

    const result = try sender.sendManyBytesProgress(
        receiver.address(),
        &.{ "first", "second" },
    );
    try std.testing.expectEqual(@as(usize, 1), result.sent_count);
    try std.testing.expectEqual(error.NetworkDown, result.send_error.?);
    try std.testing.expectEqual(@as(usize, 1), partial.calls);
    var received = try receiver.receiveBytes();
    defer received.deinit(allocator);
    try std.testing.expectEqualStrings("first", received.bytes);
    try std.testing.expectEqual(SocketTrafficStats{
        .sent_datagrams = 1,
        .sent_bytes = 5,
    }, sender_traffic.stats());
    try std.testing.expectEqual(SocketTrafficStats{
        .received_datagrams = 1,
        .received_bytes = 5,
    }, receiver_traffic.stats());
}

test "QUIC addressed UDP batch reports a partially sent prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_traffic: SocketTrafficCounters = .{};
    var first = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 64 },
    );
    defer first.deinit();
    var second = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 64 },
    );
    defer second.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 64,
            .enable_gso_send = false,
            .socket_traffic_counters = &sender_traffic,
        },
    );
    defer sender.deinit();

    var partial = AcceptFirstBatchDatagram{ .delegate = sender.io };
    var partial_vtable = sender.io.vtable.*;
    partial_vtable.netSend = AcceptFirstBatchDatagram.netSend;
    sender.io = .{ .userdata = &partial, .vtable = &partial_vtable };
    defer sender.io = partial.delegate;

    const datagrams = [_]AddressedDatagram{
        .{ .to = first.address(), .bytes = "first" },
        .{ .to = second.address(), .bytes = "second" },
    };
    const progress = try sender.sendManyAddressedBytesProgressWithEcn(
        &datagrams,
        .not_ect,
    );
    try std.testing.expectEqual(@as(usize, 1), progress.sent_count);
    try std.testing.expectEqual(error.NetworkDown, progress.send_error.?);
    try std.testing.expectEqual(@as(usize, 1), partial.calls);
    var received = try first.receiveBytes();
    defer received.deinit(allocator);
    try std.testing.expectEqualStrings("first", received.bytes);
    try std.testing.expectEqual(SocketTrafficStats{
        .sent_datagrams = 1,
        .sent_bytes = 5,
    }, sender_traffic.stats());
}

test "QUIC endpoint send interceptor drops selected single and batch datagrams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var calls: usize = 0;
    var sender_traffic: SocketTrafficCounters = .{};
    var receiver_traffic: SocketTrafficCounters = .{};
    const Interceptor = struct {
        fn drop(context: *anyopaque, bytes: []const u8) bool {
            const count: *usize = @ptrCast(@alignCast(context));
            count.* += 1;
            return bytes[0] == 0xaa;
        }
    };
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 64,
            .socket_traffic_counters = &receiver_traffic,
        },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 64,
            .send_interceptor = .{
                .context = &calls,
                .should_drop = Interceptor.drop,
            },
            .socket_traffic_counters = &sender_traffic,
        },
    );
    defer sender.deinit();

    try sender.sendBytes(receiver.address(), &.{0xaa});
    try sender.sendBytes(receiver.address(), &.{0xbb});
    var received = try receiver.receiveBytes();
    try std.testing.expectEqualSlices(u8, &.{0xbb}, received.bytes);

    const batch = [_][]const u8{ &.{0xaa}, &.{0xcc} };
    const progress = try sender.sendManyBytesProgress(
        receiver.address(),
        &batch,
    );
    try std.testing.expectEqual(@as(usize, 2), progress.sent_count);
    received.deinit(allocator);
    received = try receiver.receiveBytes();
    try std.testing.expectEqualSlices(u8, &.{0xcc}, received.bytes);
    try std.testing.expectEqual(@as(usize, 4), calls);
    received.deinit(allocator);
    try std.testing.expectEqual(SocketTrafficStats{
        .sent_datagrams = 2,
        .sent_bytes = 2,
    }, sender_traffic.stats());
    try std.testing.expectEqual(SocketTrafficStats{
        .received_datagrams = 2,
        .received_bytes = 2,
    }, receiver_traffic.stats());
}

test "QUIC endpoint send interceptor reorders one datagram pair" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var held_once = false;
    const Interceptor = struct {
        fn hold(context: *anyopaque, _: []const u8) bool {
            const held: *bool = @ptrCast(@alignCast(context));
            if (held.*) return false;
            held.* = true;
            return true;
        }
    };
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 64 },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 64,
            .send_interceptor = .{
                .context = &held_once,
                .should_hold = Interceptor.hold,
            },
        },
    );
    defer sender.deinit();

    try sender.sendBytes(receiver.address(), "first");
    try sender.sendBytes(receiver.address(), "second");
    var second = try receiver.receiveBytes();
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("second", second.bytes);
    var first = try receiver.receiveBytes();
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.bytes);
}

test "QUIC endpoint hold interceptor publishes state only after allocation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const AlwaysHold = struct {
        fn hold(_: *anyopaque, _: []const u8) bool {
            return true;
        }
    };
    var context: u8 = 0;
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 64,
            .send_interceptor = .{
                .context = &context,
                .should_hold = AlwaysHold.hold,
            },
        },
    );
    defer sender.deinit();

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    sender.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        sender.sendBytes(sender.address(), "held"),
    );
    sender.allocator = allocator;
    try std.testing.expect(sender.held_send == null);
    try std.testing.expect(failing.has_induced_failure);
}

test "QUIC endpoint send interceptor corrupts an owned datagram copy" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var corrupted_once = false;
    const Interceptor = struct {
        fn corrupt(context: *anyopaque, bytes: []u8) bool {
            const corrupted: *bool = @ptrCast(@alignCast(context));
            if (corrupted.*) return false;
            corrupted.* = true;
            bytes[0] ^= 0xff;
            return true;
        }
    };
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 64 },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 64,
            .send_interceptor = .{
                .context = &corrupted_once,
                .corrupt = Interceptor.corrupt,
            },
        },
    );
    defer sender.deinit();

    const source = [_]u8{ 0x11, 0x22 };
    try sender.sendBytes(receiver.address(), &source);
    var received = try receiver.receiveBytes();
    defer received.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0xee, 0x22 }, received.bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0x11, 0x22 }, &source);
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

test "QUIC endpoint serializes concurrent sends from shared connections" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 64 },
    );
    defer receiver.deinit();
    var sender = try Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 64 },
    );
    defer sender.deinit();

    const Task = struct {
        endpoint: *Endpoint,
        peer: net.IpAddress,
        byte: u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var payload = [_]u8{0} ** 16;
            @memset(&payload, self.byte);
            self.endpoint.sendBytes(self.peer, &payload) catch |err| {
                self.err = err;
            };
        }
    };
    var tasks: [16]Task = undefined;
    var threads: [tasks.len]std.Thread = undefined;
    for (&tasks, 0..) |*task, index| {
        task.* = .{
            .endpoint = &sender,
            .peer = receiver.address(),
            .byte = @intCast(index + 1),
        };
        threads[index] = try std.Thread.spawn(.{}, Task.run, .{task});
    }
    for (&threads) |*thread| thread.join();
    for (tasks) |task| if (task.err) |err| return err;

    var seen = [_]bool{false} ** tasks.len;
    for (0..tasks.len) |_| {
        var datagram = try receiver.receiveBytes();
        defer datagram.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 16), datagram.bytes.len);
        const marker = datagram.bytes[0];
        try std.testing.expect(marker >= 1 and marker <= tasks.len);
        for (datagram.bytes) |byte| try std.testing.expectEqual(marker, byte);
        try std.testing.expect(!seen[marker - 1]);
        seen[marker - 1] = true;
    }
    for (seen) |received| try std.testing.expect(received);
}
