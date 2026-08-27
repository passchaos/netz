const std = @import("std");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const webtransport = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const handshake_stream = @import("stream.zig");
const session_control = @import("session_control.zig");

test "WebTransport sessions poll dispatcher-routed stream and datagram state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_a_cid = "wt-client-a";
    const client_b_cid = "wt-client-b";
    const server_a_cid = "wt-server-a";
    const server_b_cid = "wt-server-b";
    const client_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc1} ** quic.protection.secret_len,
    );
    const client_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd1} ** quic.protection.secret_len,
    );
    const server_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc2} ** quic.protection.secret_len,
    );
    const server_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd2} ** quic.protection.secret_len,
    );
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});
    const h3_options = http3.runtime.HandshakeSessionOptions{
        .local_settings = settings,
        .max_stream_frame_data = 1024,
    };

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_a_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_a_endpoint.deinit();
    var client_b_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_b_endpoint.deinit();

    var server_a_h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client_a_endpoint.address(),
        h3_options,
        .{
            .receive_keys = client_a_keys,
            .send_keys = server_a_keys,
            .local_connection_id = server_a_cid,
            .peer_connection_id = client_a_cid,
            .local_transport_parameters = transport_parameters,
            .peer_transport_parameters = transport_parameters,
        },
    );
    var server_a_h3_owned = true;
    defer if (server_a_h3_owned) server_a_h3.deinit();
    var server_b_h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client_b_endpoint.address(),
        h3_options,
        .{
            .receive_keys = client_b_keys,
            .send_keys = server_b_keys,
            .local_connection_id = server_b_cid,
            .peer_connection_id = client_b_cid,
            .local_transport_parameters = transport_parameters,
            .peer_transport_parameters = transport_parameters,
        },
    );
    var server_b_h3_owned = true;
    defer if (server_b_h3_owned) server_b_h3.deinit();

    var streams_a = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_a_owned = true;
    defer if (streams_a_owned) streams_a.deinit();
    var streams_b = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_b_owned = true;
    defer if (streams_b_owned) streams_b.deinit();

    var session_a = runtime.AcceptedHandshakeSession{
        .h3 = server_a_h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams_a,
        .control = try session_control.Control.init(.init(0)),
    };
    server_a_h3_owned = false;
    streams_a_owned = false;
    defer {
        session_a.streams.deinit();
        session_a.h3.deinit();
    }
    var session_b = runtime.AcceptedHandshakeSession{
        .h3 = server_b_h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams_b,
        .control = try session_control.Control.init(.init(0)),
    };
    server_b_h3_owned = false;
    streams_b_owned = false;
    defer {
        session_b.streams.deinit();
        session_b.h3.deinit();
    }
    // These sessions are constructed after the CONNECT exchange boundary so
    // seed the peer SETTINGS that acceptance has already validated. The test
    // then focuses exclusively on post-admission dispatcher routing.
    session_a.h3.control.settings.markSent(settings);
    session_a.h3.control.settings.markReceived(settings);
    session_b.h3.control.settings.markSent(settings);
    session_b.h3.control.settings.markReceived(settings);

    var client_a = try quic.one_rtt.Connection.init(&client_a_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_a_keys,
        .send_keys = client_a_keys,
        .local_connection_id = client_a_cid,
        .peer_connection_id = server_a_cid,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer client_a.deinit();
    var client_b = try quic.one_rtt.Connection.init(&client_b_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_b_keys,
        .send_keys = client_b_keys,
        .local_connection_id = client_b_cid,
        .peer_connection_id = server_b_cid,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer client_b.deinit();

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &session_a.h3.established.connection);
    try dispatcher.registerConnection(2, &session_b.h3.established.connection);

    var prefix_a: [16]u8 = undefined;
    var prefix_b: [16]u8 = undefined;
    const header_a = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_a,
        .init(0),
    );
    const header_b = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_b,
        .init(0),
    );
    const stream_a = [_]quic.Frame{ .{ .stream = .{
        .stream_id = 4,
        .data = header_a,
    } }, .{ .stream = .{
        .stream_id = 4,
        .offset = header_a.len,
        .data = "stream-a",
        .fin = true,
    } } };
    const stream_b = [_]quic.Frame{ .{ .stream = .{
        .stream_id = 4,
        .data = header_b,
    } }, .{ .stream = .{
        .stream_id = 4,
        .offset = header_b.len,
        .data = "stream-b",
        .fin = true,
    } } };
    try client_b.send(&stream_b);
    try client_a.send(&stream_a);
    try sendDatagram(&client_b, .init(0), "datagram-b");
    try sendDatagram(&client_a, .init(0), "datagram-a");
    var drain_a_storage: [16]u8 = undefined;
    const drain_a = try session_control.writeDrainInto(&drain_a_storage);
    var framed_a: [32]u8 = undefined;
    const framed_a_len = try writeDataFrame(
        &framed_a,
        drain_a,
    );
    const control_a = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = framed_a[0..framed_a_len],
    } }};
    try client_a.send(&control_a);

    var saw_stream_a = false;
    var saw_stream_b = false;
    var saw_datagram_a = false;
    var saw_datagram_b = false;
    var saw_drain_a = false;
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    while (!saw_stream_a or !saw_stream_b or
        !saw_datagram_a or !saw_datagram_b or !saw_drain_a)
    {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                const session = switch (routed.connection_handle) {
                    1 => &session_a,
                    2 => &session_b,
                    else => return error.TestUnexpectedResult,
                };
                try session.processPacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(
                    routed.connection_handle,
                );
                if (try session.pollCompleteStream()) |stream_value| {
                    var stream = stream_value;
                    defer stream.deinit();
                    const expected = if (routed.connection_handle == 1)
                        "stream-a"
                    else
                        "stream-b";
                    try std.testing.expectEqualStrings(
                        expected,
                        stream.payload,
                    );
                    if (routed.connection_handle == 1)
                        saw_stream_a = true
                    else
                        saw_stream_b = true;
                }
                if (try session.pollDatagram()) |datagram_value| {
                    var datagram = datagram_value;
                    defer datagram.deinit(allocator);
                    const expected = if (routed.connection_handle == 1)
                        "datagram-a"
                    else
                        "datagram-b";
                    try std.testing.expectEqualStrings(
                        expected,
                        datagram.datagram.payload,
                    );
                    if (routed.connection_handle == 1)
                        saw_datagram_a = true
                    else
                        saw_datagram_b = true;
                }
                if (try session.pollSessionEvent()) |control| {
                    try std.testing.expectEqual(
                        @as(usize, 1),
                        routed.connection_handle,
                    );
                    try std.testing.expect(control == .draining);
                    saw_drain_a = true;
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
}

test "WebTransport client polls a dispatcher-injected packet" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = "wt-routed-client";
    const server_cid = "wt-routed-server";
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe2} ** quic.protection.secret_len,
    );
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});
    const limits = http3.runtime.Limits{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    } };

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer client_endpoint.deinit();
    var pending = try runtime.HandshakeClientSession.beginEstablishedConnect(
        &client_endpoint,
        server_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &client_endpoint,
            server_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = client_cid,
                .peer_connection_id = server_cid,
                .local_transport_parameters = transport_parameters,
                .peer_transport_parameters = transport_parameters,
                .one_rtt = .{ .enable_pacing = false },
            },
        ),
        .{
            .authority = "localhost",
            .path = "/routed",
            .origin = "https://localhost",
            .limits = .{ .http3 = limits, .max_session_streams = 8 },
            .h3 = .{ .local_settings = settings },
        },
    );
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();

    var server = try quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = server_cid,
        .peer_connection_id = client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer server.deinit();
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .headers = &.{http3.capsule.protocol_header},
        .extended_connect = true,
    }).write(&response_bytes, allocator);
    var server_control = http3.ControlState{};
    var settings_bytes: std.ArrayList(u8) = .empty;
    defer settings_bytes.deinit(allocator);
    try server_control.writeSettingsStream(
        &settings_bytes,
        allocator,
        settings,
    );
    const response_frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 3,
            .data = settings_bytes.items,
        } },
        .{ .stream = .{
            .stream_id = pending.sessionId().value,
            .data = response_bytes.items,
        } },
    };
    try server.send(&response_frames);

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &client_endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, pending.connection());
    try std.testing.expect((try pending.pollConnect()) == null);
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var session = while (true) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                try pending.processPacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(1);
                if (try pending.pollConnect()) |attempt_value| {
                    var attempt = attempt_value;
                    pending_owned = false;
                    _ = try dispatcher.unregisterConnection(1);
                    routed.packet.deinit(allocator);
                    event = .consumed;
                    break try attempt.requireAccepted();
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    };
    defer session.deinit();
    try dispatcher.registerConnection(1, &session.h3.established.connection);
    const session_id = session.session_id.value;

    var stream_header: std.ArrayList(u8) = .empty;
    defer stream_header.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &stream_header,
        allocator,
        session.session_id,
    );
    var control_storage: [16]u8 = undefined;
    const drain = try session_control.writeDrainInto(&control_storage);
    var framed_control: [32]u8 = undefined;
    const framed_control_len = try writeDataFrame(&framed_control, drain);
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 7,
            .data = stream_header.items,
        } },
        .{ .stream = .{
            .stream_id = 7,
            .offset = stream_header.items.len,
            .data = "incremental",
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = 19,
            .data = stream_header.items,
        } },
        .{ .stream = .{
            .stream_id = 19,
            .offset = stream_header.items.len,
            .data = "complete",
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = session_id,
            .offset = response_bytes.items.len,
            .data = framed_control[0..framed_control_len],
        } },
    };
    try server.send(&frames);
    try sendDatagram(
        &server,
        session.session_id,
        "client-datagram",
    );

    try std.testing.expect((try session.pollCompleteStream()) == null);
    try std.testing.expect((try session.pollDatagram()) == null);
    try std.testing.expect((try session.pollSessionEvent()) == null);

    var saw_incremental_stream = false;
    var saw_complete_stream = false;
    var saw_datagram = false;
    var saw_drain = false;
    var stream_buffer: [32]u8 = undefined;
    while (!saw_incremental_stream or !saw_complete_stream or
        !saw_datagram or !saw_drain)
    {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                try std.testing.expectEqual(
                    @as(usize, 1),
                    routed.connection_handle,
                );
                try session.processPacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(1);

                if (try session.pollStream(&stream_buffer)) |stream| {
                    if (stream != .data) return error.TestUnexpectedResult;
                    try std.testing.expectEqual(@as(u62, 7), stream.data.stream_id);
                    try std.testing.expect(stream.data.fin);
                    try std.testing.expectEqualStrings(
                        "incremental",
                        stream_buffer[0..stream.data.bytes],
                    );
                    saw_incremental_stream = true;
                }
                if (try session.pollCompleteStream()) |stream_value| {
                    var stream = stream_value;
                    defer stream.deinit();
                    try std.testing.expectEqual(@as(u62, 19), stream.stream_id);
                    try std.testing.expectEqual(
                        webtransport.StreamDirection.unidirectional,
                        stream.direction,
                    );
                    try std.testing.expect(!stream.locally_initiated);
                    try std.testing.expect(stream.fin);
                    try std.testing.expectEqualStrings(
                        "complete",
                        stream.payload,
                    );
                    saw_complete_stream = true;
                }
                if (try session.pollDatagram()) |datagram_value| {
                    var datagram = datagram_value;
                    defer datagram.deinit(allocator);
                    try std.testing.expectEqualStrings(
                        "client-datagram",
                        datagram.datagram.payload,
                    );
                    saw_datagram = true;
                }
                if (try session.pollSessionEvent()) |control| {
                    try std.testing.expect(control == .draining);
                    saw_drain = true;
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
}

test "WebTransport handshake admission polls routed CONNECT state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const peer = client_endpoint.address();
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer,
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-server",
            .peer_connection_id = "wt-client",
            .local_transport_parameters = transport_parameters,
            .peer_transport_parameters = transport_parameters,
        },
    );
    var admission = runtime.HandshakeAdmission{
        .h3 = h3,
        .limits = .{ .max_session_streams = 8 },
    };
    h3 = undefined;
    var admission_owned = true;
    defer if (admission_owned) admission.deinit();
    admission.h3.control.settings.markSent(settings);
    admission.h3.control.settings.markReceived(settings);
    try std.testing.expect((try admission.pollSessionRequest()) == null);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{
        .method = "CONNECT",
        .scheme = "https",
        .authority = "localhost",
        .path = "/routed",
        .headers = &.{
            .{ .name = ":protocol", .value = "webtransport" },
            http3.capsule.protocol_header,
        },
    }).write(&encoded, allocator);
    var client = try quic.one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-client",
        .peer_connection_id = "wt-server",
        .enable_pacing = false,
    });
    defer client.deinit();
    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = encoded.items,
        .fin = false,
    } }};
    try client.send(&frames);
    var packet = try admission.h3.established.connection.receivePacket();
    defer packet.deinit(allocator);
    try admission.processPacket(&packet);

    var pending = (try admission.pollSessionRequest()) orelse
        return error.TestUnexpectedResult;
    admission_owned = false;
    defer pending.deinit();
    try std.testing.expectEqualStrings("localhost", pending.authority().?);
    try std.testing.expectEqualStrings("/routed", pending.path());
}

test "WebTransport handshake receive helpers honor timeouts" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe8} ** quic.protection.secret_len,
    );
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();

    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-timeout-server",
            .peer_connection_id = "wt-timeout-client",
            .local_transport_parameters = transport_parameters,
            .peer_transport_parameters = transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    var h3_owned = true;
    defer if (h3_owned) h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var session = runtime.AcceptedHandshakeSession{
        .h3 = h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(.init(0)),
    };
    h3_owned = false;
    streams_owned = false;
    defer {
        session.streams.deinit();
        session.h3.deinit();
    }
    var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-timeout-client",
        .peer_connection_id = "wt-timeout-server",
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer peer.deinit();

    try std.testing.expectError(
        error.Timeout,
        session.receiveDatagramWithTimeout(.fromMilliseconds(1)),
    );
    var buffer: [32]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        session.readStreamWithTimeout(&buffer, .fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receiveSessionEventWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receiveDatagramWithDeadline(.fromNow(
            io,
            .{ .raw = .fromMilliseconds(1), .clock = .awake },
        )),
    );
    try std.testing.expectError(
        error.Timeout,
        session.readStreamWithDeadline(
            &buffer,
            .fromNow(
                io,
                .{ .raw = .fromMilliseconds(1), .clock = .awake },
            ),
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receiveSessionEventWithDeadline(.fromNow(
            io,
            .{ .raw = .fromMilliseconds(1), .clock = .awake },
        )),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receivePeerConnectionCloseWithDeadline(.fromNow(
            io,
            .{ .raw = .fromMilliseconds(1), .clock = .awake },
        )),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receiveStreamWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receiveStreamWithDeadline(.fromNow(
            io,
            .{ .raw = .fromMilliseconds(1), .clock = .awake },
        )),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receivePeerConnectionCloseWithTimeout(
            .fromMilliseconds(1),
        ),
    );

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        .init(0),
    );
    const first_payload = "partial-";
    const partial_frames = [_]quic.Frame{ .{ .stream = .{
        .stream_id = 4,
        .data = prefix,
    } }, .{ .stream = .{
        .stream_id = 4,
        .offset = prefix.len,
        .data = first_payload,
    } } };
    try peer.send(&partial_frames);
    var partial_packet =
        try session.h3.established.connection.receivePacket();
    defer partial_packet.deinit(allocator);
    try session.processPacket(&partial_packet);
    try std.testing.expectError(
        error.Timeout,
        session.receiveStreamWithTimeout(.fromMilliseconds(1)),
    );

    // A bounded whole-stream receive must leave QUIC reassembly and the
    // WebTransport association intact when FIN has not arrived yet.
    const final_frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .offset = prefix.len + first_payload.len,
        .data = "complete",
        .fin = true,
    } }};
    try peer.send(&final_frames);
    var received = try session.receiveStreamWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer received.deinit();
    try std.testing.expectEqual(@as(u62, 4), received.stream_id);
    try std.testing.expectEqual(
        webtransport.StreamDirection.bidirectional,
        received.direction,
    );
    try std.testing.expect(!received.locally_initiated);
    try std.testing.expect(received.fin);
    try std.testing.expectEqualStrings(
        "partial-complete",
        received.payload,
    );
}

fn writeDataFrame(out: []u8, payload: []const u8) !usize {
    const frame_type = try quic.varint.encodeInto(
        out,
        http3.FrameType.data,
    );
    const length = try quic.varint.encodeInto(
        out[frame_type.len..],
        payload.len,
    );
    const start = frame_type.len + length.len;
    if (payload.len > out.len - start) return error.BufferTooShort;
    @memcpy(out[start..][0..payload.len], payload);
    return start + payload.len;
}

fn sendDatagram(
    connection: *quic.one_rtt.Connection,
    session_id: webtransport.SessionId,
    payload: []const u8,
) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try (webtransport.Datagram{
        .session_id = session_id,
        .payload = payload,
    }).write(&encoded, std.testing.allocator);
    try connection.sendDatagram(encoded.items);
}
