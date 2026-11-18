//! HTTP/2 SETTINGS, capacity, frame-size, and header-limit tests.

const std = @import("std");
const http2 = @import("../mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const Client = runtime.Client;
const ClientDuplexStream = runtime.ClientDuplexStream;
const ConcurrentServeResult = runtime.ConcurrentServeResult;
const Connection = runtime.Connection;
const DuplexHeaderBlockSlot = runtime.DuplexHeaderBlockSlot;
const Error = runtime.Error;
const ExtendedConnectResponse = runtime.ExtendedConnectResponse;
const GoAwayRetryDisposition = runtime.GoAwayRetryDisposition;
const Limits = runtime.Limits;
const OwnedFrameSlot = runtime.OwnedFrameSlot;
const OwnedRequest = runtime.OwnedRequest;
const OwnedResponse = runtime.OwnedResponse;
const RequestOptions = runtime.RequestOptions;
const ResponseOptions = runtime.ResponseOptions;
const ResponseTimeoutError = runtime.ResponseTimeoutError;
const RetainedFrameSlot = runtime.RetainedFrameSlot;
const Server = runtime.Server;
const ServerDuplexStream = runtime.ServerDuplexStream;
const StapledOcspPolicy = runtime.StapledOcspPolicy;
const StreamingRequest = runtime.StreamingRequest;
const StreamingResponse = runtime.StreamingResponse;
const StreamingResponseHead = runtime.StreamingResponseHead;
const appendAutomaticDateHeaderValue = runtime.appendAutomaticDateHeaderValue;
const appendFrameBytes = runtime.appendFrameBytes;
const bdp = runtime.bdp;
const builtin = runtime.builtin;
const client_authority = runtime.client_authority;
const client_duplex_owner = runtime.client_duplex_owner;
const concurrent = runtime.concurrent;
const containsHttpToken = runtime.containsHttpToken;
const data_frame_budget = runtime.data_frame_budget;
const decodeOwnedHeaders = runtime.decodeOwnedHeaders;
const default_flow_window = runtime.default_flow_window;
const default_max_frame_size = runtime.default_max_frame_size;
const encodeFrameHeader = runtime.encodeFrameHeader;
const endpoint_host = runtime.endpoint_host;
const expectClientConnectionErrorGoAway = runtime.expectClientConnectionErrorGoAway;
const expectServerInitialConnectionErrorGoAway = runtime.expectServerInitialConnectionErrorGoAway;
const findHeader = runtime.findHeader;
const flag_ack = runtime.flag_ack;
const flag_end_headers = runtime.flag_end_headers;
const flag_end_stream = runtime.flag_end_stream;
const freeHeaders = runtime.freeHeaders;
const freeStackFirstHeaderFieldBuffer = runtime.freeStackFirstHeaderFieldBuffer;
const graceful_shutdown_ping_payload = runtime.graceful_shutdown_ping_payload;
const host_connect = runtime.host_connect;
const http1_runtime = runtime.http1_runtime;
const http_date = runtime.http_date;
const max_flow_window = runtime.max_flow_window;
const max_max_frame_size = runtime.max_max_frame_size;
const outbound_headers = runtime.outbound_headers;
const peer_metadata = runtime.peer_metadata;
const push = runtime.push;
const queueTestPendingRequest = runtime.queueTestPendingRequest;
const readExact = runtime.readExact;
const readFrame = runtime.readFrame;
const settingsForLimits = runtime.settingsForLimits;
const stackFirstHeaderFieldBuffer = runtime.stackFirstHeaderFieldBuffer;
const stripSuccessfulConnectContentLength = runtime.stripSuccessfulConnectContentLength;
const test_socket = runtime.test_socket;
const testing = runtime.testing;
const tls_stream = runtime.tls_stream;
const vail = runtime.vail;
const validateHeaderBlock = runtime.validateHeaderBlock;
const validateHeaderListSize = runtime.validateHeaderListSize;
const validateLocalLimits = runtime.validateLocalLimits;
const validateOutgoingResponseBodyForStatus = runtime.validateOutgoingResponseBodyForStatus;
const validateResponseBodyForStatus = runtime.validateResponseBodyForStatus;
const verifiedTlsClientOptions = runtime.verifiedTlsClientOptions;
const webtransport_settings = runtime.webtransport_settings;
const writeAll = runtime.writeAll;
const writeFrame = runtime.writeFrame;
const writeInitialSettings = runtime.writeInitialSettings;

test "HTTP/2 sendWindowUpdate rejects idle streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    // h2 only releases capacity for streams that exist in the state machine.
    // Sending WINDOW_UPDATE on an idle stream is a protocol error, so the
    // helper refuses before it mutates receive-window bookkeeping or writes.
    try std.testing.expectError(error.InvalidStreamId, connection.sendWindowUpdate(1, 1));
    try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
}

test "HTTP/2 local initial window config seeds receive stream windows" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .initial_window_size = 1024 },
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(i64, 1024), (try connection.recvStreamWindow(1)).value);
    try std.testing.expectEqual(@as(?usize, 0), connection.recv_stream_window_index.get(1));
}

test "HTTP/2 peer max concurrent streams limits locally opened streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .peer_max_concurrent_streams = 1,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activeLocalStreamCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activePeerStreamCount(),
    );
    try std.testing.expect(!connection.peerExtendedConnectEnabled());

    const first = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 1), first);
    try std.testing.expectEqual(@as(usize, 1), connection.active_local_streams.items.len);
    try std.testing.expectEqual(@as(?usize, 0), connection.active_local_index.get(first));
    try std.testing.expectEqual(
        @as(?u32, 0),
        connection.availableLocalStreamCapacity(),
    );
    try std.testing.expectError(error.FlowControlBlocked, connection.reserveNextClientStreamId());
    try std.testing.expectEqual(@as(u31, 3), connection.next_client_stream_id);

    connection.releaseLocalStream(first);
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    const second = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 3), second);
    try std.testing.expectEqual(@as(usize, 1), connection.active_local_streams.items.len);
    try std.testing.expectEqual(@as(?usize, 0), connection.active_local_index.get(second));
    connection.releaseLocalStream(second);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_index.count());
    connection.releaseLocalStream(second);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);

    const third = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 5), third);
    try std.testing.expectError(error.ConnectionGoAway, connection.handleGoAwayForStream(third, .{
        .last_stream_id = 3,
        .error_code = .no_error,
        .debug_data = &.{},
    }));
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
    try std.testing.expectError(error.InvalidFrame, connection.handleGoAwayForStream(1, .{
        .last_stream_id = 5,
        .error_code = .no_error,
        .debug_data = &.{},
    }));
}

test "HTTP/2 available local stream capacity matches priority reservations" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .peer_max_concurrent_streams = 2,
    };
    defer {
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
    }

    try std.testing.expectEqual(
        @as(?u32, 2),
        connection.availableLocalStreamCapacity(),
    );
    try connection.priority_state.reserveIdleRequest(
        allocator,
        3,
        connection.activeLocalStreamCount(),
        connection.peerMaxConcurrentStreams(),
        connection.limits.max_idle_priority_updates,
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    try connection.priority_state.reserveIdleRequest(
        allocator,
        connection.next_client_stream_id,
        connection.activeLocalStreamCount(),
        connection.peerMaxConcurrentStreams(),
        connection.limits.max_idle_priority_updates,
    );
    // The next request consumes its existing reservation rather than charging
    // the peer limit twice. One later unreserved stream also still fits.
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    const first = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 1), first);
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    const second = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 3), second);
    try std.testing.expectEqual(
        @as(?u32, 0),
        connection.availableLocalStreamCapacity(),
    );
}

test "HTTP/2 public peer capabilities track SETTINGS updates" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn writeSettingsUpdate(
            self: *@This(),
            stream: net.Stream,
            settings: []const http2.Setting,
        ) !void {
            var payload: std.ArrayList(u8) = .empty;
            defer payload.deinit(self.allocator);
            try http2.writeSettings(&payload, self.allocator, settings);
            try writeFrame(
                self.allocator,
                self.io,
                stream,
                .settings,
                0,
                0,
                payload.items,
            );
        }

        fn waitForSettingsAckAndPing(
            self: *@This(),
            stream: net.Stream,
            expected_ping: [8]u8,
        ) !void {
            var saw_settings_ack = false;
            var saw_ping = false;
            while (!saw_settings_ack or !saw_ping) {
                var frame = try readFrame(
                    self.allocator,
                    self.io,
                    stream,
                    .{},
                );
                defer frame.deinit(self.allocator);
                switch (frame.frame.header.frame_type) {
                    .settings => {
                        try std.testing.expect(
                            frame.frame.header.flags & flag_ack != 0,
                        );
                        saw_settings_ack = true;
                    },
                    .ping => {
                        try std.testing.expectEqual(
                            @as(u8, 0),
                            frame.frame.header.flags & flag_ack,
                        );
                        const ping = try http2.PingPayload.parse(frame.frame);
                        try std.testing.expectEqualSlices(
                            u8,
                            &expected_ping,
                            &ping.data,
                        );
                        try writeFrame(
                            self.allocator,
                            self.io,
                            stream,
                            .ping,
                            flag_ack,
                            0,
                            &ping.data,
                        );
                        saw_ping = true;
                    },
                    else => return error.UnexpectedFrame,
                }
            }
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(self.io, stream, &preface);
            try http2.validateClientPreface(&preface);

            var client_settings = try readFrame(
                self.allocator,
                self.io,
                stream,
                .{},
            );
            defer client_settings.deinit(self.allocator);
            try std.testing.expectEqual(
                http2.FrameType.settings,
                client_settings.frame.header.frame_type,
            );
            try std.testing.expectEqual(
                @as(u8, 0),
                client_settings.frame.header.flags & flag_ack,
            );

            try self.writeSettingsUpdate(stream, &.{
                .{
                    .id = .max_concurrent_streams,
                    .value = 3,
                },
                // RFC 9113 permits a server to make its effective zero value
                // explicit; the client must reject only value 1.
                .{ .id = .enable_push, .value = 0 },
            });
            try writeFrame(
                self.allocator,
                self.io,
                stream,
                .settings,
                flag_ack,
                0,
                &.{},
            );
            var initial_ack = try readFrame(
                self.allocator,
                self.io,
                stream,
                .{},
            );
            defer initial_ack.deinit(self.allocator);
            try std.testing.expectEqual(
                http2.FrameType.settings,
                initial_ack.frame.header.frame_type,
            );
            try std.testing.expect(
                initial_ack.frame.header.flags & flag_ack != 0,
            );

            try self.writeSettingsUpdate(stream, &.{
                .{ .id = .max_concurrent_streams, .value = 1 },
                .{ .id = .enable_connect_protocol, .value = 1 },
            });
            const first_ping = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
            try self.waitForSettingsAckAndPing(stream, first_ping);

            try self.writeSettingsUpdate(stream, &.{.{
                .id = .max_concurrent_streams,
                .value = 4,
            }});
            const second_ping = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
            try self.waitForSettingsAckAndPing(stream, second_ping);
        }
    };

    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{},
    );
    defer client.close();
    try std.testing.expectEqual(
        @as(?u32, 3),
        client.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 3),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(!client.peerExtendedConnectEnabled());

    const first_ping = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try std.testing.expectEqualSlices(u8, &first_ping, &(try client.ping(first_ping)));
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(client.peerExtendedConnectEnabled());

    const second_ping = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    try std.testing.expectEqualSlices(
        u8,
        &second_ping,
        &(try client.ping(second_ping)),
    );
    try std.testing.expectEqual(
        @as(?u32, 4),
        client.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 4),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(client.peerExtendedConnectEnabled());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client stream id allocation detects overflow" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .next_client_stream_id = std.math.maxInt(u31),
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    // Rust h2's StreamId::next_id returns an overflow error instead of wrapping
    // once the 31-bit stream-id space is exhausted.  Keep the same invariant so
    // long-lived clients cannot wrap to an invalid/previously-used stream id.
    try std.testing.expectError(error.InvalidStreamId, connection.reserveNextClientStreamId());
    try std.testing.expectEqual(@as(u31, std.math.maxInt(u31)), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
}

test "HTTP/2 active stream releases skip empty indexes" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.push_state.deinit(std.testing.allocator);
        connection.priority_state.deinit(std.testing.allocator);
        connection.response_semantics.deinit(std.testing.allocator);
        connection.response_semantics_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    // Release paths are frequently called from reset/cleanup code for streams
    // that may already be gone.  With empty indexes they should stay as cheap
    // no-ops and avoid probing the hash maps.
    try std.testing.expect(!connection.removeActiveLocalStream(1));
    try std.testing.expect(!connection.removeActivePeerStream(1));
    connection.releaseLocalStream(1);
    connection.releasePeerStream(1);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_index.count());
    try std.testing.expectEqual(@as(usize, 0), connection.active_peer_index.count());
}

test "HTTP/2 local max concurrent streams limits peer opened streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_concurrent_streams = 1 },
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.locally_reset_streams.deinit(std.testing.allocator);
        connection.locally_reset_stream_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.reservePeerStream(1);
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);
    try std.testing.expectEqual(@as(?usize, 0), connection.active_peer_index.get(1));
    try std.testing.expectError(error.FlowControlViolation, connection.reservePeerStream(3));
    connection.releasePeerStream(1);
    try connection.reservePeerStream(3);
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);

    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(3, .{
        .status = 204,
        .body = "must not send",
    }));
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);
    try std.testing.expectError(error.FlowControlViolation, connection.reservePeerStream(5));

    connection.releasePeerStream(3);
    try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
    try connection.reservePeerStream(5);
    try std.testing.expectError(error.InvalidStatus, connection.rejectExtendedConnect(5, 200, &.{}));
    try std.testing.expectError(
        error.InvalidContentLength,
        connection.rejectExtendedConnectWithBody(
            5,
            304,
            &.{},
            "not allowed",
            &.{},
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);
    connection.releasePeerStream(5);
    try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
}

test "HTTP/2 refused request advances observed but not processed boundary" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{
            .max_concurrent_streams = 1,
            .max_reset_stream_history = 0,
        },
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
    }

    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.admitted,
        try connection.claimPeerRequestStream(1),
    );
    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.refused,
        try connection.claimPeerRequestStream(3),
    );
    try std.testing.expectEqual(@as(u31, 3), connection.last_peer_client_stream_id);
    try std.testing.expectEqual(@as(u31, 1), connection.lastPeerProcessedStreamId());
    connection.releasePeerStream(1);
    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.admitted,
        try connection.claimPeerRequestStream(5),
    );
    try std.testing.expectEqual(@as(u31, 5), connection.lastPeerProcessedStreamId());
}

test "HTTP/2 SETTINGS_MAX_FRAME_SIZE controls outbound DATA splitting" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        data_lengths: [4]usize = [_]usize{0} ** 4,
        data_count: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);
            const limits = Limits{ .max_frame_payload = 64 * 1024, .max_body_bytes = 128 * 1024, .max_frame_size = 20_000 };

            var preface_buf: [http2.connection_preface.len]u8 = undefined;
            try readExact(shared.io, stream, &preface_buf);
            try http2.validateClientPreface(&preface_buf);

            var client_settings = try readFrame(shared.allocator, shared.io, stream, limits);
            defer client_settings.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_settings.frame.header.frame_type);
            try std.testing.expectEqual(@as(u8, 0), client_settings.frame.header.flags & flag_ack);

            var settings_payload: std.ArrayList(u8) = .empty;
            defer settings_payload.deinit(shared.allocator);
            try http2.writeSettings(&settings_payload, shared.allocator, &.{
                .{ .id = .max_frame_size, .value = 20_000 },
            });
            try writeFrame(shared.allocator, shared.io, stream, .settings, 0, 0, settings_payload.items);
            try writeFrame(shared.allocator, shared.io, stream, .settings, flag_ack, 0, &.{});

            var client_ack = try readFrame(shared.allocator, shared.io, stream, limits);
            defer client_ack.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_ack.frame.header.frame_type);
            try std.testing.expect((client_ack.frame.header.flags & flag_ack) != 0);

            var request_stream_id: u31 = 0;
            while (true) {
                var frame = try readFrame(shared.allocator, shared.io, stream, limits);
                defer frame.deinit(shared.allocator);
                switch (frame.frame.header.frame_type) {
                    .headers => {
                        request_stream_id = frame.frame.header.stream_id;
                    },
                    .data => {
                        const data = try http2.DataPayload.parse(frame.frame);
                        try std.testing.expect(shared.data_count < shared.data_lengths.len);
                        shared.data_lengths[shared.data_count] = data.data.len;
                        shared.data_count += 1;
                        if ((frame.frame.header.flags & flag_end_stream) != 0) break;
                    },
                    else => {},
                }
            }

            try std.testing.expectEqual(@as(u31, 1), request_stream_id);
            var response_block: std.ArrayList(u8) = .empty;
            defer response_block.deinit(shared.allocator);
            try http2.Hpack.encodeLiteralBlock(&response_block, shared.allocator, &.{
                .{ .name = ":status", .value = "200" },
            });
            try writeFrame(shared.allocator, shared.io, stream, .headers, flag_end_headers | flag_end_stream, request_stream_id, response_block.items);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const body = try allocator.alloc(u8, 45_000);
    defer allocator.free(body);
    @memset(body, 'x');

    var client = try Client.connect(allocator, io, listener.socket.address, .{ .max_frame_payload = 64 * 1024, .max_body_bytes = 128 * 1024 });
    defer client.close();
    var response = try client.request(.{
        .method = "POST",
        .path = "/split-data",
        .authority = "localhost",
        .body = body,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqual(@as(usize, 3), shared.data_count);
    try std.testing.expectEqual(@as(usize, 20_000), shared.data_lengths[0]);
    try std.testing.expectEqual(@as(usize, 20_000), shared.data_lengths[1]);
    try std.testing.expectEqual(@as(usize, 5_000), shared.data_lengths[2]);
}

test "HTTP/2 readFrame enforces inbound SETTINGS_MAX_FRAME_SIZE before payload read" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);
            try std.testing.expectError(error.MessageTooLarge, readFrame(shared.allocator, shared.io, stream, .{
                .max_frame_payload = 64 * 1024,
                .max_frame_size = default_max_frame_size,
            }));
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    // Send only the header.  A compliant receiver can reject this frame from
    // the advertised size alone and must not allocate or block waiting for the
    // oversized payload bytes.
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    try (http2.FrameHeader{
        .length = @intCast(default_max_frame_size + 1),
        .frame_type = .data,
        .flags = 0,
        .stream_id = 1,
    }).write(&raw, allocator);
    try writeAll(io, stream, raw.items);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime rejects invalid local SETTINGS limits" {
    if (@sizeOf(usize) > @sizeOf(u32)) {
        const beyond_settings_value = @as(usize, std.math.maxInt(u32)) + 1;
        try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
            .header_table_size = beyond_settings_value,
        }));
        try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
            .max_header_list_size = beyond_settings_value,
        }));
    }
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .initial_window_size = @as(u32, std.math.maxInt(i31)) + 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .initial_connection_window_size = @as(u32, @intCast(default_flow_window)) - 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .initial_connection_window_size = @as(u32, std.math.maxInt(i31)) + 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_frame_size = default_max_frame_size - 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_frame_size = max_max_frame_size + 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_idle_priority_updates = 0,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_pending_ping_frames = 0,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .reset_stream_duration = .fromNanoseconds(-1),
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .adaptive_window = true,
        .adaptive_window_max = 1024,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .adaptive_window = true,
        .adaptive_window_max = @as(u32, std.math.maxInt(i31)) + 1,
    }));
    try validateLocalLimits(.{
        .header_table_size = std.math.maxInt(u32),
        .initial_window_size = std.math.maxInt(i31),
        .initial_connection_window_size = std.math.maxInt(i31),
        .max_frame_size = max_max_frame_size,
        .max_header_list_size = std.math.maxInt(u32),
    });
}

test "HTTP/2 local SETTINGS preserve maximum 32-bit header limits" {
    const settings = try settingsForLimits(.{
        .header_table_size = std.math.maxInt(u32),
        .max_header_list_size = std.math.maxInt(u32),
    }, .server);
    var header_table_size: ?u32 = null;
    var header_list_size: ?u32 = null;
    for (settings.buf[0..settings.count]) |setting| switch (setting.id) {
        .header_table_size => header_table_size = setting.value,
        .max_header_list_size => header_list_size = setting.value,
        else => {},
    };
    try std.testing.expectEqual(
        @as(?u32, std.math.maxInt(u32)),
        header_table_size,
    );
    try std.testing.expectEqual(
        @as(?u32, std.math.maxInt(u32)),
        header_list_size,
    );
}

test "HTTP/2 constructors reject unrepresentable SETTINGS before I/O" {
    if (@sizeOf(usize) <= @sizeOf(u32)) return;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const unreachable_address = net.IpAddress{ .ip4 = .loopback(1) };
    const beyond_settings_value = @as(usize, std.math.maxInt(u32)) + 1;

    try std.testing.expectError(
        error.InvalidSetting,
        Server.listen(allocator, io, unreachable_address, .{
            .header_table_size = beyond_settings_value,
        }),
    );
    try std.testing.expectError(
        error.InvalidSetting,
        Client.connect(allocator, io, unreachable_address, .{
            .max_header_list_size = beyond_settings_value,
        }),
    );
}

test "HTTP/2 runtime validates SETTINGS frame-size and window bounds" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }
    try std.testing.expect(!connection.peerPushEnabled());

    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = default_max_frame_size - 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = max_max_frame_size + 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .initial_window_size, .value = @as(u32, std.math.maxInt(i31)) + 1 },
    }));
    try connection.applySettings(&.{
        .{ .id = .enable_push, .value = 0 },
        .{ .id = .no_rfc7540_priorities, .value = 1 },
    });
    try std.testing.expect(!connection.peer_enable_push);
    try std.testing.expect(connection.peer_no_rfc7540_priorities);
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .enable_push, .value = 1 },
    }));
    try std.testing.expect(!connection.peer_enable_push);

    try connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = 32_768 },
        .{ .id = .max_concurrent_streams, .value = 7 },
        .{ .id = .header_table_size, .value = 128 },
    });
    try std.testing.expectEqual(@as(usize, 32_768), connection.peer_max_frame_size);
    try std.testing.expectEqual(
        @as(?u32, 7),
        connection.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(@as(usize, 128), connection.hpack_encoder.dynamic_table.size_limit);
    try std.testing.expect(connection.peer_no_rfc7540_priorities);

    // A peer setting is permission, not an instruction to retain up to 4 GiB
    // of encoder state. The default local ceiling remains 4 KiB.
    try connection.applySettings(&.{.{
        .id = .header_table_size,
        .value = std.math.maxInt(u32),
    }});
    try std.testing.expectEqual(
        http2.Hpack.default_dynamic_table_size,
        connection.hpack_encoder.dynamic_table.size_limit,
    );

    try connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 0 },
    });
    try std.testing.expect(!connection.peerExtendedConnectEnabled());
    try connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 1 },
    });
    try std.testing.expect(connection.peerExtendedConnectEnabled());
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 0 },
    }));
    try std.testing.expect(connection.peerExtendedConnectEnabled());
    try connection.applySettings(&.{
        .{ .id = .no_rfc7540_priorities, .value = 1 },
    });
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .no_rfc7540_priorities, .value = 0 },
    }));

    var server_connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        server_connection.send_stream_windows.deinit(std.testing.allocator);
        server_connection.recv_stream_windows.deinit(std.testing.allocator);
        server_connection.hpack_decoder.deinit(std.testing.allocator);
        server_connection.hpack_encoder.deinit(std.testing.allocator);
    }
    try server_connection.applySettings(&.{.{ .id = .enable_push, .value = 0 }});
    try std.testing.expect(!server_connection.peer_enable_push);
    try server_connection.applySettings(&.{.{ .id = .enable_push, .value = 1 }});
    try std.testing.expect(server_connection.peer_enable_push);
    try std.testing.expectError(error.InvalidSetting, server_connection.applySettings(&.{
        .{ .id = .enable_push, .value = 2 },
    }));
}

test "HTTP/2 runtime applies independent local HPACK table limits" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{
            .header_table_size = 32,
            .max_encoder_table_size = 128,
        },
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }
    connection.applyLocalLimits();
    try std.testing.expectEqual(@as(usize, 32), connection.hpack_decoder.max_dynamic_table_size);
    try std.testing.expectEqual(
        @as(usize, 128),
        connection.hpack_encoder.dynamic_table.size_limit,
    );
    try connection.applySettings(&.{.{
        .id = .header_table_size,
        .value = 1024,
    }});
    try std.testing.expectEqual(
        @as(usize, 128),
        connection.hpack_encoder.dynamic_table.size_limit,
    );

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(std.testing.allocator);
    try block.appendSlice(std.testing.allocator, &.{ 0x3f, 0x02 }); // Dynamic table size update value 33 > local limit.
    try std.testing.expectError(error.InvalidEncoding, connection.hpack_decoder.decodeBlock(std.testing.allocator, block.items));
}

test "HTTP/2 runtime enforces header list size limits" {
    const allocator = std.testing.allocator;

    const oversized = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "x-large", .value = "0123456789" },
    };
    try std.testing.expectError(error.MessageTooLarge, validateHeaderListSize(&oversized, 172));
    try validateHeaderListSize(&oversized, 173);

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &oversized);
    var decoder = http2.Hpack.Decoder{};
    defer decoder.deinit(allocator);
    try std.testing.expectError(error.MessageTooLarge, decodeOwnedHeaders(allocator, block.items, .{
        .max_header_fields = 16,
        .max_header_list_size = 120,
    }, &decoder));
    var no_alloc_block: std.ArrayList(u8) = .empty;
    defer no_alloc_block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(
        &no_alloc_block,
        allocator,
        &.{.{
            .name = "authorization",
            .value = "compressible-value",
        }},
    );
    var no_alloc_decoder = http2.Hpack.Decoder{};
    defer no_alloc_decoder.deinit(allocator);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        decodeOwnedHeaders(
            no_alloc.allocator(),
            no_alloc_block.items,
            .{
                .max_header_fields = 16,
                .max_header_list_size = 1,
            },
            &no_alloc_decoder,
        ),
    );
    try std.testing.expect(!no_alloc.has_induced_failure);

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }
    try connection.applySettings(&.{.{ .id = .max_header_list_size, .value = 120 }});
    try std.testing.expectEqual(@as(usize, 120), connection.peer_max_header_list_size);
    try std.testing.expectError(error.MessageTooLarge, connection.writeHeaders(1, &oversized, true));
}

test "HTTP/2 runtime decodes owned headers into one allocation" {
    const allocator = std.testing.allocator;
    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-first", .value = "one", .never_index = true },
        .{ .name = "x-second", .value = "two", .never_index = true },
    };
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &fields);
    var decoder = http2.Hpack.Decoder{};
    defer decoder.deinit(allocator);
    const cloned = try decodeOwnedHeaders(
        allocator,
        block.items,
        .{ .max_header_fields = 8 },
        &decoder,
    );
    defer freeHeaders(allocator, cloned);

    try std.testing.expect(cloned[0].block_storage != null);
    try std.testing.expect(cloned[1].block_storage == null);
    try std.testing.expectEqual(
        @intFromPtr(cloned.ptr),
        @intFromPtr(cloned[0].block_storage.?.ptr),
    );
    try std.testing.expectEqualStrings("x-second", cloned[2].name);
    const storage = cloned[0].block_storage.?;
    for (cloned) |field| {
        try std.testing.expect(@intFromPtr(field.name.ptr) >= @intFromPtr(storage.ptr));
        try std.testing.expect(@intFromPtr(field.value.ptr) >= @intFromPtr(storage.ptr));
        try std.testing.expect(
            @intFromPtr(field.value.ptr) + field.value.len <=
                @intFromPtr(storage.ptr) + storage.len,
        );
    }

    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    var tracked_decoder = http2.Hpack.Decoder{};
    defer tracked_decoder.deinit(tracking.allocator());
    const before = tracking.allocations;
    const tracked_headers = try decodeOwnedHeaders(
        tracking.allocator(),
        block.items,
        .{ .max_header_fields = 8 },
        &tracked_decoder,
    );
    defer freeHeaders(tracking.allocator(), tracked_headers);
    // The plan list stays on the stack; the final fields and strings share one
    // aligned allocation for a static/literal application result.
    try std.testing.expectEqual(before + 1, tracking.allocations);
}

test "HTTP/2 runtime advertises configured initial SETTINGS" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        header_table_size: ?u32 = null,
        initial_window_size: ?u32 = null,
        max_concurrent_streams: ?u32 = null,
        max_frame_size: ?u32 = null,
        max_header_list_size: ?u32 = null,
        enable_push: ?u32 = null,
        enable_connect_protocol: ?u32 = null,
        no_rfc7540_priorities: ?u32 = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var frame = try readFrame(shared.allocator, shared.io, stream, .{});
            defer frame.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, frame.frame.header.frame_type);
            const settings = try http2.parseSettings(shared.allocator, frame.frame.payload);
            defer shared.allocator.free(settings);
            for (settings) |setting| switch (setting.id) {
                .header_table_size => shared.header_table_size = setting.value,
                .initial_window_size => shared.initial_window_size = setting.value,
                .max_concurrent_streams => shared.max_concurrent_streams = setting.value,
                .max_frame_size => shared.max_frame_size = setting.value,
                .max_header_list_size => shared.max_header_list_size = setting.value,
                .enable_push => shared.enable_push = setting.value,
                .enable_connect_protocol => shared.enable_connect_protocol = setting.value,
                .no_rfc7540_priorities => shared.no_rfc7540_priorities = setting.value,
                else => {},
            };
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeInitialSettings(allocator, io, stream, .{
        .header_table_size = 1024,
        .initial_window_size = 70_000,
        .max_concurrent_streams = 11,
        .max_frame_size = 20_000,
        .max_header_list_size = 4096,
        .enable_connect_protocol = true,
        .no_rfc7540_priorities = true,
    }, .client);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(?u32, 1024), shared.header_table_size);
    try std.testing.expectEqual(@as(?u32, 70_000), shared.initial_window_size);
    try std.testing.expectEqual(@as(?u32, 11), shared.max_concurrent_streams);
    try std.testing.expectEqual(@as(?u32, 20_000), shared.max_frame_size);
    try std.testing.expectEqual(@as(?u32, 4096), shared.max_header_list_size);
    try std.testing.expectEqual(@as(?u32, 0), shared.enable_push);
    try std.testing.expectEqual(@as(?u32, 1), shared.enable_connect_protocol);
    try std.testing.expectEqual(
        @as(?u32, 1),
        shared.no_rfc7540_priorities,
    );
}
