//! HTTP/2 GOAWAY boundary and stream-state classification tests.

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

test "HTTP/2 rejects unexpected SETTINGS ACK" {
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

    const ack = http2.Frame{
        .header = .{ .length = 0, .frame_type = .settings, .flags = flag_ack, .stream_id = 0 },
        .payload = &.{},
    };
    try std.testing.expectError(error.InvalidFrame, connection.handleConnectionFrame(ack));
    connection.awaiting_settings_ack = true;
    try std.testing.expect(try connection.handleConnectionFrame(ack));
    try std.testing.expect(!connection.awaiting_settings_ack);
    try std.testing.expectError(error.InvalidFrame, connection.handleConnectionFrame(ack));
}

test "HTTP/2 sendGoAway enforces non-increasing boundaries" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.validateLocalGoAway(7);
    connection.local_goaway_last_stream_id = 7;
    try connection.validateLocalGoAway(5);
    connection.local_goaway_last_stream_id = 5;
    try std.testing.expectError(error.InvalidFrame, connection.validateLocalGoAway(7));
    try std.testing.expectEqual(@as(?u31, 5), connection.local_goaway_last_stream_id);
}

test "HTTP/2 readGoAway records monotonic peer boundary" {
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
        connection.response_semantics.deinit(std.testing.allocator);
        connection.response_semantics_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.rememberResponseSemantics(
        1,
        "HEAD",
        null,
        .{},
    );
    try std.testing.expectEqual(@as(?usize, 0), connection.response_semantics_index.get(1));
    try std.testing.expect((connection.responseSemanticsFor(1, .{})).head);
    connection.forgetResponseSemantics(1);
    try std.testing.expectEqual(@as(usize, 0), connection.response_semantics_index.count());
    try std.testing.expect(!(connection.responseSemanticsFor(1, .{})).head);
    connection.forgetResponseSemantics(1);

    try connection.recordPeerGoAway(.{ .last_stream_id = 7, .error_code = .no_error, .debug_data = &.{} });
    try std.testing.expectEqual(@as(?u31, 7), connection.peer_goaway_last_stream_id);
    try std.testing.expect(!connection.peerGoAwayTooManyPings());
    try connection.recordPeerGoAway(.{ .last_stream_id = 5, .error_code = .enhance_your_calm, .debug_data = "too_many_pings" });
    try std.testing.expectEqual(@as(?u31, 5), connection.peer_goaway_last_stream_id);
    try std.testing.expect(connection.peerGoAwayTooManyPings());
    try connection.recordPeerGoAway(.{ .last_stream_id = 5, .error_code = .no_error, .debug_data = &.{} });
    try std.testing.expect(connection.peerGoAwayTooManyPings());
    try std.testing.expectError(error.InvalidFrame, connection.recordPeerGoAway(.{ .last_stream_id = 7, .error_code = .no_error, .debug_data = &.{} }));
    try std.testing.expectEqual(@as(?u31, 5), connection.peer_goaway_last_stream_id);
}

test "HTTP/2 stream idle classification follows initiator cursors" {
    var server_connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .last_peer_client_stream_id = 3,
    };
    defer server_connection.push_state.deinit(std.testing.allocator);

    try std.testing.expect(!server_connection.streamIsIdle(1));
    try std.testing.expect(!server_connection.streamIsIdle(3));
    try std.testing.expect(server_connection.streamIsIdle(5));
    try std.testing.expect(server_connection.streamIsIdle(2));
    const reserved = try server_connection.push_state.reserveLocal(
        std.testing.allocator,
    );
    try std.testing.expectEqual(@as(u31, 2), reserved);
    try std.testing.expect(!server_connection.streamIsIdle(2));
    try std.testing.expect(server_connection.streamIsIdle(4));

    var client_connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .next_client_stream_id = 5,
    };
    try std.testing.expect(!client_connection.streamIsIdle(1));
    try std.testing.expect(!client_connection.streamIsIdle(3));
    try std.testing.expect(client_connection.streamIsIdle(5));
    try std.testing.expect(client_connection.streamIsIdle(2));
}

test "HTTP/2 continues after RST_STREAM on a half-closed request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest();
            try std.testing.expectEqual(@as(u31, 1), request.stream_id);
            request.deinit(server_ptr.allocator);

            // readRequest must consume the intervening reset rather than
            // terminating the connection before the next request stream.
            var next_request = try connection.readRequest();
            defer next_request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 3), next_request.stream_id);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const first = try client.sendCompleteRequest(.{
        .path = "/reset",
        .authority = "localhost",
    });
    try client.sendResetStream(first.stream_id, .cancel);
    const second = try client.sendCompleteRequest(.{
        .path = "/after-reset",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u31, 3), second.stream_id);

    thread.join();
    if (shared.err) |err| return err;
}
