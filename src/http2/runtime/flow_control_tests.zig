//! HTTP/2 DATA flow-control and receive-window tests.

const std = @import("std");
const forwarded_io = @import("../../internal/testing/forwarded_io.zig");
const native_protocol_io = @import("../../internal/testing/native_protocol_io.zig");
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

test "HTTP/2 padded DATA charges full frame payload to receive windows" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .initial_window_size = 4 },
        .recv_connection_window = .{ .value = 5 },
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    const padded_payload = [_]u8{ 2, 'o', 'k', 0, 0 };
    const padded_frame = http2.Frame{
        .header = .{
            .length = padded_payload.len,
            .frame_type = .data,
            .flags = 0x8, // PADDED
            .stream_id = 1,
        },
        .payload = &padded_payload,
    };

    try std.testing.expectError(error.FlowControlViolation, connection.receiveDataPayload(1, padded_frame));
    try std.testing.expectEqual(@as(i64, 5), connection.recv_connection_window.value);
    try std.testing.expectEqual(@as(i64, 4), (try connection.recvStreamWindow(1)).value);

    try (try connection.recvStreamWindow(1)).update(1);
    const data = try connection.receiveDataPayload(1, padded_frame);
    defer connection.releaseDataFrameBudget(data);
    try std.testing.expectEqualStrings("ok", data.data);
    try std.testing.expectEqual(@as(i64, 0), connection.recv_connection_window.value);
    try std.testing.expectEqual(@as(i64, 0), (try connection.recvStreamWindow(1)).value);
}

test "HTTP/2 empty DATA is legal while stream window is negative" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }
    connection.recv_connection_window.value = -7;
    const stream_window = try connection.recvStreamWindow(1);
    stream_window.value = -11;

    const data = try connection.receiveDataPayload(1, .{
        .header = .{
            .length = 0,
            .frame_type = .data,
            .flags = flag_end_stream,
            .stream_id = 1,
        },
        .payload = &.{},
    });
    defer connection.releaseDataFrameBudget(data);
    try std.testing.expectEqual(@as(usize, 0), data.data.len);
    try std.testing.expectEqual(@as(i64, -7), connection.recv_connection_window.value);
    try std.testing.expectEqual(@as(i64, -11), stream_window.value);
}

test "HTTP/2 final DATA returns connection credit without stream update" {
    try native_protocol_io.runStream(finalDataReturnsConnectionCreditWithoutStreamUpdate);
}

fn finalDataReturnsConnectionCreditWithoutStreamUpdate(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        delegate: std.Io,
        bytes: [32]u8 = undefined,
        len: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = @min(bytes.len, self.bytes.len - self.len);
            if (count == 0) return error.SocketUnconnected;
            @memcpy(self.bytes[self.len..][0..count], bytes[0..count]);
            self.len += count;
            return count;
        }
    };

    var writer: RecordingWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = RecordingWriter.write }),
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .recv_connection_window = .{ .value = 20_000 },
        .recv_connection_window_target = 65_535,
        .recv_stream_window_target = 65_535,
        .adaptive_window = bdp.Estimator.init(65_535, 1024 * 1024),
    };
    defer {
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
    }
    (try connection.recvStreamWindow(1)).value = 20_000;

    try connection.maybeReleaseReceivedCapacity(1, true);

    try std.testing.expectEqual(
        @as(usize, http2.FrameHeader.encoded_len + 4),
        writer.len,
    );
    const frame = try http2.Frame.parse(writer.bytes[0..writer.len]);
    const update = try http2.WindowUpdatePayload.parse(frame);
    try std.testing.expectEqual(@as(u31, 0), update.stream_id);
    try std.testing.expectEqual(@as(u31, 45_535), update.increment);
    try std.testing.expectEqual(
        @as(i64, 20_000),
        (try connection.recvStreamWindow(1)).value,
    );
}

test "HTTP/2 DATA send waits for WINDOW_UPDATE capacity" {
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

            while (true) {
                var headers = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
                defer headers.deinit(server_ptr.allocator);
                if (try connection.handleConnectionFrame(headers.frame)) continue;
                try std.testing.expectEqual(http2.FrameType.headers, headers.frame.header.frame_type);
                try std.testing.expectEqual(@as(u31, 1), headers.frame.header.stream_id);
                try std.testing.expect((headers.frame.header.flags & flag_end_stream) == 0);
                // This test deliberately bypasses the high-level request
                // parser, so mirror its stream reservation before using the
                // high-level response writer below.
                try connection.reservePeerStream(1);
                break;
            }

            var first = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http2.FrameType.data, first.frame.header.frame_type);
            const first_data = try http2.DataPayload.parse(first.frame);
            try std.testing.expectEqualStrings("hello", first_data.data);
            try std.testing.expect((first.frame.header.flags & flag_end_stream) == 0);

            // h2/hyper style senders park DATA behind flow control.  Once both
            // connection and stream credit are restored, the blocked request
            // can continue without the application retrying the send.
            try connection.sendWindowUpdate(0, 64);
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .window_update, 0, 1, &.{ 0, 0, 0, 64 });

            var second = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http2.FrameType.data, second.frame.header.frame_type);
            const second_data = try http2.DataPayload.parse(second.frame);
            try std.testing.expectEqualStrings(" world", second_data.data);
            try std.testing.expect((second.frame.header.flags & flag_end_stream) != 0);

            try connection.writeResponse(1, .{ .status = 200, .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    client.send_connection_window.value = 5;
    (try client.sendStreamWindow(1)).value = 5;

    var response = try client.request(.{
        .method = "POST",
        .path = "/flow-wait",
        .authority = "localhost",
        .body = "hello world",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);

    thread.join();
    if (shared.err) |err| return err;
}
