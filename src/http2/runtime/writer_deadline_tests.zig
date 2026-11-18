//! HTTP/2 request/response writer deadline and committed-prefix tests.

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

test "HTTP/2 request writer deadline reports committed flow-control prefix" {
    const allocator = std.testing.allocator;
    const payload = "hello world";

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
        allow_credit: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            const deadline = std.Io.Clock.Timestamp.fromNow(
                shared.server.io,
                .{ .raw = .fromSeconds(2), .clock = .awake },
            );

            while (true) {
                var frame = try connection.readOwnedFrameWithDeadline(
                    deadline,
                );
                defer frame.deinit(shared.server.allocator);
                if (try connection.handleConnectionFrame(frame.frame)) {
                    continue;
                }
                try std.testing.expectEqual(
                    http2.FrameType.headers,
                    frame.frame.header.frame_type,
                );
                try std.testing.expectEqual(@as(u31, 1), frame.frame.header.stream_id);
                try std.testing.expect(
                    (frame.frame.header.flags & flag_end_stream) == 0,
                );
                try connection.addActivePeerStream(1);
                break;
            }

            var first = try connection.readOwnedFrameWithDeadline(deadline);
            defer first.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                http2.FrameType.data,
                first.frame.header.frame_type,
            );
            const first_data = try http2.DataPayload.parse(first.frame);
            try std.testing.expectEqualStrings("hello", first_data.data);
            try std.testing.expect(
                (first.frame.header.flags & flag_end_stream) == 0,
            );

            try shared.allow_credit.wait(shared.server.io);
            const increment = [_]u8{ 0, 0, 0, 64 };
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .window_update,
                0,
                0,
                &increment,
            );
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .window_update,
                0,
                1,
                &increment,
            );

            var second = try connection.readOwnedFrameWithDeadline(deadline);
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                http2.FrameType.data,
                second.frame.header.frame_type,
            );
            const second_data = try http2.DataPayload.parse(second.frame);
            try std.testing.expectEqualStrings(" world", second_data.data);
            try std.testing.expect(
                (second.frame.header.flags & flag_end_stream) != 0,
            );
            try connection.writeResponse(1, .{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.allow_credit.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    var writer = try client.startRequest(.{
        .path = "/deadline-upload",
        .authority = "localhost",
        .body_length = payload.len,
    });
    defer writer.deinit();
    client.send_connection_window.value = 5;
    (try client.sendStreamWindow(1)).value = 5;

    try std.testing.expectError(
        error.Timeout,
        writer.finishDataWithDeadline(payload, .{
            .raw = .zero,
            .clock = .real,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), writer.committedBytes());
    try std.testing.expectEqual(@as(i64, 5), client.send_connection_window.value);
    try std.testing.expectEqual(@as(i64, 5), (try client.sendStreamWindow(1)).value);

    try std.testing.expectError(
        error.Timeout,
        writer.writeWithTimeout(payload, .fromMilliseconds(80)),
    );
    try std.testing.expectEqual(@as(usize, 5), writer.committedBytes());
    try std.testing.expectEqual(@as(i64, 0), client.send_connection_window.value);
    try std.testing.expectEqual(@as(i64, 0), (try client.sendStreamWindow(1)).value);

    shared.allow_credit.set(io);
    try writer.finishData(payload[writer.committedBytes()..]);
    try std.testing.expectEqual(payload.len, writer.committedBytes());

    var response = try writer.readResponse();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 response writer deadline reports committed flow-control prefix" {
    const allocator = std.testing.allocator;
    const payload = "hello world";

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
        timeout_done: std.Io.Event = .unset,
        allow_retry: std.Io.Event = .unset,
        committed_after_timeout: usize = 0,
        connection_window_after_timeout: i64 = -1,
        stream_window_after_timeout: i64 = -1,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
                shared.timeout_done.set(shared.server.io);
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);

            var writer = try connection.startResponse(request.stream_id, .{
                .headers = &.{.{
                    .name = "content-length",
                    .value = "11",
                }},
            });
            defer writer.deinit();
            connection.send_connection_window.value = 5;
            (try connection.sendStreamWindow(request.stream_id)).value = 5;

            try std.testing.expectError(
                error.Timeout,
                writer.finishDataWithDeadline(payload, .{
                    .raw = .zero,
                    .clock = .real,
                }),
            );
            try std.testing.expectEqual(@as(usize, 0), writer.committedBytes());
            try std.testing.expectEqual(
                @as(i64, 5),
                connection.send_connection_window.value,
            );
            try std.testing.expectEqual(
                @as(i64, 5),
                (try connection.sendStreamWindow(request.stream_id)).value,
            );

            try std.testing.expectError(
                error.Timeout,
                writer.finishDataWithTimeout(payload, .fromMilliseconds(80)),
            );
            shared.committed_after_timeout = writer.committedBytes();
            shared.connection_window_after_timeout =
                connection.send_connection_window.value;
            shared.stream_window_after_timeout =
                (try connection.sendStreamWindow(request.stream_id)).value;
            shared.timeout_done.set(shared.server.io);

            try shared.allow_retry.wait(shared.server.io);
            try writer.finishData(payload[writer.committedBytes()..]);
            try std.testing.expectEqual(payload.len, writer.committedBytes());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.allow_retry.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const pending = try client.sendCompleteRequest(.{
        .path = "/deadline-response",
        .authority = "localhost",
    });
    defer client.releaseLocalStream(pending.stream_id);
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(2), .clock = .awake },
    );

    while (true) {
        var frame = try client.readOwnedFrameWithDeadline(deadline);
        defer frame.deinit(allocator);
        if (try client.handleConnectionFrame(frame.frame)) continue;
        try std.testing.expectEqual(
            http2.FrameType.headers,
            frame.frame.header.frame_type,
        );
        try std.testing.expectEqual(pending.stream_id, frame.frame.header.stream_id);
        try std.testing.expect((frame.frame.header.flags & flag_end_stream) == 0);
        break;
    }

    var first = try client.readOwnedFrameWithDeadline(deadline);
    defer first.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.data, first.frame.header.frame_type);
    const first_data = try http2.DataPayload.parse(first.frame);
    try std.testing.expectEqualStrings("hello", first_data.data);
    try std.testing.expect((first.frame.header.flags & flag_end_stream) == 0);

    try shared.timeout_done.wait(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 5), shared.committed_after_timeout);
    try std.testing.expectEqual(@as(i64, 0), shared.connection_window_after_timeout);
    try std.testing.expectEqual(@as(i64, 0), shared.stream_window_after_timeout);

    const increment = [_]u8{ 0, 0, 0, 64 };
    try writeFrame(
        allocator,
        io,
        client.stream,
        .window_update,
        0,
        0,
        &increment,
    );
    try writeFrame(
        allocator,
        io,
        client.stream,
        .window_update,
        0,
        pending.stream_id,
        &increment,
    );
    shared.allow_retry.set(io);

    var second = try client.readOwnedFrameWithDeadline(deadline);
    defer second.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.data, second.frame.header.frame_type);
    const second_data = try http2.DataPayload.parse(second.frame);
    try std.testing.expectEqualStrings(" world", second_data.data);
    try std.testing.expect((second.frame.header.flags & flag_end_stream) != 0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
