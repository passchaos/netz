//! HTTP/2 response-batch ordering and deadline tests.

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

test "HTTP/2 response batch reorders out-of-order responses" {
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

            var requests: [3]OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(server_ptr.allocator);
            };
            for (&requests) |*request| {
                request.* = try connection.readRequest();
                initialized += 1;
            }

            var stream_ids: [requests.len]u31 = undefined;
            var response_headers: [requests.len]http2.Hpack.HeaderField =
                undefined;
            var responses: [requests.len]ResponseOptions = undefined;
            var index = requests.len;
            while (index != 0) {
                index -= 1;
                const output_index = requests.len - 1 - index;
                stream_ids[output_index] = requests[index].stream_id;
                response_headers[output_index] = .{
                    .name = "x-path",
                    .value = requests[index].path,
                };
                responses[output_index] = .{
                    .headers = response_headers[output_index..][0..1],
                };
            }
            try connection.writeResponseBatch(&stream_ids, &responses);
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

    const requests = [_]RequestOptions{
        .{ .path = "/one", .authority = "localhost" },
        .{ .path = "/two", .authority = "localhost" },
        .{ .path = "/three", .authority = "localhost" },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try client.requestBatchInto(&requests, &responses);
    defer for (&responses) |*response| response.deinit(allocator);

    try std.testing.expectEqualStrings(
        "/one",
        findHeader(responses[0].headers, "x-path").?,
    );
    try std.testing.expectEqualStrings(
        "/two",
        findHeader(responses[1].headers, "x-path").?,
    );
    try std.testing.expectEqualStrings(
        "/three",
        findHeader(responses[2].headers, "x-path").?,
    );
    for (responses) |response| {
        const date = findHeader(response.headers, "date") orelse
            return error.MissingPseudoHeader;
        try std.testing.expectEqual(@as(usize, http_date.value_len), date.len);
        try std.testing.expectEqualStrings("GMT", date[26..]);
    }
    try std.testing.expectEqual(@as(usize, 0), client.active_local_streams.items.len);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 response batch deadline is not renewed by partial completion" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
        reset_stream_id: ?u31 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);

            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
            try connection.writeResponse(first.stream_id, .{
                .body = "first",
            });
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(350),
                .awake,
            );
            try connection.writeResponse(second.stream_id, .{
                .body = "late",
            });
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            self.reset_stream_id = reset.reset.stream_id;
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{ .path = "/first", .authority = "localhost" },
        .{ .path = "/second", .authority = "localhost" },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.requestBatchIntoWithTimeout(
            &requests,
            &responses,
            .fromMilliseconds(400),
        ),
    );
    try std.testing.expect(!client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(?u31, 3), shared.reset_stream_id);
}

test "HTTP/2 batch deadlines validate before stream or wire mutation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var connection = Connection{
        .io = threaded.io(),
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.batch_data_headers.deinit(allocator);
        connection.batch_data_parts.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }
    const requests = [_]RequestOptions{.{
        .authority = "localhost",
    }};
    const body_requests = [_]RequestOptions{.{
        .method = "POST",
        .authority = "localhost",
        .body = "body",
    }};
    var responses: [1]OwnedResponse = undefined;
    var streaming_responses: [1]StreamingResponse = undefined;
    const noopConsume = struct {
        fn consume(_: void, _: usize, _: []const u8) !void {}
    }.consume;
    try std.testing.expectError(
        error.Timeout,
        connection.requestBatchIntoWithTimeout(
            &requests,
            &responses,
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchIntoWithDeadline(
            &body_requests,
            4,
            &responses,
            .fromNow(connection.io, .{
                .raw = .fromSeconds(1),
                .clock = .real,
            }),
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBatchStreamingIntoWithTimeout(
            &requests,
            &streaming_responses,
            .zero,
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBatchStreamingWithInformationalIntoWithDeadline(
            &requests,
            &streaming_responses,
            null,
            .fromNow(connection.io, .{
                .raw = .fromSeconds(1),
                .clock = .real,
            }),
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchStreamingIntoWithTimeout(
            &body_requests,
            4,
            &streaming_responses,
            .zero,
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchStreamingWithInformationalIntoWithDeadline(
            &body_requests,
            4,
            &streaming_responses,
            null,
            .fromNow(connection.io, .{
                .raw = .fromSeconds(1),
                .clock = .real,
            }),
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchStreamingWithInformationalIntoWithTimeout(
            &body_requests,
            4,
            &streaming_responses,
            null,
            .zero,
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        connection.requestBodyBatchStreamingWithInformationalInto(
            &body_requests,
            0,
            &streaming_responses,
            null,
            {},
            noopConsume,
        ),
    );
    connection.role = .server;
    var inbound_requests: [1]StreamingRequest = undefined;
    try std.testing.expectError(
        error.Timeout,
        connection.readRequestBatchStreamingIntoWithTimeout(
            &inbound_requests,
            .zero,
            {},
            struct {
                fn consume(_: void, _: u31, _: []const u8) !void {}
            }.consume,
        ),
    );
    try std.testing.expectEqual(@as(u31, 1), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expectEqual(@as(u31, 0), connection.last_peer_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
    try std.testing.expectEqual(@as(usize, 0), connection.write_batch.items.len);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);
}
