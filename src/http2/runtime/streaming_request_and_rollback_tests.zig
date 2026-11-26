//! HTTP/2 streaming-request and transactional batch rollback tests.

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

test "HTTP/2 streaming request consumes body without aggregation" {
    const allocator = std.testing.allocator;
    const body = "streaming-data-" ** 8192;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: Limits = .{
        .max_body_bytes = body.len,
        .initial_window_size = 1024 * 1024,
        .initial_connection_window_size = 1024 * 1024,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        bytes: usize = 0,
        checksum: u64 = 0,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn consume(shared: *@This(), data: []const u8) !void {
            shared.bytes += data.len;
            for (data) |byte| shared.checksum +%= byte;
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var request = try connection.readRequestStreaming(
                shared,
                consume,
            );
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqual(body.len, request.body_bytes);
            try connection.writeResponse(request.stream_id, .{});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var response = try client.request(.{
        .method = "POST",
        .path = "/stream",
        .authority = "localhost",
        .body = body,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    var expected_checksum: u64 = 0;
    for (body) |byte| expected_checksum +%= byte;
    try std.testing.expectEqual(body.len, shared.bytes);
    try std.testing.expectEqual(expected_checksum, shared.checksum);
}

test "HTTP/2 streaming pending request cleans up callback failure" {
    const allocator = std.testing.allocator;
    const headers = try allocator.alloc(http2.Hpack.HeaderField, 3);
    headers[0] = .{
        .name = try allocator.dupe(u8, ":method"),
        .value = try allocator.dupe(u8, "POST"),
    };
    headers[1] = .{
        .name = try allocator.dupe(u8, ":path"),
        .value = try allocator.dupe(u8, "/fail"),
    };
    headers[2] = .{
        .name = try allocator.dupe(u8, ":scheme"),
        .value = try allocator.dupe(u8, "http"),
    };
    const body = try allocator.dupe(u8, "callback body");

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
            pending.deinit(allocator);
        }
        connection.pending_requests.deinit(allocator);
    }
    try connection.appendPendingRequest(.{
        .stream_id = 1,
        .headers = headers,
        .method = headers[0].value,
        .path = headers[1].value,
        .scheme = headers[2].value,
        .authority = null,
        .body = body,
    }, allocator);

    try std.testing.expectError(
        error.InvalidResponse,
        connection.readRequestStreaming(
            {},
            struct {
                fn consume(_: void, _: []const u8) Error!void {
                    return error.InvalidResponse;
                }
            }.consume,
        ),
    );
    try std.testing.expectEqual(
        connection.pending_requests.items.len,
        connection.pending_request_head,
    );
}

test "HTTP/2 request batch rolls back staged HPACK state" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    const requests = [_]RequestOptions{
        .{
            .authority = "localhost",
            .headers = &.{.{
                .name = "x-transactional",
                .value = "first",
            }},
        },
        .{
            .authority = "localhost",
            .headers = &.{.{
                .name = "Uppercase-Invalid",
                .value = "second",
            }},
        },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.InvalidHeader,
        connection.requestBatchInto(&requests, &responses),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.active_local_streams.items.len,
    );
}

test "HTTP/2 request body batch rolls back staged HPACK state" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
        .send_connection_window = .{ .value = 1024 },
        .peer_initial_stream_window = 1024,
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

    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .authority = "localhost",
            .body = "first",
            .headers = &.{.{
                .name = "x-transactional",
                .value = "first",
            }},
        },
        .{
            .method = "POST",
            .authority = "localhost",
            .body = "second",
            .headers = &.{.{
                .name = "Uppercase-Invalid",
                .value = "second",
            }},
        },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.InvalidHeader,
        connection.requestBodyBatchInto(
            &requests,
            4,
            &responses,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.active_local_streams.items.len,
    );
    try std.testing.expectEqual(@as(u31, 1), connection.next_client_stream_id);
    try std.testing.expectEqual(
        @as(i64, 1024),
        connection.send_connection_window.value,
    );
}

test "HTTP/2 response batch validates transactionally" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }
    try connection.addActivePeerStream(1);
    try connection.addActivePeerStream(3);

    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponseBatch(
            &.{ 1, 3 },
            &.{
                .{ .headers = &.{.{
                    .name = "x-transactional",
                    .value = "first",
                }} },
                .{ .body = "not bodyless" },
            },
        ),
    );
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(connection.outboundStreamIsActive(3));
    // Full preflight rejects the invalid member before staging any HPACK or
    // wire bytes, which is stronger than merely allowing partial scratch.
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.write_batch.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );

    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponseBatch(
            &.{ 1, 3 },
            &.{
                .{},
                .{
                    .status = 205,
                    .headers = &.{.{
                        .name = "content-length",
                        .value = "1",
                    }},
                },
            },
        ),
    );
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(connection.outboundStreamIsActive(3));
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.write_batch.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );

    try std.testing.expectError(
        error.InvalidStreamId,
        connection.writeResponseBatch(
            &.{ 1, 1 },
            &.{ .{}, .{} },
        ),
    );
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(connection.outboundStreamIsActive(3));
}

test "HTTP/2 response batch partial HEADERS write fails closed" {
    try native_protocol_io.runStream(responseBatchPartialHeadersWriteFailsClosed);
}

fn responseBatchPartialHeadersWriteFailsClosed(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        delegate: std.Io,
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var writer: PartialWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = PartialWriter.write }),
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .auto_date_header = false },
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }
    try connection.addActivePeerStream(1);
    try connection.addActivePeerStream(3);

    try std.testing.expectError(
        error.NetworkDown,
        connection.writeResponseBatch(&.{ 1, 3 }, &.{
            .{ .headers = &.{.{ .name = "x-first", .value = "one" }} },
            .{ .headers = &.{.{ .name = "x-second", .value = "two" }} },
        }),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(
        connection.hpack_encoder.dynamic_table.entries.items.len != 0,
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.writeResponseBatch(&.{1}, &.{.{}}),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}
