//! HTTP/2 request-body batch and streaming-response batch tests.

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

test "HTTP/2 streaming request batch partial HEADERS write fails closed" {
    try native_protocol_io.runStream(streamingRequestBatchPartialHeadersWriteFailsClosed);
}

fn streamingRequestBatchPartialHeadersWriteFailsClosed(io: std.Io) !void {
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
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    const requests = [_]RequestOptions{
        .{ .path = "/first", .authority = "localhost" },
        .{ .path = "/second", .authority = "localhost" },
    };
    var responses: [requests.len]StreamingResponse = undefined;
    try std.testing.expectError(
        error.NetworkDown,
        connection.requestBatchStreamingInto(
            &requests,
            &responses,
            {},
            struct {
                fn consume(_: void, _: usize, _: []const u8) !void {}
            }.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expectEqual(@as(u31, 5), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendCompleteRequest(.{ .authority = "localhost" }),
    );
}

test "HTTP/2 body request streaming response batch partial HEADERS fails closed" {
    try native_protocol_io.runStream(bodyRequestStreamingResponseBatchPartialHeadersFailsClosed);
}

fn bodyRequestStreamingResponseBatchPartialHeadersFailsClosed(io: std.Io) !void {
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

    const requests = [_]RequestOptions{
        .{ .method = "POST", .authority = "localhost", .body = "one" },
        .{ .method = "POST", .authority = "localhost", .body = "two" },
    };
    var responses: [requests.len]StreamingResponse = undefined;
    try std.testing.expectError(
        error.NetworkDown,
        connection.requestBodyBatchStreamingInto(
            &requests,
            3,
            &responses,
            {},
            struct {
                fn consume(_: void, _: usize, _: []const u8) !void {}
            }.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expectEqual(@as(u31, 5), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
}

test "HTTP/2 request body batch partial DATA does not append cleanup resets" {
    try native_protocol_io.runStream(requestBodyBatchPartialDataDoesNotAppendCleanupResets);
}

fn requestBodyBatchPartialDataDoesNotAppendCleanupResets(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const PartialDataWriter = struct {
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
            if (self.writes == 1) return bytes.len;
            if (self.writes == 2) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var writer: PartialDataWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = PartialDataWriter.write }),
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
        .method = "POST",
        .authority = "localhost",
        .body = "payload",
    }};
    var responses: [1]OwnedResponse = undefined;
    try std.testing.expectError(
        error.NetworkDown,
        connection.requestBodyBatchInto(
            &requests,
            requests[0].body.len,
            &responses,
        ),
    );
    // HEADERS, one partial DATA prefix, then the failing continuation. The
    // unwind path must not attempt a fourth write for RST_STREAM cleanup.
    try std.testing.expectEqual(@as(usize, 3), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
}

test "HTTP/2 aggregate response batch borrows wire frames after warmup" {
    const allocator = std.testing.allocator;
    const parallel = 3;

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

            {
                var warmup = try connection.readRequest();
                defer warmup.deinit(server_ptr.allocator);
                try connection.writeResponse(warmup.stream_id, .{});
            }

            const responses = [_]ResponseOptions{.{}} ** parallel;
            for (0..2) |batch_index| {
                var requests: [parallel]OwnedRequest = undefined;
                var initialized: usize = 0;
                defer for (requests[0..initialized]) |*request| {
                    request.deinit(server_ptr.allocator);
                };
                var stream_ids: [parallel]u31 = undefined;
                for (&requests, &stream_ids) |*request, *stream_id| {
                    request.* = try connection.readRequest();
                    initialized += 1;
                    stream_id.* = request.stream_id;
                }
                if (batch_index == 0) {
                    try connection.writeResponseBatch(
                        &stream_ids,
                        &responses,
                    );
                    continue;
                }

                var tracking = std.testing.FailingAllocator.init(
                    allocator,
                    .{},
                );
                const saved_allocator = connection.allocator;
                connection.allocator = tracking.allocator();
                defer connection.allocator = saved_allocator;
                try connection.writeResponseBatch(
                    &stream_ids,
                    &responses,
                );
                try std.testing.expectEqual(
                    @as(usize, 0),
                    tracking.allocations,
                );
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    {
        var warmup = try client.request(.{
            .path = "/batch-borrow",
            .authority = "localhost",
        });
        defer warmup.deinit(allocator);
    }

    const requests = [_]RequestOptions{.{
        .path = "/batch-borrow",
        .authority = "localhost",
    }} ** parallel;
    {
        var responses: [parallel]OwnedResponse = undefined;
        try client.requestBatchInto(&requests, &responses);
        defer for (&responses) |*response| response.deinit(allocator);
    }
    {
        var responses: [parallel]OwnedResponse = undefined;
        var tracking = std.testing.FailingAllocator.init(allocator, .{});
        const saved_allocator = client.allocator;
        client.allocator = tracking.allocator();
        defer client.allocator = saved_allocator;
        try client.requestBatchInto(&requests, &responses);
        defer for (&responses) |*response| {
            response.deinit(client.allocator);
        };
        // Request/response staging and wire-frame reads reuse connection
        // storage. Only one combined HPACK block per response is allocated.
        try std.testing.expectEqual(
            @as(usize, parallel),
            tracking.allocations,
        );
        for (responses) |response| {
            try std.testing.expectEqual(@as(u16, 200), response.status);
            try std.testing.expectEqualStrings("", response.body);
        }
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request body batch crosses connection flow-control window" {
    const allocator = std.testing.allocator;
    // Each body exceeds the default 65,535-byte stream window and the batch
    // exceeds the connection window, forcing both WINDOW_UPDATE paths.
    const request_body = "batch-body-" ** 8192;
    const parallel = 3;
    const total_body_bytes = request_body.len * parallel;
    const limits: Limits = .{
        .max_body_bytes = request_body.len,
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
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

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var requests: [parallel]StreamingRequest = undefined;
            var initialized = false;
            defer if (initialized) for (&requests) |*request| {
                request.deinit(server_ptr.allocator);
            };
            const Context = struct {
                bytes: usize = 0,
                fn consume(
                    self: *@This(),
                    _: u31,
                    data: []const u8,
                ) !void {
                    self.bytes += data.len;
                }
            };
            var context: Context = .{};
            try connection.readRequestBatchStreamingIntoWithTimeout(
                &requests,
                .fromSeconds(2),
                &context,
                Context.consume,
            );
            initialized = true;
            for (&requests) |*request| {
                try std.testing.expectEqualStrings(
                    "POST",
                    request.method,
                );
                try std.testing.expectEqual(
                    request_body.len,
                    request.body_bytes,
                );
            }
            try std.testing.expectEqual(
                total_body_bytes,
                context.bytes,
            );
            var stream_ids: [parallel]u31 = undefined;
            var response_headers: [parallel]http2.Hpack.HeaderField =
                undefined;
            var responses: [parallel]ResponseOptions = undefined;
            for (&stream_ids, &response_headers, &responses, 0..) |
                *stream_id,
                *response_header,
                *response,
                index,
            | {
                const reverse = parallel - 1 - index;
                stream_id.* = requests[reverse].stream_id;
                response_header.* = .{
                    .name = "x-path",
                    .value = requests[reverse].path,
                };
                response.* = .{
                    .headers = response_headers[index..][0..1],
                };
            }
            try connection.writeResponseBatch(
                &stream_ids,
                &responses,
            );
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
    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .path = "/one",
            .authority = "localhost",
            .body = request_body,
        },
        .{
            .method = "POST",
            .path = "/two",
            .authority = "localhost",
            .body = request_body,
        },
        .{
            .method = "POST",
            .path = "/three",
            .authority = "localhost",
            .body = request_body,
        },
    };
    var responses: [parallel]OwnedResponse = undefined;
    try client.requestBodyBatchIntoWithTimeout(
        &requests,
        request_body.len,
        &responses,
        .fromSeconds(2),
    );
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

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request body batch consumes an early response while another upload waits" {
    const allocator = std.testing.allocator;
    const large_body = "large-upload-" ** 8192;
    const limits: Limits = .{ .max_body_bytes = large_body.len };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        connection: ?*Connection = null,
        early_bytes: usize = 0,
        early_response_sent: bool = false,
        large_bytes: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn consume(
            self: *@This(),
            stream_id: u31,
            data: []const u8,
        ) !void {
            if (stream_id == 1) {
                self.early_bytes += data.len;
                if (self.early_bytes == "small".len) {
                    try self.connection.?.writeResponseInternal(
                        stream_id,
                        .{
                            .body = "early-finished",
                            .request_method = "POST",
                        },
                        false,
                    );
                    self.early_response_sent = true;
                }
                return;
            }
            self.large_bytes += data.len;
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            self.connection = &connection;
            defer self.connection = null;
            var incoming: [2]StreamingRequest = undefined;
            try connection.readRequestBatchStreamingInto(
                &incoming,
                self,
                @This().consume,
            );
            defer for (&incoming) |*request| {
                request.deinit(self.server.allocator);
            };
            try std.testing.expect(self.early_response_sent);
            try std.testing.expectEqualStrings("/early", incoming[0].path);
            try std.testing.expectEqualStrings("/large", incoming[1].path);
            try std.testing.expectEqual(large_body.len, incoming[1].body_bytes);
            connection.releasePeerStream(incoming[0].stream_id);
            try connection.writeResponse(incoming[1].stream_id, .{
                .body = "large-finished",
            });
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
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .path = "/early",
            .authority = "localhost",
            .body = "small",
        },
        .{
            .method = "POST",
            .path = "/large",
            .authority = "localhost",
            .body = large_body,
        },
    };
    var responses: [requests.len]StreamingResponse = undefined;
    const ResponseContext = struct {
        bodies: [requests.len][32]u8 = undefined,
        lengths: [requests.len]usize = .{0} ** requests.len,

        fn consume(
            self: *@This(),
            index: usize,
            data: []const u8,
        ) !void {
            if (self.lengths[index] + data.len > self.bodies[index].len) {
                return error.MessageTooLarge;
            }
            @memcpy(
                self.bodies[index][self.lengths[index]..][0..data.len],
                data,
            );
            self.lengths[index] += data.len;
        }
    };
    var response_context: ResponseContext = .{};
    try client.requestBodyBatchStreamingIntoWithTimeout(
        &requests,
        16 * 1024,
        &responses,
        .fromSeconds(2),
        &response_context,
        ResponseContext.consume,
    );
    defer for (&responses) |*response| response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), responses[0].status);
    try std.testing.expectEqual(@as(u16, 200), responses[1].status);
    try std.testing.expectEqualStrings(
        "early-finished",
        response_context.bodies[0][0..response_context.lengths[0]],
    );
    try std.testing.expectEqualStrings(
        "large-finished",
        response_context.bodies[1][0..response_context.lengths[1]],
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(large_body.len, shared.large_bytes);
}

test "HTTP/2 request body batch deadline covers blocked upload" {
    const allocator = std.testing.allocator;
    const large_body = "deadline-upload-" ** 8192;
    const limits: Limits = .{ .max_body_bytes = large_body.len };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
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

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            std.Io.sleep(
                self.server.io,
                .fromMilliseconds(100),
                .awake,
            ) catch |err| {
                self.err = err;
            };
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
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .path = "/blocked-one",
            .authority = "localhost",
            .body = large_body,
        },
        .{
            .method = "POST",
            .path = "/blocked-two",
            .authority = "localhost",
            .body = large_body,
        },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.requestBodyBatchIntoWithTimeout(
            &requests,
            16 * 1024,
            &responses,
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(!client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 request body batch streaming ignores duplicate reset and admits later request" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_pending_accept_reset_streams = 4,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        stream_one_bytes: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();

            var requests: [2]StreamingRequest = undefined;
            var initialized = false;
            defer if (initialized) for (&requests) |*request| {
                request.deinit(shared.server.allocator);
            };

            const Context = @This();
            try connection.readRequestBatchStreamingInto(
                &requests,
                shared,
                struct {
                    fn consume(
                        context: *Context,
                        stream_id: u31,
                        data: []const u8,
                    ) Error!void {
                        if (stream_id == 1) context.stream_one_bytes += data.len;
                    }
                }.consume,
            );
            initialized = true;

            try std.testing.expectEqual(@as(u31, 1), requests[0].stream_id);
            try std.testing.expectEqualStrings("/first-batch", requests[0].path);
            try std.testing.expectEqual(@as(usize, 10), requests[0].body_bytes);

            try std.testing.expectEqual(@as(u31, 5), requests[1].stream_id);
            try std.testing.expectEqualStrings("/replacement-batch", requests[1].path);
            try std.testing.expectEqual(@as(usize, 0), requests[1].body_bytes);

            try std.testing.expectEqual(@as(usize, 10), shared.stream_one_bytes);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_pending_accept_reset_streams = 4,
    });
    defer client.close();

    try client.writeHeaders(1, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/first-batch" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "10" },
    }, false);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/reset-batch" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.sendResetStream(3, .cancel);
    // The public API deliberately rejects resetting an already closed stream.
    // Inject the duplicate peer frame directly to exercise the receiver's
    // tolerance for a legal retransmission already in flight on the wire.
    var duplicate_reset: [http2.ResetStreamPayload.encoded_len]u8 = undefined;
    const encoded_duplicate = try http2.ResetStreamPayload.writeInto(
        &duplicate_reset,
        3,
        .cancel,
    );
    try client.transportForIo().writeAll(encoded_duplicate);
    try client.writeHeaders(5, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/replacement-batch" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.writeData(1, "first-body", true);

    thread.join();
    if (shared.err) |err| return err;
}
