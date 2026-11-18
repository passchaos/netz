//! HTTP/2 extended CONNECT and CONNECT header-assembly tests.

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

test "HTTP/2 CONNECT header assembly is stack-first with exact fallback" {
    const allocator = std.testing.allocator;
    var stack: [16]http2.Hpack.HeaderField = undefined;

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const common = try stackFirstHeaderFieldBuffer(
        no_alloc.allocator(),
        &stack,
        stack.len,
    );
    defer freeStackFirstHeaderFieldBuffer(
        no_alloc.allocator(),
        &stack,
        common,
    );
    try std.testing.expectEqual(stack[0..].ptr, common.ptr);
    try std.testing.expect(!no_alloc.has_induced_failure);

    try std.testing.expectError(
        error.OutOfMemory,
        stackFirstHeaderFieldBuffer(
            no_alloc.allocator(),
            &stack,
            stack.len + 1,
        ),
    );
    try std.testing.expect(no_alloc.has_induced_failure);

    const overflow = try stackFirstHeaderFieldBuffer(
        allocator,
        &stack,
        stack.len + 1,
    );
    defer freeStackFirstHeaderFieldBuffer(
        allocator,
        &stack,
        overflow,
    );
    try std.testing.expect(overflow.ptr != stack[0..].ptr);
    try std.testing.expectEqual(stack.len + 1, overflow.len);
}

test "HTTP/2 runtime supports RFC 8441 extended CONNECT" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(shared.server.allocator);
            std.testing.expectEqualStrings("CONNECT", request.method) catch |err| {
                shared.err = err;
                return;
            };
            std.testing.expectEqualStrings("websocket", request.protocol orelse "") catch |err| {
                shared.err = err;
                return;
            };
            std.testing.expectEqualStrings("/chat", request.path) catch |err| {
                shared.err = err;
                return;
            };
            std.testing.expectEqualStrings("http", request.scheme) catch |err| {
                shared.err = err;
                return;
            };
            std.testing.expectEqualStrings("example.com", request.authority orelse "") catch |err| {
                shared.err = err;
                return;
            };
            std.testing.expectEqualStrings("client bytes", request.body) catch |err| {
                shared.err = err;
                return;
            };

            connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = "server bytes",
            }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try std.testing.expect(client.peerExtendedConnectEnabled());

    var response = try client.request(.{
        .method = "CONNECT",
        .path = "/chat",
        .authority = "example.com",
        .protocol = "websocket",
        .body = "client bytes",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("server bytes", response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 extended CONNECT deadline preserves one response budget" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        io: std.Io,
        request_received: std.Io.Event = .unset,
        send_response: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.request_received.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readExtendedConnectRequest(
                "websocket",
            );
            defer request.deinit(self.server.allocator);
            self.request_received.set(self.io);
            try self.send_response.wait(self.io);
            try connection.rejectExtendedConnect(
                request.stream_id,
                408,
                &.{},
            );
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.send_response.set(io);
        server_thread.join();
    };

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromMilliseconds(120), .clock = .awake },
    );
    const Result = ResponseTimeoutError!ExtendedConnectResponse;
    const Wake = union(enum) {
        client: Result,
        request: std.Io.Cancelable!void,
    };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer while (select.cancel()) |wake| switch (wake) {
        .client => |result| if (result) |response_value| {
            var response = response_value;
            response.deinit(allocator);
        } else |_| {},
        .request => {},
    };
    select.async(
        .client,
        Connection.openExtendedConnectWithDeadline,
        .{ &client, RequestOptions{
            .method = "CONNECT",
            .path = "/deadline",
            .authority = "localhost",
            .protocol = "websocket",
        }, deadline },
    );
    select.async(
        .request,
        std.Io.Event.wait,
        .{ &shared.request_received, io },
    );
    switch (try select.await()) {
        .client => |result| {
            if (result) |response_value| {
                var response = response_value;
                response.deinit(allocator);
                return error.TestUnexpectedResult;
            } else |err| return err;
        },
        .request => |result| try result,
    }

    const remaining = deadline.durationFromNow(io).raw.nanoseconds;
    if (remaining > 0) {
        try std.Io.sleep(
            io,
            .{ .nanoseconds = remaining + 10 * std.time.ns_per_ms },
            .awake,
        );
    }
    shared.send_response.set(io);
    try std.testing.expectError(
        error.Timeout,
        switch (try select.await()) {
            .client => |result| result,
            .request => return error.TestUnexpectedResult,
        },
    );
    try std.testing.expect(!client.isReusable());

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 extended CONNECT deadline validates before stream mutation" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
        .peer_enable_connect_protocol = true,
    };
    defer {
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.priority_state.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    connection.io = threaded.io();

    try std.testing.expectError(
        error.Timeout,
        connection.openExtendedConnectWithDeadline(
            .{
                .method = "CONNECT",
                .path = "/",
                .authority = "localhost",
                .protocol = "websocket",
            },
            .fromNow(
                connection.io,
                .{ .raw = .fromSeconds(1), .clock = .real },
            ),
        ),
    );
    try std.testing.expectEqual(@as(u31, 1), connection.next_client_stream_id);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.active_local_streams.items.len,
    );
}

test "HTTP/2 extended CONNECT requires peer opt-in" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(error.ExtendedConnectDisabled, connection.request(.{
        .method = "CONNECT",
        .path = "/chat",
        .authority = "example.com",
        .protocol = "websocket",
    }));

    const invalid_protocol_method = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&invalid_protocol_method, .request));

    const lowercase_extended_connect = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "connect" },
        .{ .name = ":path", .value = "/bad" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&lowercase_extended_connect, .request));

    const empty_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":path", .value = "/bad" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&empty_protocol, .request));

    const invalid_protocol_token = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":path", .value = "/bad-protocol" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "web socket" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&invalid_protocol_token, .request));

    const missing_extended_authority = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(error.MissingPseudoHeader, validateHeaderBlock(&missing_extended_authority, .request));

    const extended_host_fallback = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = "host", .value = "example.com" },
    };
    try validateHeaderBlock(&extended_host_fallback, .request);
}
