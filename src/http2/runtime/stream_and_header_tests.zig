//! HTTP/2 stream-id, trailer, and header-validation tests.

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

test "HTTP/2 runtime rejects server-initiated request stream ids" {
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
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                if (err == error.InvalidFrame) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/even-stream" },
        .{ .name = ":scheme", .value = "https" },
    });
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 2, block.items);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 runtime rejects reused or decreasing client stream ids" {
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
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var first = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer first.deinit(shared.server.allocator);
            if (!std.mem.eql(u8, first.path, "/first-high")) {
                shared.err = error.UnexpectedFrame;
                return;
            }

            var second = connection.readRequest() catch |err| {
                if (err == error.InvalidFrame) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            second.deinit(shared.server.allocator);
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const first_fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/first-high" },
        .{ .name = ":scheme", .value = "https" },
    };
    try client.writeHeaders(3, &first_fields, true);

    const second_fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/second-low" },
        .{ .name = ":scheme", .value = "https" },
    };
    try client.writeHeaders(1, &second_fields, true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 runtime exchanges request and response trailers" {
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
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("POST", request.method);
            try std.testing.expectEqualStrings("/trailers", request.path);
            try std.testing.expectEqualStrings("hello", request.body);
            try std.testing.expectEqual(@as(usize, 1), request.trailers.len);
            try std.testing.expectEqualStrings("request-checksum", request.trailers[0].name);
            try std.testing.expectEqualStrings("ok", request.trailers[0].value);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "world",
                .trailers = &.{.{ .name = "grpc-status", .value = "0" }},
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "POST",
        .path = "/trailers",
        .authority = "localhost",
        .body = "hello",
        .trailers = &.{.{ .name = "request-checksum", .value = "ok" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("world", response.body);
    try std.testing.expectEqual(@as(usize, 1), response.trailers.len);
    try std.testing.expectEqualStrings("grpc-status", response.trailers[0].name);
    try std.testing.expectEqualStrings("0", response.trailers[0].value);
}

test "HTTP/2 readRequest queues complete interleaved peer request" {
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

            var first = try connection.readRequest();
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqualStrings("/first-interleaved", first.path);
            try std.testing.expectEqualStrings("first-body", first.body);

            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 3), second.stream_id);
            try std.testing.expectEqualStrings("/second-interleaved", second.path);
            try std.testing.expectEqualStrings("", second.body);
            try std.testing.expectEqual(@as(usize, 0), connection.pending_requests.items.len);
            try std.testing.expectEqual(@as(usize, 0), connection.pending_request_head);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try client.writeHeaders(1, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/first-interleaved" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "10" },
    }, false);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/second-interleaved" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.writeData(1, "first-body", true);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime rejects inbound connection-specific headers" {
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
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                if (err == error.InvalidHeader) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.InvalidHeader;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad-header" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "connection", .value = "x-hop" },
        .{ .name = "x-hop", .value = "secret" },
    };
    try client.writeHeaders(1, &fields, true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 serveOne resets malformed request stream and serves sibling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        calls: usize = 0,

        fn handle(ctx: *@This(), request: OwnedRequest) Error!ResponseOptions {
            ctx.calls += 1;
            if (!std.mem.eql(u8, request.path, "/good-after-reset")) {
                return error.UnexpectedFrame;
            }
            return .{ .status = 204 };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        saw_bad_header: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.serveOne(
                Context,
                &shared.context,
                Context.handle,
            ) catch |err| {
                if (err == error.InvalidHeader) {
                    shared.saw_bad_header = true;
                } else {
                    shared.err = err;
                    return;
                }
            };
            _ = connection.serveOne(
                Context,
                &shared.context,
                Context.handle,
            ) catch |err| {
                shared.err = err;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    var encoder = http2.Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var bad_block: std.ArrayList(u8) = .empty;
    defer bad_block.deinit(allocator);
    try encoder.encodeBlock(&bad_block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = "connection", .value = "close" },
    });
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 1, bad_block.items);

    var good_block: std.ArrayList(u8) = .empty;
    defer good_block.deinit(allocator);
    try encoder.encodeBlock(&good_block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/good-after-reset" },
        .{ .name = ":scheme", .value = "http" },
    });
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 3, good_block.items);

    var reset = try client.readResetStream();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);
    var response = try client.readResponse(3, "GET", false, null);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.status);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_bad_header);
    try std.testing.expectEqual(@as(usize, 1), shared.context.calls);
}

test "HTTP/2 serveOne resets content-length mismatch after request DATA" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        fn handle(_: *@This(), _: OwnedRequest) Error!ResponseOptions {
            return error.UnexpectedFrame;
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.serveOne(
                Context,
                &shared.context,
                Context.handle,
            ) catch |err| {
                if (err == error.InvalidContentLength) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    try client.writeHeaders(1, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/short" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = "content-length", .value = "5" },
    }, false);
    try client.writeData(1, "four", true);
    var reset = try client.readResetStream();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 high-level writers strip outbound connection-specific headers" {
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
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/strip-hop-by-hop", request.path);
            try std.testing.expect(findHeader(request.headers, "connection") == null);
            try std.testing.expect(findHeader(request.headers, "x-hop") == null);
            try std.testing.expect(findHeader(request.headers, "keep-alive") == null);
            try std.testing.expect(findHeader(request.headers, "proxy-connection") == null);
            try std.testing.expect(findHeader(request.headers, "transfer-encoding") == null);
            try std.testing.expect(findHeader(request.headers, "upgrade") == null);
            try std.testing.expect(findHeader(request.headers, "te") == null);
            try std.testing.expectEqualStrings("kept", findHeader(request.headers, "x-end-to-end") orelse return error.MissingPseudoHeader);

            try connection.writeResponse(request.stream_id, .{
                .headers = &.{
                    .{ .name = "connection", .value = "x-response-hop" },
                    .{ .name = "x-response-hop", .value = "secret" },
                    .{ .name = "keep-alive", .value = "timeout=5" },
                    .{ .name = "proxy-connection", .value = "keep-alive" },
                    .{ .name = "transfer-encoding", .value = "chunked" },
                    .{ .name = "upgrade", .value = "websocket" },
                    .{ .name = "te", .value = "gzip" },
                    .{ .name = "x-response-end-to-end", .value = "kept" },
                },
                .body = "ok",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/strip-hop-by-hop",
        .authority = "localhost",
        .headers = &.{
            .{ .name = "connection", .value = "x-hop" },
            .{ .name = "x-hop", .value = "secret" },
            .{ .name = "keep-alive", .value = "timeout=5" },
            .{ .name = "proxy-connection", .value = "keep-alive" },
            .{ .name = "transfer-encoding", .value = "chunked" },
            .{ .name = "upgrade", .value = "websocket" },
            .{ .name = "te", .value = "gzip" },
            .{ .name = "x-end-to-end", .value = "kept" },
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expect(findHeader(response.headers, "connection") == null);
    try std.testing.expect(findHeader(response.headers, "x-response-hop") == null);
    try std.testing.expect(findHeader(response.headers, "keep-alive") == null);
    try std.testing.expect(findHeader(response.headers, "proxy-connection") == null);
    try std.testing.expect(findHeader(response.headers, "transfer-encoding") == null);
    try std.testing.expect(findHeader(response.headers, "upgrade") == null);
    try std.testing.expect(findHeader(response.headers, "te") == null);
    try std.testing.expectEqualStrings("kept", findHeader(response.headers, "x-response-end-to-end") orelse return error.MissingPseudoHeader);
}

test "HTTP/2 high-level writer strips a late Connection nomination" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var request_headers: [259]http2.Hpack.HeaderField = undefined;
    for (request_headers[0..256]) |*header| {
        header.* = .{ .name = "connection", .value = "x-decoy" };
    }
    request_headers[256] = .{
        .name = "connection",
        .value = "x-late-hop",
    };
    request_headers[257] = .{
        .name = "x-late-hop",
        .value = "must-not-cross-h2",
    };
    request_headers[258] = .{ .name = "x-kept", .value = "yes" };

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_header_fields = 512,
            .max_header_list_size = 64 * 1024,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expect(findHeader(
                request.headers,
                "connection",
            ) == null);
            try std.testing.expect(findHeader(
                request.headers,
                "x-late-hop",
            ) == null);
            try std.testing.expectEqualStrings(
                "yes",
                findHeader(request.headers, "x-kept") orelse
                    return error.MissingPseudoHeader,
            );

            var response_headers: [259]http2.Hpack.HeaderField = undefined;
            for (response_headers[0..256]) |*header| {
                header.* = .{
                    .name = "connection",
                    .value = "x-response-decoy",
                };
            }
            response_headers[256] = .{
                .name = "connection",
                .value = "x-response-late",
            };
            response_headers[257] = .{
                .name = "x-response-late",
                .value = "must-not-cross-h2",
            };
            response_headers[258] = .{
                .name = "x-response-kept",
                .value = "yes",
            };
            try connection.writeResponse(request.stream_id, .{
                .headers = &response_headers,
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_header_fields = 512,
        .max_header_list_size = 64 * 1024,
    });
    defer client.close();
    var response = try client.request(.{
        .method = "GET",
        .path = "/late-nomination",
        .authority = "localhost",
        .headers = &request_headers,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(findHeader(
        response.headers,
        "connection",
    ) == null);
    try std.testing.expect(findHeader(
        response.headers,
        "x-response-late",
    ) == null);
    try std.testing.expectEqualStrings(
        "yes",
        findHeader(response.headers, "x-response-kept") orelse
            return error.MissingPseudoHeader,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 stripConnectionHeaders compacts nominated hop-by-hop fields" {
    const allocator = std.testing.allocator;
    var headers: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer headers.deinit(allocator);
    try headers.appendSlice(allocator, &.{
        .{ .name = "x-keep-a", .value = "a" },
        .{ .name = "Connection", .value = "x-hop-a, x-hop-b" },
        .{ .name = "x-hop-a", .value = "remove" },
        .{ .name = "te", .value = "trailers" },
        .{ .name = "x-hop-b", .value = "remove" },
        .{ .name = "Connection", .value = "x-hop-c" },
        .{ .name = "x-hop-c", .value = "remove" },
        .{ .name = "x-keep-b", .value = "b" },
    });

    try outbound_headers.stripConnectionHeaders(
        allocator,
        &headers,
        .request,
    );
    try std.testing.expectEqual(@as(usize, 3), headers.items.len);
    try std.testing.expectEqualStrings("x-keep-a", headers.items[0].name);
    try std.testing.expectEqualStrings("te", headers.items[1].name);
    try std.testing.expectEqualStrings("x-keep-b", headers.items[2].name);
}

test "HTTP/2 high-level request writer preserves TE trailers" {
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
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("trailers", findHeader(request.headers, "te") orelse return error.MissingPseudoHeader);
            try connection.writeResponse(request.stream_id, .{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/te-trailers",
        .authority = "localhost",
        .headers = &.{.{ .name = "te", .value = "trailers" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("ok", response.body);
}

test "HTTP/2 runtime rejects invalid wire and outbound header names" {
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
        expected_errors: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            while (shared.expected_errors < 3) {
                var request = connection.readRequest() catch |err| {
                    if (err == error.InvalidHeader or err == error.MissingPseudoHeader) {
                        shared.expected_errors += 1;
                        continue;
                    }
                    shared.err = err;
                    return;
                };
                request.deinit(shared.server.allocator);
                shared.err = error.InvalidHeader;
                return;
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

    const uppercase = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/uppercase" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "Host", .value = "localhost" },
    };
    try client.writeHeaders(1, &uppercase, true);

    const late_pseudo = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/late-pseudo" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":scheme", .value = "https" },
    };
    try client.writeHeaders(3, &late_pseudo, true);

    const duplicate_pseudo = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/duplicate-pseudo" },
        .{ .name = ":scheme", .value = "https" },
    };
    try client.writeHeaders(5, &duplicate_pseudo, true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 3), shared.expected_errors);

    try std.testing.expectError(error.InvalidHeader, client.request(.{
        .method = "GET",
        .path = "/bad-response-header",
        .authority = "localhost",
        .headers = &.{.{ .name = "Uppercase", .value = "bad" }},
    }));
    try std.testing.expectError(error.InvalidHeader, client.request(.{
        .method = "GET",
        .path = "/bad-request-pseudo",
        .authority = "localhost",
        .headers = &.{.{ .name = ":status", .value = "200" }},
    }));
}
