//! HTTP/2 CONNECT tunnel and informational-response tests.

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

test "HTTP/2 CONNECT tunnel skips valid informational responses" {
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
            try std.testing.expectEqualStrings("CONNECT", request.method);

            try connection.writeExtendedConnectResponse(request.stream_id, 103, &.{
                .{ .name = "link", .value = "</proxy-hint>; rel=preload" },
            }, false);
            try connection.writeExtendedConnectResponse(request.stream_id, 200, &.{}, false);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    const date = findHeader(response.headers, "date") orelse
        return error.MissingPseudoHeader;
    try std.testing.expectEqual(@as(usize, http_date.value_len), date.len);
    try std.testing.expectEqualStrings("GMT", date[26..]);
}

test "HTTP/2 CONNECT informational response omits automatic Date" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .enable_connect_protocol = true,
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
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
            var request = try connection.readExtendedConnectRequest(
                "websocket",
            );
            defer request.deinit(self.server.allocator);
            try connection.writeExtendedConnectResponse(
                request.stream_id,
                103,
                &.{.{
                    .name = "link",
                    .value = "</proxy-hint>; rel=preload",
                }},
                false,
            );
            try connection.writeExtendedConnectResponse(
                request.stream_id,
                200,
                &.{},
                false,
            );
        }
    };

    const HeadReader = struct {
        fn read(
            connection: *Connection,
            decoder: *http2.Hpack.Decoder,
        ) ![]http2.Hpack.HeaderField {
            while (true) {
                var frame = try connection.readOwnedFrame();
                defer frame.deinit(connection.allocator);
                if (try connection.handleConnectionFrame(frame.frame)) {
                    continue;
                }
                if (frame.frame.header.frame_type != .headers) {
                    return error.UnexpectedFrame;
                }
                if ((frame.frame.header.flags & flag_end_headers) == 0) {
                    return error.UnexpectedFrame;
                }
                const payload = try http2.HeadersPayload.parse(frame.frame);
                return decoder.decodeBlockOwnedWithLimit(
                    connection.allocator,
                    payload.header_block,
                    connection.limits.max_header_fields,
                    connection.limits.max_header_list_size,
                );
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    try std.testing.expect(client.peerExtendedConnectEnabled());
    const stream_id = try client.reserveNextClientStreamId();
    try client.writeHeaders(stream_id, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":protocol", .value = "websocket" },
    }, false);

    var decoder: http2.Hpack.Decoder = .{};
    defer decoder.deinit(allocator);
    const informational = try HeadReader.read(&client, &decoder);
    defer freeHeaders(allocator, informational);
    try std.testing.expectEqualStrings(
        "103",
        findHeader(informational, ":status").?,
    );
    try std.testing.expect(findHeader(informational, "date") == null);

    const final = try HeadReader.read(&client, &decoder);
    defer freeHeaders(allocator, final);
    try std.testing.expectEqualStrings(
        "200",
        findHeader(final, ":status").?,
    );
    const date = findHeader(final, "date") orelse
        return error.MissingPseudoHeader;
    try std.testing.expectEqual(@as(usize, http_date.value_len), date.len);
    try std.testing.expectEqualStrings("GMT", date[26..]);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 CONNECT tunnel rejects content-length on informational response" {
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
            try std.testing.expectEqualStrings("CONNECT", request.method);

            // Raw HEADERS emulate an invalid peer; the high-level writer rejects
            // this field before it can hit the wire.
            try connection.writeHeaders(request.stream_id, &.{
                .{ .name = ":status", .value = "103" },
                .{ .name = "content-length", .value = "0" },
            }, false);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidContentLength, client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime accepts multipart traditional CONNECT DATA tunnel" {
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
            try std.testing.expectEqualStrings("CONNECT", request.method);
            try std.testing.expectEqualStrings("example.com:443", request.authority orelse "");

            var tunnel = try connection.acceptConnectTunnel(request, &.{
                .{ .name = "content-length", .value = "0" },
            });
            var inbound = try tunnel.read();
            defer inbound.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("client tunnel bytes", inbound.data);
            try std.testing.expect(!inbound.end_stream);

            try tunnel.writeParts("server tunnel ", "bytes", true);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(findHeader(response.headers, "content-length") == null);
    try std.testing.expectEqual(
        @as(usize, http_date.value_len),
        findHeader(response.headers, "date").?.len,
    );

    var tunnel = response.tunnel;
    try tunnel.writeParts("client ", "tunnel bytes", false);
    var inbound = try tunnel.read();
    defer inbound.deinit(allocator);
    try std.testing.expectEqualStrings("server tunnel bytes", inbound.data);
    try std.testing.expect(inbound.end_stream);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 tunnel preserves a sibling response for its owner" {
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

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();

            var connect_request = try connection.readRequest();
            defer connect_request.deinit(self.server.allocator);
            var tunnel = try connection.acceptConnectTunnel(
                connect_request,
                &.{},
            );

            var sibling_request = try connection.readRequest();
            defer sibling_request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/sibling",
                sibling_request.path,
            );
            try connection.writeResponse(sibling_request.stream_id, .{
                .body = "sibling response",
                .request_method = sibling_request.method,
            });
            try tunnel.write("tunnel response", true);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    var connect_response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer connect_response.deinit(allocator);
    var sibling = try client.startRequest(.{
        .path = "/sibling",
        .authority = "localhost",
        .body_length = 0,
    });
    defer sibling.deinit();
    try sibling.finish();

    try std.testing.expectError(
        error.ResponseAvailable,
        connect_response.tunnel.readWithDeadline(.fromNow(
            io,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        )),
    );
    var sibling_response = try sibling.readResponse();
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "sibling response",
        sibling_response.body,
    );

    var tunnel_data = try connect_response.tunnel.readWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer tunnel_data.deinit(allocator);
    try std.testing.expectEqualStrings("tunnel response", tunnel_data.data);
    try std.testing.expect(tunnel_data.end_stream);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 tunnel releases concurrency only after both halves close" {
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
            .max_concurrent_streams = 1,
        },
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
            try std.testing.expectEqual(
                @as(?u32, null),
                connection.peerMaxConcurrentStreams(),
            );
            try std.testing.expectEqual(
                @as(?u32, null),
                connection.availableLocalStreamCapacity(),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );

            var first_request = try connection.readRequest();
            defer first_request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                @as(usize, 1),
                connection.activePeerStreamCount(),
            );
            var first = try connection.acceptConnectTunnel(
                first_request,
                &.{},
            );
            try first.write("server half close", true);
            try std.testing.expectEqual(
                @as(usize, 1),
                connection.activePeerStreamCount(),
            );
            try std.testing.expectError(
                error.FlowControlViolation,
                connection.reservePeerStream(3),
            );
            try std.testing.expectError(
                error.ConnectionClosed,
                first.write("after end", false),
            );
            var first_end = try first.read();
            defer first_end.deinit(server_ptr.allocator);
            try std.testing.expect(first_end.end_stream);
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );
            try std.testing.expect(
                connection.send_stream_window_index.get(first.stream_id) == null,
            );
            try std.testing.expect(
                connection.recv_stream_window_index.get(first.stream_id) == null,
            );

            var second_request = try connection.readRequest();
            defer second_request.deinit(server_ptr.allocator);
            var second = try connection.acceptConnectTunnel(
                second_request,
                &.{},
            );
            var writer = try second.beginWriteSequence();
            try writer.write("server writer close", true);
            try std.testing.expectError(
                error.ConnectionClosed,
                writer.write("after end", false),
            );
            var second_end = try second.read();
            defer second_end.deinit(server_ptr.allocator);
            try std.testing.expect(second_end.end_stream);
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.activeLocalStreamCount(),
    );
    try std.testing.expect(!client.peerExtendedConnectEnabled());

    var first_response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer first_response.deinit(allocator);
    var first = first_response.tunnel;
    var first_data = try first.read();
    defer first_data.deinit(allocator);
    try std.testing.expectEqualStrings("server half close", first_data.data);
    try std.testing.expect(first_data.end_stream);
    try std.testing.expectEqual(
        @as(usize, 1),
        client.activeLocalStreamCount(),
    );
    try std.testing.expectEqual(
        @as(?u32, 0),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expectError(
        error.FlowControlBlocked,
        client.openConnectTunnel(.{
            .method = "CONNECT",
            .authority = "example.com:443",
        }),
    );
    try first.closeWrite();
    try std.testing.expectError(error.ConnectionClosed, first.closeWrite());
    try std.testing.expectEqual(
        @as(usize, 0),
        client.activeLocalStreamCount(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(
        client.send_stream_window_index.get(first.stream_id) == null,
    );
    try std.testing.expect(
        client.recv_stream_window_index.get(first.stream_id) == null,
    );

    var second_response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer second_response.deinit(allocator);
    var second = second_response.tunnel;
    var writer = try second.beginWriteSequence();
    try writer.write("client writer close", true);
    try std.testing.expectError(
        error.ConnectionClosed,
        writer.write("after end", false),
    );
    var second_data = try second.read();
    defer second_data.deinit(allocator);
    try std.testing.expectEqualStrings(
        "server writer close",
        second_data.data,
    );
    try std.testing.expect(second_data.end_stream);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.activeLocalStreamCount(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 writers reject status-forbidden response bodies" {
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(204, &.{}, "body", &.{}));
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(204, &.{.{ .name = "content-length", .value = "0" }}, "", &.{}));
    try validateResponseBodyForStatus(304, &.{.{ .name = "content-length", .value = "123" }}, "", &.{});
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(304, &.{}, "body", &.{}));
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(103, &.{.{ .name = "content-length", .value = "0" }}, "", &.{}));
    // Receive validation follows stream framing for 205; only outgoing
    // validation enforces the RFC 9110 server requirement.
    try validateResponseBodyForStatus(205, &.{.{ .name = "content-length", .value = "4" }}, "body", &.{});
    try std.testing.expectError(error.InvalidContentLength, validateOutgoingResponseBodyForStatus(205, &.{}, "body", &.{}));
    try std.testing.expectError(error.InvalidContentLength, validateOutgoingResponseBodyForStatus(205, &.{.{ .name = "content-length", .value = "1" }}, "", &.{}));
    try validateOutgoingResponseBodyForStatus(205, &.{.{ .name = "content-length", .value = "0" }}, "", &.{.{ .name = "x-checksum", .value = "ok" }});

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
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }
    try connection.reservePeerStream(1);
    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(1, .{
        .status = 204,
        .body = "body",
    }));
    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(1, .{
        .status = 205,
        .body = "body",
    }));
    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(1, .{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = "5" }},
        .body = "pong",
    }));
    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(1, .{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = "5" }},
    }));
    try std.testing.expectError(error.InvalidStatus, connection.writeResponse(1, .{
        .status = 103,
    }));
    try std.testing.expectError(error.InvalidStatus, connection.writeInformationalResponse(1, 200, &.{}));
    try std.testing.expectError(error.InvalidContentLength, connection.writeInformationalResponse(1, 103, &.{
        .{ .name = "content-length", .value = "0" },
    }));
    try std.testing.expectError(error.InvalidContentLength, connection.writeExtendedConnectResponse(1, 103, &.{
        .{ .name = "content-length", .value = "0" },
    }, false));
    try std.testing.expectError(error.InvalidContentLength, connection.writeExtendedConnectResponse(1, 200, &.{
        .{ .name = "content-length", .value = "1" },
    }, false));

    var connect_headers: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer connect_headers.deinit(std.testing.allocator);
    try connect_headers.appendSlice(std.testing.allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "0" },
        .{ .name = "content-length", .value = "0" },
        .{ .name = "x-ok", .value = "kept" },
    });
    try stripSuccessfulConnectContentLength(&connect_headers);
    try std.testing.expect(findHeader(connect_headers.items, "content-length") == null);
    try std.testing.expectEqualStrings("kept", findHeader(connect_headers.items, "x-ok") orelse return error.MissingPseudoHeader);
}
