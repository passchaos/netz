//! HTTP/2 client response, informational, and malformed-response tests.

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

test "HTTP/2 client answers PING while reading response" {
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
            try std.testing.expectEqualStrings("/response-ping", request.path);

            const ping_payload = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .ping, 0, 0, &ping_payload);
            var ping_ack = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
            defer ping_ack.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http2.FrameType.ping, ping_ack.frame.header.frame_type);
            try std.testing.expect((ping_ack.frame.header.flags & flag_ack) != 0);
            try std.testing.expectEqualSlices(u8, &ping_payload, ping_ack.frame.payload);

            try connection.writeResponse(request.stream_id, .{ .body = "after-ping" });
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
        .path = "/response-ping",
        .authority = "localhost",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("after-ping", response.body);
}

test "HTTP/2 client skips informational responses before final response" {
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
            try std.testing.expectEqualStrings("/interim-h2", request.path);

            try connection.writeInformationalResponse(request.stream_id, 103, &.{.{ .name = "link", .value = "</style.css>; rel=preload" }});
            try connection.writeResponse(request.stream_id, .{ .body = "final" });
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
        .path = "/interim-h2",
        .authority = "localhost",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("final", response.body);
}

test "HTTP/2 response writers reject a stream after its final response" {
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

            var first = try connection.readRequest();
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/first", first.path);
            try connection.writeResponse(first.stream_id, .{ .body = "one" });
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );
            try std.testing.expectError(
                error.InvalidStreamId,
                connection.writeResponse(first.stream_id, .{ .body = "duplicate" }),
            );
            try std.testing.expectError(
                error.InvalidStreamId,
                connection.writeInformationalResponse(
                    first.stream_id,
                    103,
                    &.{},
                ),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );

            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/second", second.path);
            try connection.writeResponse(second.stream_id, .{ .body = "two" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var first = try client.request(.{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.body);

    var second = try client.request(.{
        .method = "GET",
        .path = "/second",
        .authority = "localhost",
    });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client observes bounded informational responses in order" {
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
            for (0..4) |index| {
                var request = try connection.readRequest();
                defer request.deinit(server_ptr.allocator);
                try connection.writeInformationalResponse(
                    request.stream_id,
                    103,
                    &.{.{ .name = "link", .value = "</style.css>" }},
                );
                try connection.writeInformationalResponse(
                    request.stream_id,
                    102,
                    &.{.{ .name = "x-progress", .value = "half" }},
                );
                if (index == 3) {
                    try connection.writeInformationalResponse(
                        request.stream_id,
                        103,
                        &.{.{ .name = "link", .value = "</late.css>" }},
                    );
                }
                try connection.writeResponse(request.stream_id, .{
                    .body = "final",
                    .request_method = request.method,
                });
            }
        }
    };

    const Observer = struct {
        statuses: [4]u16 = undefined,
        count: usize = 0,
        valid_headers: bool = true,

        fn observe(context_ptr: *anyopaque, head: StreamingResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.statuses[self.count] = head.status;
            self.valid_headers = self.valid_headers and
                findHeader(head.headers, "date") == null;
            const expected_name = if (head.status == 103)
                "link"
            else
                "x-progress";
            const expected_value = if (head.status == 103)
                "</style.css>"
            else
                "half";
            self.valid_headers = self.valid_headers and
                std.mem.eql(
                    u8,
                    findHeader(head.headers, expected_name) orelse "",
                    expected_value,
                );
            self.count += 1;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_informational_responses = 2,
    });
    defer client.close();

    var aggregate_observer = Observer{};
    var aggregate = try client.requestWithInformational(.{
        .path = "/informational-aggregate",
        .authority = "localhost",
    }, .{
        .context = &aggregate_observer,
        .on_response = Observer.observe,
    });
    defer aggregate.deinit(allocator);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        aggregate_observer.statuses[0..aggregate_observer.count],
    );
    try std.testing.expect(aggregate_observer.valid_headers);
    try std.testing.expectEqualStrings("final", aggregate.body);
    try std.testing.expectEqual(
        @as(usize, http_date.value_len),
        findHeader(aggregate.headers, "date").?.len,
    );

    var streaming_observer = Observer{};
    var body_bytes: usize = 0;
    var streaming = try client.requestStreamingWithInformational(.{
        .path = "/informational-streaming",
        .authority = "localhost",
    }, .{
        .context = &streaming_observer,
        .on_response = Observer.observe,
    }, &body_bytes, struct {
        fn consume(count: *usize, data: []const u8) !void {
            count.* += data.len;
        }
    }.consume);
    defer streaming.deinit(allocator);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        streaming_observer.statuses[0..streaming_observer.count],
    );
    try std.testing.expect(streaming_observer.valid_headers);
    try std.testing.expectEqual(@as(usize, 5), body_bytes);

    var writer = try client.startRequest(.{
        .path = "/informational-writer",
        .authority = "localhost",
        .body_length = 0,
    });
    defer writer.deinit();
    try writer.finish();
    var writer_observer = Observer{};
    var writer_response = try writer.readResponseWithInformational(.{
        .context = &writer_observer,
        .on_response = Observer.observe,
    });
    defer writer_response.deinit(allocator);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        writer_observer.statuses[0..writer_observer.count],
    );
    try std.testing.expect(writer_observer.valid_headers);
    try std.testing.expectEqualStrings("final", writer_response.body);

    try std.testing.expectError(
        error.TooManyInformationalResponses,
        client.request(.{
            .path = "/informational-over-limit",
            .authority = "localhost",
        }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client rejects 101 switching protocols response" {
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
            try std.testing.expectEqualStrings("/bad-101-h2", request.path);

            // RFC 9113 has no 101 upgrade path; HTTP/2 peers must use extended
            // CONNECT instead.  Send raw HEADERS so this remains a receive-path
            // regression even if the writer helper rejects 101 in the future.
            try connection.writeHeaders(request.stream_id, &.{
                .{ .name = ":status", .value = "101" },
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

    try std.testing.expectError(error.InvalidStatus, client.request(.{
        .method = "GET",
        .path = "/bad-101-h2",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client resets malformed response stream and reuses connection" {
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

    const Shared = struct {
        server: *Server,
        saw_reset: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            try connection.writeHeaders(first.stream_id, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "connection", .value = "close" },
            }, true);
            var reset = try connection.readResetStream();
            defer reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(first.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);
            shared.saw_reset = true;

            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings("/good-after-bad-response", second.path);
            try connection.writeResponse(second.stream_id, .{
                .status = 204,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidHeader, client.request(.{
        .path = "/bad-response",
        .authority = "localhost",
    }));
    var response = try client.request(.{
        .path = "/good-after-bad-response",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.status);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_reset);
}

test "HTTP/2 streaming client resets malformed response and reuses connection" {
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

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            try connection.writeHeaders(first.stream_id, &.{
                .{ .name = ":status", .value = "204" },
                .{ .name = "content-length", .value = "0" },
            }, true);
            var reset = try connection.readResetStream();
            defer reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(first.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);

            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings("/streaming-sibling", second.path);
            try connection.writeResponse(second.stream_id, .{
                .status = 204,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidContentLength, client.requestStreaming(
        .{ .path = "/bad-streaming-response", .authority = "localhost" },
        {},
        struct {
            fn consume(_: void, _: []const u8) !void {}
        }.consume,
    ));
    var response = try client.request(.{
        .path = "/streaming-sibling",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.status);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate batch resets malformed member cancels sibling and reuses connection" {
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

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqual(@as(u31, 3), second.stream_id);

            try connection.writeHeaders(first.stream_id, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "connection", .value = "close" },
            }, true);
            var first_reset = try connection.readResetStream();
            defer first_reset.deinit(shared.server.allocator);
            var second_reset = try connection.readResetStream();
            defer second_reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first_reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.protocol_error, first_reset.reset.error_code);
            try std.testing.expectEqual(@as(u31, 3), second_reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.cancel, second_reset.reset.error_code);

            var third = try connection.readRequest();
            defer third.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 5), third.stream_id);
            try connection.writeResponse(third.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    var responses: [2]OwnedResponse = undefined;
    try std.testing.expectError(error.InvalidHeader, client.requestBatchInto(
        &.{
            .{ .path = "/bad-batch-response", .authority = "localhost" },
            .{ .path = "/cancelled-batch-sibling", .authority = "localhost" },
        },
        &responses,
    ));
    var third = try client.request(.{
        .path = "/after-batch-error",
        .authority = "localhost",
    });
    defer third.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), third.status);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 streaming batch resets malformed member and cancels sibling" {
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

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqual(@as(u31, 3), second.stream_id);

            try connection.writeHeaders(first.stream_id, &.{
                .{ .name = ":status", .value = "204" },
                .{ .name = "content-length", .value = "0" },
            }, true);
            var first_reset = try connection.readResetStream();
            defer first_reset.deinit(shared.server.allocator);
            var second_reset = try connection.readResetStream();
            defer second_reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first_reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.protocol_error, first_reset.reset.error_code);
            try std.testing.expectEqual(@as(u31, 3), second_reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.cancel, second_reset.reset.error_code);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    var responses: [2]StreamingResponse = undefined;
    try std.testing.expectError(
        error.InvalidContentLength,
        client.requestBatchStreamingInto(
            &.{
                .{ .path = "/bad-streaming-batch", .authority = "localhost" },
                .{ .path = "/cancel-streaming-sibling", .authority = "localhost" },
            },
            &responses,
            {},
            struct {
                fn consume(_: void, _: usize, _: []const u8) !void {}
            }.consume,
        ),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate batch maps malformed HPACK to one GOAWAY" {
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

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .headers,
                flag_end_headers | flag_end_stream,
                first.stream_id,
                &.{0x80},
            );
            var goaway = try readFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                connection.limits,
            );
            defer goaway.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                http2.FrameType.goaway,
                goaway.frame.header.frame_type,
            );
            try std.testing.expectEqual(
                http2.ErrorCode.compression_error,
                (try http2.GoAwayPayload.parse(goaway.frame)).error_code,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    var responses: [2]OwnedResponse = undefined;
    try std.testing.expectError(error.InvalidEncoding, client.requestBatchInto(
        &.{
            .{ .path = "/bad-batch-hpack", .authority = "localhost" },
            .{ .path = "/hpack-sibling", .authority = "localhost" },
        },
        &responses,
    ));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate batch does not reset an already peer-reset member" {
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

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try connection.sendResetStream(first.stream_id, .refused_stream);

            // The peer-originated reset already closed stream 1. Batch cleanup
            // should send exactly one local cancellation for stream 3.
            var sibling_reset = try connection.readResetStream();
            defer sibling_reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(second.stream_id, sibling_reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.cancel, sibling_reset.reset.error_code);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    var responses: [2]OwnedResponse = undefined;
    try std.testing.expectError(error.StreamReset, client.requestBatchInto(
        &.{
            .{ .path = "/peer-reset", .authority = "localhost" },
            .{ .path = "/cancel-after-peer-reset", .authority = "localhost" },
        },
        &responses,
    ));

    thread.join();
    if (shared.err) |err| return err;
}
