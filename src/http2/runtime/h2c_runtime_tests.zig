//! HTTP/2 h2c runtime and 100-continue tests.

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

test "HTTP/2 h2c runtime client and server exchange over TCP" {
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

            var client_window = try connection.readWindowUpdate();
            defer client_window.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 0), client_window.window_update.stream_id);
            try std.testing.expectEqual(@as(u31, 4096), client_window.window_update.increment);

            const ping_data = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &[_]u8{ 8, 6, 7, 5, 3, 0, 9, 9 }, &ping_data);

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("POST", request.method);
            try std.testing.expectEqualStrings("/echo", request.path);
            try std.testing.expectEqualStrings("ping", request.body);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "pong",
            });
            try connection.sendWindowUpdate(0, 2048);
            try connection.sendWindowUpdate(request.stream_id, 1024);
            try connection.sendGoAway(request.stream_id, .no_error, "done");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try client.sendWindowUpdate(0, 4096);
    const ping_ack = try client.ping(.{ 8, 6, 7, 5, 3, 0, 9, 9 });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 8, 6, 7, 5, 3, 0, 9, 9 }, &ping_ack);

    var response = try client.request(.{
        .method = "POST",
        .path = "/echo",
        .authority = "127.0.0.1",
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "ping",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("pong", response.body);
    try std.testing.expectEqualStrings("text/plain", findHeader(response.headers, "content-type").?);
    var window = try client.readWindowUpdate();
    defer window.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 2048), window.window_update.increment);
    try std.testing.expectEqual(@as(i64, default_flow_window + 2048 - "ping".len), client.send_connection_window.value);
    var stream_window = try client.readWindowUpdate();
    defer stream_window.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), stream_window.window_update.stream_id);
    try std.testing.expectEqual(@as(u31, 1024), stream_window.window_update.increment);
    // The response closed stream 1 before this late WINDOW_UPDATE arrived.
    // Return the frame to the explicit observer without recreating the
    // retired stream's window. RFC 9113 permits ignoring this race.
    try std.testing.expectEqual(@as(usize, 0), client.send_stream_window_index.count());
    try std.testing.expectEqual(@as(usize, 0), client.send_stream_windows.items.len);
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.no_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("done", goaway.goaway.debug_data);
}

test "HTTP/2 server sends 100 Continue before reading an expected body" {
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
            try std.testing.expectEqualStrings("/expect", request.path);
            try std.testing.expectEqualStrings("ping", request.body);
            try std.testing.expectEqualStrings(
                "100-continue",
                findHeader(request.headers, "expect").?,
            );
            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = "pong",
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

    const Observer = struct {
        seen_continue: bool = false,

        fn onResponse(context: *anyopaque, response: StreamingResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (response.status == 100) self.seen_continue = true;
        }
    };
    var observer = Observer{};
    var response = try client.requestWithInformational(.{
        .method = "POST",
        .path = "/expect",
        .authority = "127.0.0.1",
        .headers = &.{.{ .name = "expect", .value = "100-continue" }},
        .body = "ping",
    }, .{
        .context = &observer,
        .on_response = Observer.onResponse,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expect(observer.seen_continue);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("pong", response.body);
}

test "HTTP/2 streaming server sends 100 Continue before body callbacks" {
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

            const Sink = struct {
                bytes: usize = 0,

                fn consume(self: *@This(), data: []const u8) !void {
                    self.bytes += data.len;
                }
            };
            var sink = Sink{};
            var request = try connection.readRequestStreaming(
                &sink,
                Sink.consume,
            );
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/expect-streaming", request.path);
            try std.testing.expectEqual(@as(usize, 4), sink.bytes);
            try std.testing.expectEqualStrings(
                "100-continue",
                findHeader(request.headers, "expect").?,
            );
            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = "pong",
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

    var writer = try client.startRequest(.{
        .method = "POST",
        .path = "/expect-streaming",
        .authority = "127.0.0.1",
        .headers = &.{.{ .name = "expect", .value = "100-continue" }},
        .body_length = 4,
    });
    defer writer.deinit();
    try writer.write("ping");
    try writer.finish();

    const Observer = struct {
        seen_continue: bool = false,

        fn onResponse(context: *anyopaque, response: StreamingResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (response.status == 100) self.seen_continue = true;
        }
    };
    var observer = Observer{};
    var response = try writer.readResponseWithInformational(.{
        .context = &observer,
        .on_response = Observer.onResponse,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expect(observer.seen_continue);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("pong", response.body);
}

test "HTTP/2 aggregate empty exchange borrows wire frames after warmup" {
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

            {
                var warmup = try connection.readRequest();
                defer warmup.deinit(server_ptr.allocator);
                try std.testing.expectEqualStrings("/measured", warmup.path);
                try connection.writeResponse(warmup.stream_id, .{});
            }

            const second_stream_id = blk: {
                var tracking = std.testing.FailingAllocator.init(
                    allocator,
                    .{},
                );
                const saved_allocator = connection.allocator;
                connection.allocator = tracking.allocator();
                defer connection.allocator = saved_allocator;

                var request = try connection.readRequest();
                defer request.deinit(connection.allocator);
                try std.testing.expectEqualStrings("/measured", request.path);
                try std.testing.expectEqualStrings("", request.body);
                // The owned HPACK fields and strings share one allocation. The
                // complete HEADERS wire frame remains borrowed from the
                // reusable frame-reader buffer.
                try std.testing.expectEqual(
                    @as(usize, 1),
                    tracking.allocations,
                );
                break :blk request.stream_id;
            };
            try connection.writeResponse(second_stream_id, .{});

            {
                var warmup = try connection.readRequest();
                defer warmup.deinit(server_ptr.allocator);
                try std.testing.expectEqualStrings(
                    "small-body",
                    warmup.body,
                );
                try connection.writeResponse(warmup.stream_id, .{});
            }

            const post_stream_id = blk: {
                var tracking = std.testing.FailingAllocator.init(
                    allocator,
                    .{},
                );
                const saved_allocator = connection.allocator;
                connection.allocator = tracking.allocator();
                defer connection.allocator = saved_allocator;

                var request = try connection.readRequest();
                defer request.deinit(connection.allocator);
                try std.testing.expectEqualStrings("POST", request.method);
                try std.testing.expectEqualStrings(
                    "small-body",
                    request.body,
                );
                // Known Content-Length reserves the exact body once. Together
                // with the combined HPACK block, no other allocation remains.
                try std.testing.expectEqual(
                    @as(usize, 2),
                    tracking.allocations,
                );
                break :blk request.stream_id;
            };
            try connection.writeResponse(post_stream_id, .{});

            for (0..2) |_| {
                var request = try connection.readRequest();
                defer request.deinit(server_ptr.allocator);
                try connection.writeResponse(request.stream_id, .{
                    .body = "small-body",
                });
            }

            {
                var body_bytes: usize = 0;
                var tracking = std.testing.FailingAllocator.init(
                    allocator,
                    .{},
                );
                const saved_allocator = connection.allocator;
                connection.allocator = tracking.allocator();
                defer connection.allocator = saved_allocator;

                var request = try connection.readRequestStreaming(
                    &body_bytes,
                    struct {
                        fn consume(
                            count: *usize,
                            data: []const u8,
                        ) !void {
                            count.* += data.len;
                        }
                    }.consume,
                );
                defer request.deinit(connection.allocator);
                try std.testing.expectEqual(@as(usize, 10), body_bytes);
                // Streaming DATA is borrowed and the HEADERS wire frame now
                // remains borrowed too, leaving only the owned HPACK block.
                try std.testing.expectEqual(
                    @as(usize, 1),
                    tracking.allocations,
                );
                try connection.writeResponse(request.stream_id, .{});
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
            .path = "/measured",
            .authority = "localhost",
        });
        defer warmup.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), warmup.status);
    }

    const pending = try client.sendCompleteRequest(.{
        .path = "/measured",
        .authority = "localhost",
    });
    {
        var tracking = std.testing.FailingAllocator.init(allocator, .{});
        const saved_allocator = client.allocator;
        client.allocator = tracking.allocator();
        defer client.allocator = saved_allocator;

        var response = try client.readResponse(
            pending.stream_id,
            pending.request_method,
            pending.extended_connect,
            null,
        );
        defer response.deinit(client.allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
        try std.testing.expectEqualStrings("", response.body);
        // As on the request side, aggregate ownership is one HPACK block.
        try std.testing.expectEqual(@as(usize, 1), tracking.allocations);
    }

    {
        var response = try client.request(.{
            .method = "POST",
            .path = "/measured",
            .authority = "localhost",
            .body = "small-body",
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
    }
    {
        var response = try client.request(.{
            .method = "POST",
            .path = "/measured",
            .authority = "localhost",
            .body = "small-body",
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
    }

    {
        var warmup = try client.request(.{
            .path = "/measured",
            .authority = "localhost",
        });
        defer warmup.deinit(allocator);
        try std.testing.expectEqualStrings("small-body", warmup.body);
    }
    {
        const response_pending = try client.sendCompleteRequest(.{
            .path = "/measured",
            .authority = "localhost",
        });
        var tracking = std.testing.FailingAllocator.init(allocator, .{});
        const saved_allocator = client.allocator;
        client.allocator = tracking.allocator();
        defer client.allocator = saved_allocator;

        var response = try client.readResponse(
            response_pending.stream_id,
            response_pending.request_method,
            response_pending.extended_connect,
            null,
        );
        defer response.deinit(client.allocator);
        try std.testing.expectEqualStrings("small-body", response.body);
        // The combined HPACK block and exact body buffer are the only owned
        // allocations for a warmed known-length aggregate response.
        try std.testing.expectEqual(@as(usize, 2), tracking.allocations);
    }

    {
        var response = try client.request(.{
            .method = "POST",
            .path = "/measured",
            .authority = "localhost",
            .body = "small-body",
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
    }

    thread.join();
    if (shared.err) |err| return err;
}
