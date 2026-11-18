//! HTTP/2 pending-request queue and reset-tombstone tests.

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

test "HTTP/2 pending request queue reuses consumed slots" {
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
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
            pending.deinit(allocator);
        }
        connection.pending_requests.deinit(allocator);
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.pending_requests.ensureTotalCapacityPrecise(allocator, 4);
    try queueTestPendingRequest(&connection, 1, "/one", allocator);
    try queueTestPendingRequest(&connection, 3, "/three", allocator);
    try queueTestPendingRequest(&connection, 5, "/five", allocator);
    try queueTestPendingRequest(&connection, 7, "/seven", allocator);

    var first = connection.popPendingRequest() orelse
        return error.TestUnexpectedResult;
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), first.stream_id);
    try std.testing.expectEqual(@as(usize, 3), connection.pendingRequestCount());
    try std.testing.expectEqual(@as(usize, 1), connection.pending_request_head);

    // The queue is logically non-empty and physically full with one consumed
    // head element. A new interleaved complete request should compact and reuse
    // that slot rather than allocate during a burst of peer request completions.
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try queueTestPendingRequest(&connection, 9, "/nine", no_alloc.allocator());
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 4), connection.pendingRequestCount());
    try std.testing.expectEqual(@as(usize, 0), connection.pending_request_head);

    for ([_]u31{ 3, 5, 7, 9 }) |expected_stream_id| {
        var pending = connection.popPendingRequest() orelse
            return error.TestUnexpectedResult;
        defer pending.deinit(allocator);
        try std.testing.expectEqual(expected_stream_id, pending.stream_id);
    }
    try std.testing.expect(connection.popPendingRequest() == null);
    try std.testing.expectEqual(@as(usize, 0), connection.pending_requests.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.pending_request_head);
}

test "HTTP/2 pending request queue skips peer-reset tombstones" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_pending_accept_reset_streams = 2 },
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
            pending.deinit(allocator);
        }
        connection.pending_requests.deinit(allocator);
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try queueTestPendingRequest(&connection, 1, "/one", allocator);
    try queueTestPendingRequest(&connection, 3, "/three", allocator);
    try queueTestPendingRequest(&connection, 5, "/five", allocator);

    try std.testing.expect(!connection.markPendingRequestReset(3));
    try std.testing.expectEqual(@as(usize, 1), connection.pendingAcceptResetStreamCount());
    try std.testing.expectEqual(@as(usize, 3), connection.pendingRequestCount());

    var first = connection.popPendingRequest() orelse
        return error.TestUnexpectedResult;
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), first.stream_id);
    try std.testing.expectEqual(@as(usize, 1), connection.pendingAcceptResetStreamCount());

    var second = connection.popPendingRequest() orelse
        return error.TestUnexpectedResult;
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 5), second.stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingAcceptResetStreamCount());

    try std.testing.expect(connection.popPendingRequest() == null);
    try std.testing.expectEqual(@as(usize, 0), connection.pending_requests.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.pending_request_head);
}

test "HTTP/2 pending request reset accounting preserves unrelated queue entries" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_pending_accept_reset_streams = 4 },
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
            pending.deinit(allocator);
        }
        connection.pending_requests.deinit(allocator);
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try queueTestPendingRequest(&connection, 1, "/one", allocator);
    try queueTestPendingRequest(&connection, 3, "/three", allocator);
    try queueTestPendingRequest(&connection, 5, "/five", allocator);

    try std.testing.expect(!connection.markPendingRequestReset(3));
    try std.testing.expectEqual(@as(usize, 1), connection.pendingAcceptResetStreamCount());
    try std.testing.expect(!connection.markPendingRequestReset(3));
    try std.testing.expectEqual(@as(usize, 1), connection.pendingAcceptResetStreamCount());
    try std.testing.expect(!connection.markPendingRequestReset(99));
    try std.testing.expectEqual(@as(usize, 1), connection.pendingAcceptResetStreamCount());

    for ([_]u31{ 1, 5 }) |expected_stream_id| {
        var pending = connection.popPendingRequest() orelse
            return error.TestUnexpectedResult;
        defer pending.deinit(allocator);
        try std.testing.expectEqual(expected_stream_id, pending.stream_id);
    }
    try std.testing.expect(connection.popPendingRequest() == null);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingAcceptResetStreamCount());
}

test "HTTP/2 pending request reset tombstone reuses consumed slot without allocation" {
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
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
            pending.deinit(allocator);
        }
        connection.pending_requests.deinit(allocator);
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.pending_requests.ensureTotalCapacityPrecise(allocator, 4);
    try queueTestPendingRequest(&connection, 1, "/one", allocator);
    try queueTestPendingRequest(&connection, 3, "/three", allocator);
    try queueTestPendingRequest(&connection, 5, "/five", allocator);
    try queueTestPendingRequest(&connection, 7, "/seven", allocator);
    try std.testing.expect(!connection.markPendingRequestReset(3));

    var first = connection.popPendingRequest() orelse
        return error.TestUnexpectedResult;
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), first.stream_id);

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try queueTestPendingRequest(&connection, 9, "/nine", no_alloc.allocator());
    try std.testing.expect(!no_alloc.has_induced_failure);

    for ([_]u31{ 5, 7, 9 }) |expected_stream_id| {
        var pending = connection.popPendingRequest() orelse
            return error.TestUnexpectedResult;
        defer pending.deinit(allocator);
        try std.testing.expectEqual(expected_stream_id, pending.stream_id);
    }
    try std.testing.expect(connection.popPendingRequest() == null);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingAcceptResetStreamCount());
}

test "HTTP/2 readRequest skips queued sibling reset and preserves unrelated request" {
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequestWithDeadline(.fromNow(
                connection.io,
                .{ .raw = .fromSeconds(2), .clock = .awake },
            ));
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqualStrings("/first", first.path);
            try std.testing.expectEqualStrings("first-body", first.body);

            var second = try connection.readRequestWithDeadline(.fromNow(
                connection.io,
                .{ .raw = .fromSeconds(2), .clock = .awake },
            ));
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 5), second.stream_id);
            try std.testing.expectEqualStrings("/third", second.path);
            try std.testing.expectEqualStrings("", second.body);
            try std.testing.expectEqual(@as(usize, 0), connection.pendingAcceptResetStreamCount());
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
        .{ .name = ":path", .value = "/first" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "10" },
    }, false);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/second" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.sendResetStream(3, .cancel);
    try client.writeHeaders(5, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/third" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.writeData(1, "first-body", true);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 readRequestStreaming skips queued sibling reset and preserves unrelated request" {
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
        first_bytes: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            const SharedState = @This();

            var first = try connection.readRequestStreamingWithDeadline(
                .fromNow(connection.io, .{
                    .raw = .fromSeconds(2),
                    .clock = .awake,
                }),
                shared,
                struct {
                    fn consume(shared_ptr: *SharedState, chunk: []const u8) Error!void {
                        shared_ptr.first_bytes += chunk.len;
                    }
                }.consume,
            );
            defer first.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqual(@as(usize, 10), shared.first_bytes);

            var second = try connection.readRequestStreamingWithDeadline(
                .fromNow(connection.io, .{
                    .raw = .fromSeconds(2),
                    .clock = .awake,
                }),
                {},
                struct {
                    fn consume(_: void, _: []const u8) Error!void {}
                }.consume,
            );
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 5), second.stream_id);
            try std.testing.expectEqualStrings("/third-streaming", second.path);
            try std.testing.expectEqual(@as(usize, 0), connection.pendingAcceptResetStreamCount());
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
        .{ .name = ":path", .value = "/first-streaming" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "10" },
    }, false);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/second-streaming" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.sendResetStream(3, .cancel);
    try client.writeHeaders(5, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/third-streaming" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.writeData(1, "first-body", true);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 pending accept reset overflow sends ENHANCE_YOUR_CALM GOAWAY" {
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
            .max_pending_accept_reset_streams = 1,
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

            try std.testing.expectError(
                error.ConnectionGoAway,
                connection.readRequestWithDeadline(.fromNow(
                    connection.io,
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                )),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_pending_accept_reset_streams = 1,
    });
    defer client.close();

    try client.writeHeaders(1, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/first-overflow" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "10" },
    }, false);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/cancel-one" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.sendResetStream(3, .cancel);
    try client.writeHeaders(5, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/cancel-two" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.sendResetStream(5, .cancel);
    try client.writeData(1, "first-body", true);

    var goaway = try client.readGoAwayWithDeadline(.fromNow(
        client.io,
        .{ .raw = .fromSeconds(2), .clock = .awake },
    ));
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 5), goaway.goaway.last_stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        goaway.goaway.error_code,
    );
    try std.testing.expectEqualStrings(
        "too_many_resets",
        goaway.goaway.debug_data,
    );

    thread.join();
    if (shared.err) |err| return err;
}
