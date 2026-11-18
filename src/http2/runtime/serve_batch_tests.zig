//! HTTP/2 serve and concurrent-handler batch tests.

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

test "HTTP/2 serveConnection handles sequential requests" {
    const allocator = std.testing.allocator;

    var backend = try @import("../../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        count: usize = 0,
        fn handle(ctx: *@This(), request: OwnedRequest) Error!ResponseOptions {
            ctx.count += 1;
            if (std.mem.eql(u8, request.path, "/one")) return .{ .body = "first" };
            if (std.mem.eql(u8, request.path, "/two")) return .{ .body = "second" };
            return .{ .status = 404, .body = "missing" };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        served: usize = 0,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            shared.served = shared.server.serveConnection(Context, &shared.context, Context.handle, 2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var first = try client.request(.{ .path = "/one" });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.body);
    var second = try client.request(.{ .path = "/two" });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("second", second.body);
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), goaway.goaway.last_stream_id);
    try std.testing.expectEqual(http2.ErrorCode.no_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("serve-complete", goaway.goaway.debug_data);

    server_task.await(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.served);
    try std.testing.expectEqual(@as(usize, 2), shared.context.count);
}

test "HTTP/2 serveOne converts handler informational status to final 500" {
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

    const Context = struct {
        calls: usize = 0,

        fn handle(
            self: *@This(),
            request: OwnedRequest,
        ) Error!ResponseOptions {
            self.calls += 1;
            if (std.mem.eql(u8, request.path, "/invalid-final")) {
                return .{ .status = 103 };
            }
            return .{ .status = 204 };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        first_error: ?anyerror = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            _ = connection.serveOne(
                Context,
                &self.context,
                Context.handle,
            ) catch |err| {
                self.first_error = err;
            };
            _ = try connection.serveOne(
                Context,
                &self.context,
                Context.handle,
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
    var invalid = try client.request(.{
        .path = "/invalid-final",
        .authority = "localhost",
    });
    defer invalid.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 500), invalid.status);
    try std.testing.expectEqualStrings("", invalid.body);
    var sibling = try client.request(.{
        .path = "/sibling",
        .authority = "localhost",
    });
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(error.InvalidStatus, shared.first_error.?);
    try std.testing.expectEqual(@as(usize, 2), shared.context.calls);
}

test "HTTP/2 concurrent handler batch converts informational status and isolates its error" {
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

    const Context = struct {
        fn handle(
            _: *@This(),
            request: OwnedRequest,
        ) Error!ResponseOptions {
            if (std.mem.eql(u8, request.path, "/invalid-final")) {
                return .{ .status = 103 };
            }
            if (std.mem.eql(u8, request.path, "/sibling")) {
                return .{ .status = 204 };
            }
            return .{ .body = request.path };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        successes: usize = 0,
        first_error: ?anyerror = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var result = try connection.serveRequestBatchConcurrent(
                Context,
                &self.context,
                Context.handle,
                2,
            );
            defer result.deinit();
            self.successes = result.successCount();
            self.first_error = result.firstError();
            try std.testing.expectEqual(@as(usize, 2), result.errors.len);
            try std.testing.expectEqual(error.InvalidStatus, result.errors[0].?);
            try std.testing.expect(result.errors[1] == null);
            _ = try connection.serveOne(
                Context,
                &self.context,
                Context.handle,
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
    const invalid_request = try client.sendCompleteRequest(.{
        .path = "/invalid-final",
        .authority = "localhost",
    });
    const sibling_request = try client.sendCompleteRequest(.{
        .path = "/sibling",
        .authority = "localhost",
    });
    {
        var states = [_]Connection.BatchResponseState{
            .{
                .stream_id = invalid_request.stream_id,
                .request_method = invalid_request.request_method,
                .extended_connect = invalid_request.extended_connect,
            },
            .{
                .stream_id = sibling_request.stream_id,
                .request_method = sibling_request.request_method,
                .extended_connect = sibling_request.extended_connect,
            },
        };
        defer for (&states) |*state| {
            client.releaseLocalStream(state.stream_id);
            state.deinit(allocator);
        };
        try client.readResponseBatch(&states, null, null);
        try std.testing.expectEqual(@as(?u16, 500), states[0].status);
        try std.testing.expectEqualStrings("", states[0].body_owned.?);
        try std.testing.expectEqual(@as(?u16, 204), states[1].status);
    }
    var after = try client.request(.{
        .path = "/after",
        .authority = "localhost",
    });
    defer after.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), after.status);
    try std.testing.expectEqualStrings("/after", after.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.successes);
    try std.testing.expectEqual(error.InvalidStatus, shared.first_error.?);
}

test "HTTP/2 concurrent handler batch writes responses in completion order" {
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

    const Context = struct {
        io: std.Io,
        slow_started: std.Io.Event = .unset,
        release_slow: std.Io.Event = .unset,

        fn handle(
            self: *@This(),
            request: OwnedRequest,
        ) Error!ResponseOptions {
            if (std.mem.eql(u8, request.path, "/slow")) {
                self.slow_started.set(self.io);
                try self.release_slow.wait(self.io);
                return .{ .body = request.path };
            }
            try self.slow_started.wait(self.io);
            return .{ .body = request.path };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context,
        successes: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var result = try connection.serveRequestBatchConcurrent(
                Context,
                &self.context,
                Context.handle,
                2,
            );
            defer result.deinit();
            self.successes = result.successCount();
            if (result.firstError()) |err| return err;
            _ = try connection.serveOne(
                Context,
                &self.context,
                Context.handle,
            );
            try connection.sendGoAway(5, .no_error, "batch-complete");
        }
    };
    var shared = Shared{
        .server = &server,
        .context = .{ .io = io },
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.context.release_slow.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const slow = try client.sendCompleteRequest(.{
        .path = "/slow",
        .authority = "localhost",
    });
    const fast = try client.sendCompleteRequest(.{
        .path = "/fast",
        .authority = "localhost",
    });
    var fast_response = try client.readResponse(
        fast.stream_id,
        fast.request_method,
        fast.extended_connect,
        null,
    );
    defer fast_response.deinit(allocator);
    try std.testing.expectEqualStrings("/fast", fast_response.body);
    shared.context.release_slow.set(io);
    var slow_response = try client.readResponse(
        slow.stream_id,
        slow.request_method,
        slow.extended_connect,
        null,
    );
    defer slow_response.deinit(allocator);
    try std.testing.expectEqualStrings("/slow", slow_response.body);
    var after = try client.request(.{
        .path = "/after",
        .authority = "localhost",
    });
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("/after", after.body);
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqualStrings("batch-complete", goaway.goaway.debug_data);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.successes);
}

test "HTTP/2 concurrent handler batch isolates handler errors" {
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

    const Context = struct {
        io: std.Io,
        release_failure: std.Io.Event = .unset,

        fn handle(
            self: *@This(),
            request: OwnedRequest,
        ) Error!ResponseOptions {
            if (std.mem.eql(u8, request.path, "/error")) {
                try self.release_failure.wait(self.io);
                return error.InvalidResponse;
            }
            return .{ .body = request.path };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context,
        successes: usize = 0,
        first_error: ?anyerror = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var result = try connection.serveRequestBatchConcurrent(
                Context,
                &self.context,
                Context.handle,
                2,
            );
            defer result.deinit();
            self.successes = result.successCount();
            self.first_error = result.firstError();
            try std.testing.expectEqual(@as(usize, 2), result.errors.len);
            try std.testing.expectEqual(
                error.InvalidResponse,
                result.errors[0].?,
            );
            try std.testing.expect(result.errors[1] == null);
            _ = try connection.serveOne(
                Context,
                &self.context,
                Context.handle,
            );
        }
    };
    var shared = Shared{
        .server = &server,
        .context = .{ .io = io },
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.context.release_failure.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const failed = try client.sendCompleteRequest(.{
        .path = "/error",
        .authority = "localhost",
    });
    const fast = try client.sendCompleteRequest(.{
        .path = "/fast",
        .authority = "localhost",
    });
    var fast_response = try client.readResponse(
        fast.stream_id,
        fast.request_method,
        fast.extended_connect,
        null,
    );
    defer fast_response.deinit(allocator);
    try std.testing.expectEqualStrings("/fast", fast_response.body);
    shared.context.release_failure.set(io);
    var reset = try client.readResetStream();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(failed.stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.internal_error, reset.reset.error_code);
    var after = try client.request(.{
        .path = "/after",
        .authority = "localhost",
    });
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("/after", after.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.successes);
    try std.testing.expectEqual(error.InvalidResponse, shared.first_error.?);
}

test "HTTP/2 concurrent handler batch accepts an empty server batch" {
    const Context = struct {
        fn handle(
            _: *@This(),
            _: OwnedRequest,
        ) Error!ResponseOptions {
            unreachable;
        }
    };
    var context: Context = .{};
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
    }
    var result = try connection.serveRequestBatchConcurrent(
        Context,
        &context,
        Context.handle,
        0,
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.errors.len);
    try std.testing.expectEqual(@as(usize, 0), result.successCount());
    try std.testing.expect(result.firstError() == null);

    connection.limits.max_concurrent_streams = 1;
    try std.testing.expectError(
        error.InvalidServeOptions,
        connection.serveRequestBatchConcurrent(
            Context,
            &context,
            Context.handle,
            2,
        ),
    );

    connection.limits.max_concurrent_streams = null;
    try connection.addActivePeerStream(1);
    defer connection.releasePeerStream(1);
    try std.testing.expectError(
        error.InvalidServeOptions,
        connection.serveRequestBatchConcurrent(
            Context,
            &context,
            Context.handle,
            1,
        ),
    );
}
