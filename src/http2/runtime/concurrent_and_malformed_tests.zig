//! HTTP/2 concurrent-handler and malformed-request tests.

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

test "HTTP/2 concurrent handler batch answers PING while a handler waits" {
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
            if (std.mem.eql(u8, request.path, "/slow-ping")) {
                self.slow_started.set(self.io);
                try self.release_slow.wait(self.io);
            } else {
                try self.slow_started.wait(self.io);
            }
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
        .path = "/slow-ping",
        .authority = "localhost",
    });
    const fast = try client.sendCompleteRequest(.{
        .path = "/fast-ping",
        .authority = "localhost",
    });
    try shared.context.slow_started.wait(io);

    // Put an application HEADERS frame ahead of the PING. The batch owner
    // must retain it for the next serveOne call while still reaching and
    // acknowledging the connection-level frame behind it.
    const after = try client.sendCompleteRequest(.{
        .path = "/after-ping",
        .authority = "localhost",
    });
    const ping_payload = [_]u8{ 3, 1, 4, 1, 5, 9, 2, 6 };
    const ping_ack = try client.pingWithTimeout(
        ping_payload,
        .fromMilliseconds(500),
    );
    try std.testing.expectEqualSlices(u8, &ping_payload, &ping_ack);

    var fast_response = try client.readResponse(
        fast.stream_id,
        fast.request_method,
        fast.extended_connect,
        null,
    );
    defer fast_response.deinit(allocator);
    try std.testing.expectEqualStrings("/fast-ping", fast_response.body);

    shared.context.release_slow.set(io);
    var slow_response = try client.readResponse(
        slow.stream_id,
        slow.request_method,
        slow.extended_connect,
        null,
    );
    defer slow_response.deinit(allocator);
    try std.testing.expectEqualStrings("/slow-ping", slow_response.body);
    var after_response = try client.readResponse(
        after.stream_id,
        after.request_method,
        after.extended_connect,
        null,
    );
    defer after_response.deinit(allocator);
    try std.testing.expectEqualStrings("/after-ping", after_response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.successes);
}

test "HTTP/2 concurrent handler batch does not delay completion behind partial frame" {
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
        handlers_started: std.atomic.Value(usize) = .init(0),
        release_fast: std.Io.Event = .unset,
        release_slow: std.Io.Event = .unset,

        fn handle(
            self: *@This(),
            request: OwnedRequest,
        ) Error!ResponseOptions {
            _ = self.handlers_started.fetchAdd(1, .release);
            if (std.mem.eql(u8, request.path, "/partial-slow")) {
                try self.release_slow.wait(self.io);
            } else {
                try self.release_fast.wait(self.io);
            }
            return .{ .body = request.path };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context,
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
            try std.testing.expectEqual(@as(usize, 2), result.successCount());
        }
    };
    var shared = Shared{
        .server = &server,
        .context = .{ .io = io },
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.context.release_fast.set(io);
        shared.context.release_slow.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const slow = try client.sendCompleteRequest(.{
        .path = "/partial-slow",
        .authority = "localhost",
    });
    const fast = try client.sendCompleteRequest(.{
        .path = "/partial-fast",
        .authority = "localhost",
    });
    while (shared.context.handlers_started.load(.acquire) != 2) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }

    var ping_header: [http2.FrameHeader.encoded_len]u8 = undefined;
    try encodeFrameHeader(&ping_header, .ping, 0, 0, 8);
    try writeAll(io, client.stream, ping_header[0..1]);
    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    shared.context.release_fast.set(io);

    var fast_response = try client.readResponseWithTimeout(
        fast.stream_id,
        fast.request_method,
        fast.extended_connect,
        .fromMilliseconds(500),
    );
    defer fast_response.deinit(allocator);
    try std.testing.expectEqualStrings("/partial-fast", fast_response.body);

    const first_ping = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try writeAll(io, client.stream, ping_header[1..]);
    try writeAll(io, client.stream, &first_ping);
    const second_ping = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    const ping_ack = try client.pingWithTimeout(
        second_ping,
        .fromMilliseconds(500),
    );
    try std.testing.expectEqualSlices(u8, &second_ping, &ping_ack);

    shared.context.release_slow.set(io);
    var slow_response = try client.readResponse(
        slow.stream_id,
        slow.request_method,
        slow.extended_connect,
        null,
    );
    defer slow_response.deinit(allocator);
    try std.testing.expectEqualStrings("/partial-slow", slow_response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime rejects malformed CONTINUATION sequence" {
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
                if (err == error.UnexpectedFrame) {
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
        .{ .name = ":path", .value = "/bad-continuation" },
        .{ .name = ":scheme", .value = "https" },
    });
    const split = block.items.len / 2;
    try writeFrame(allocator, io, client.stream, .headers, 0, 1, block.items[0..split]);
    try writeFrame(allocator, io, client.stream, .continuation, flag_end_headers, 3, block.items[split..]);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 serveOne maps malformed HPACK to COMPRESSION_ERROR GOAWAY" {
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

        fn handle(ctx: *@This(), _: OwnedRequest) Error!ResponseOptions {
            ctx.calls += 1;
            return .{};
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
                if (err == error.InvalidEncoding) {
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
    // Indexed representation with index zero is invalid HPACK.
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 1, &.{0x80});
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.compression_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("hpack-decode", goaway.goaway.debug_data);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
}

test "HTTP/2 serveOne maps malformed CONTINUATION to PROTOCOL_ERROR GOAWAY" {
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

        fn handle(ctx: *@This(), _: OwnedRequest) Error!ResponseOptions {
            ctx.calls += 1;
            return .{};
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
                if (err == error.UnexpectedFrame) {
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
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad-continuation-goaway" },
        .{ .name = ":scheme", .value = "http" },
    });
    const split = block.items.len / 2;
    try writeFrame(allocator, io, client.stream, .headers, flag_end_stream, 1, block.items[0..split]);
    try writeFrame(allocator, io, client.stream, .continuation, flag_end_headers, 3, block.items[split..]);
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("frame-sequence", goaway.goaway.debug_data);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
}

test "HTTP/2 serveOne maps unterminated continuation flood to ENHANCE_YOUR_CALM GOAWAY" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_continuation_frames = 1 },
    );
    defer server.deinit();

    const Context = struct {
        calls: usize = 0,
        fn handle(ctx: *@This(), _: OwnedRequest) Error!ResponseOptions {
            ctx.calls += 1;
            return .{};
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
                if (err == error.MessageTooLarge) {
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
    try writeFrame(allocator, io, client.stream, .headers, flag_end_stream, 1, &.{0x82});
    try writeFrame(allocator, io, client.stream, .continuation, 0, 1, &.{0x84});
    try writeFrame(allocator, io, client.stream, .continuation, 0, 1, &.{0x86});
    var wire_error = try readFrame(
        allocator,
        io,
        client.stream,
        client.limits,
    );
    defer wire_error.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.goaway, wire_error.frame.header.frame_type);
    const goaway = try http2.GoAwayPayload.parse(wire_error.frame);
    try std.testing.expectEqual(http2.ErrorCode.enhance_your_calm, goaway.error_code);
    try std.testing.expectEqualStrings("header-block-limit", goaway.debug_data);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
}

test "HTTP/2 serveConcurrent maps malformed HPACK to COMPRESSION_ERROR GOAWAY" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
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

        pub fn handle(ctx: *@This(), _: OwnedRequest) Error!ResponseOptions {
            ctx.calls += 1;
            return .{};
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(
                Context,
                &shared.context,
                Context.handle,
                1,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 1, &.{0x80});
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.compression_error, goaway.goaway.error_code);

    thread.join();
    if (shared.err) |err| return err;
    var result = shared.result orelse return error.UnexpectedFrame;
    defer result.deinit();
    try std.testing.expectEqual(error.InvalidEncoding, result.firstError().?);
    try std.testing.expectEqual(@as(usize, 0), result.successCount());
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
}

test "HTTP/2 async std.Io server handles concurrent h2c clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
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
        pub fn handle(_: *@This(), request: OwnedRequest) Error!ResponseOptions {
            if (!std.mem.eql(u8, request.method, "POST")) return error.UnexpectedFrame;
            if (std.mem.eql(u8, request.path, "/one")) {
                return .{ .status = 200, .body = "h2-one" };
            }
            if (std.mem.eql(u8, request.path, "/two")) {
                return .{ .status = 200, .body = "h2-two" };
            }
            return .{ .status = 404, .body = "missing" };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        path: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            });
            defer client.close();

            var response = try client.request(.{
                .method = "POST",
                .path = task.path,
                .authority = "localhost",
                .body = "hello",
            });
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(@as(u16, 200), response.status);
            try std.testing.expectEqualStrings(task.expected, response.body);
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .path = "/one", .expected = "h2-one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .path = "/two", .expected = "h2-two" },
    };
    const client_one = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_two = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    client_one.join();
    client_two.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    if (result.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), result.successCount());
}

test "HTTP/2 serveConcurrent converts handler informational status per connection" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
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
        fn handle(_: *@This(), request: OwnedRequest) Error!ResponseOptions {
            if (std.mem.eql(u8, request.path, "/invalid-final")) {
                return .{ .status = 103 };
            }
            return .{ .status = 204 };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(
                Context,
                &shared.context,
                Context.handle,
                2,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        path: []const u8,
        expected_status: u16,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            task.runFallible() catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            });
            defer client.close();
            var response = try client.request(.{
                .path = task.path,
                .authority = "localhost",
            });
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(task.expected_status, response.status);
            try std.testing.expectEqualStrings("", response.body);
        }
    };
    var clients = [_]ClientTask{
        .{
            .allocator = allocator,
            .io = io,
            .address = server.address(),
            .path = "/invalid-final",
            .expected_status = 500,
        },
        .{
            .allocator = allocator,
            .io = io,
            .address = server.address(),
            .path = "/sibling",
            .expected_status = 204,
        },
    };
    const invalid_client = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const sibling_client = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    invalid_client.join();
    sibling_client.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    try std.testing.expectEqual(@as(usize, 1), result.successCount());
    try std.testing.expectEqual(error.InvalidStatus, result.firstError().?);
    var invalid_count: usize = 0;
    for (result.errors) |result_error| {
        if (result_error) |err| {
            try std.testing.expectEqual(error.InvalidStatus, err);
            invalid_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), invalid_count);
}
