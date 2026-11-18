//! HTTP/2 runtime tests moved out of the runtime root.

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

test {
    _ = @import("client_and_upgrade_tests.zig");
    _ = @import("client_response_tests.zig");
    _ = @import("concurrent_tests.zig");
    _ = @import("connect_tunnel_tests.zig");
    _ = @import("content_length_and_date_tests.zig");
    _ = @import("control_readers_tests.zig");
    _ = @import("extended_connect_tests.zig");
    _ = @import("flow_control_tests.zig");
    _ = @import("graceful_shutdown_tests.zig");
    _ = @import("h2c_runtime_tests.zig");
    _ = @import("headers_priority_tests.zig");
    _ = @import("origin_altsvc_tests.zig");
    _ = @import("pending_request_tests.zig");
    _ = @import("protocol_error_tests.zig");
    _ = @import("writer_deadline_tests.zig");
    _ = @import("runtime_state_tests.zig");
    _ = @import("serve_batch_tests.zig");
    _ = @import("stream_and_header_tests.zig");
    _ = @import("settings/webtransport_tests.zig");
    _ = @import("stream_reset_tests.zig");
    _ = @import("client/authority_tests.zig");
    _ = @import("client/authority_deadline_tests.zig");
    _ = @import("client/authority_uri_tests.zig");
    _ = @import("headers/authority_reuse_tests.zig");
    _ = client_authority;
    _ = endpoint_host;
    _ = host_connect;
    _ = @import("connect/deadline_tests.zig");
    _ = @import("connect/output_deadline_tests.zig");
    _ = @import("connect/owned_accept.zig");
    _ = @import("connect/protocol_error_tests.zig");
    _ = @import("connect/tls_protocol_error_tests.zig");
    _ = @import("control/extension_deadline_tests.zig");
    _ = @import("control/output_deadline_tests.zig");
    _ = @import("control/protocol_error_deadline_tests.zig");
    _ = @import("control/tls_close_tests.zig");
    _ = @import("push/output_deadline_tests.zig");
    _ = @import("request/output_deadline_tests.zig");
    _ = @import("request/complete_deadline_tests.zig");
    _ = @import("request/cleanup_deadline_tests.zig");
    _ = @import("request/batch_output_deadline_tests.zig");
    _ = @import("request/batch_progress_tests.zig");
    _ = @import("request/batch_tls_deadline_tests.zig");
    _ = @import("request/complete_early_response_tests.zig");
    _ = @import("request/upload_tests.zig");
    _ = @import("response/output_deadline_tests.zig");
    _ = @import("response/stream_roundtrip_tests.zig");
    _ = @import("response/goaway_commitment_tests.zig");
    _ = @import("stream/termination_tests.zig");
    _ = @import("stream/peer_termination_tests.zig");
    _ = client_duplex_owner;
    _ = @import("duplex/client_tests.zig");
    _ = @import("duplex/client_pump_tests.zig");
    _ = @import("duplex/server_tests.zig");
    _ = @import("duplex/pump_tests.zig");
    _ = @import("ping_probe_tests.zig");
    _ = @import("ping_enforcement_tests.zig");
    _ = @import("duplex/response_capacity_tests.zig");
    _ = @import("duplex/batched_credit_tests.zig");
}

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

test "HTTP/2 local protocol error reset budget closes real connection" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_local_error_reset_streams = 1,
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
        io: std.Io,
        ready: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.ready.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();

            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqual(@as(u31, 3), second.stream_id);
            (try connection.sendStreamWindow(first.stream_id)).value =
                max_flow_window;
            (try connection.sendStreamWindow(second.stream_id)).value =
                max_flow_window;
            self.ready.set(self.io);

            if (connection.readRequestWithTimeout(.fromSeconds(2))) |request| {
                var unexpected = request;
                unexpected.deinit(self.server.allocator);
                return error.TestUnexpectedResult;
            } else |err| {
                try std.testing.expectEqual(
                    error.ConnectionGoAway,
                    err,
                );
            }
            try std.testing.expectEqual(
                @as(usize, 1),
                connection.local_error_reset_streams,
            );
            try std.testing.expect(connection.aggregate_timeout_unusable);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), limits);
    defer client.close();
    _ = try client.sendCompleteRequest(.{
        .path = "/first",
        .authority = "localhost",
    });
    _ = try client.sendCompleteRequest(.{
        .path = "/second",
        .authority = "localhost",
    });
    try shared.ready.wait(io);
    if (shared.err) |err| return err;

    const overflow = [_]u8{ 0, 0, 0, 1 };
    try writeFrame(
        allocator,
        io,
        client.stream,
        .window_update,
        0,
        1,
        &overflow,
    );
    try writeFrame(
        allocator,
        io,
        client.stream,
        .window_update,
        0,
        3,
        &overflow,
    );

    var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.flow_control_error,
        reset.reset.error_code,
    );

    var goaway = try client.readGoAwayWithTimeout(.fromSeconds(2));
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), goaway.goaway.last_stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        goaway.goaway.error_code,
    );
    try std.testing.expectEqualStrings(
        "too_many_internal_resets",
        goaway.goaway.debug_data,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 response batch reorders out-of-order responses" {
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

            var requests: [3]OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(server_ptr.allocator);
            };
            for (&requests) |*request| {
                request.* = try connection.readRequest();
                initialized += 1;
            }

            var stream_ids: [requests.len]u31 = undefined;
            var response_headers: [requests.len]http2.Hpack.HeaderField =
                undefined;
            var responses: [requests.len]ResponseOptions = undefined;
            var index = requests.len;
            while (index != 0) {
                index -= 1;
                const output_index = requests.len - 1 - index;
                stream_ids[output_index] = requests[index].stream_id;
                response_headers[output_index] = .{
                    .name = "x-path",
                    .value = requests[index].path,
                };
                responses[output_index] = .{
                    .headers = response_headers[output_index..][0..1],
                };
            }
            try connection.writeResponseBatch(&stream_ids, &responses);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();

    const requests = [_]RequestOptions{
        .{ .path = "/one", .authority = "localhost" },
        .{ .path = "/two", .authority = "localhost" },
        .{ .path = "/three", .authority = "localhost" },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try client.requestBatchInto(&requests, &responses);
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
    for (responses) |response| {
        const date = findHeader(response.headers, "date") orelse
            return error.MissingPseudoHeader;
        try std.testing.expectEqual(@as(usize, http_date.value_len), date.len);
        try std.testing.expectEqualStrings("GMT", date[26..]);
    }
    try std.testing.expectEqual(@as(usize, 0), client.active_local_streams.items.len);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 response batch deadline is not renewed by partial completion" {
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

    const Shared = struct {
        server: *Server,
        reset_stream_id: ?u31 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);

            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
            try connection.writeResponse(first.stream_id, .{
                .body = "first",
            });
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(350),
                .awake,
            );
            try connection.writeResponse(second.stream_id, .{
                .body = "late",
            });
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            self.reset_stream_id = reset.reset.stream_id;
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );
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
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{ .path = "/first", .authority = "localhost" },
        .{ .path = "/second", .authority = "localhost" },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.requestBatchIntoWithTimeout(
            &requests,
            &responses,
            .fromMilliseconds(400),
        ),
    );
    try std.testing.expect(!client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(?u31, 3), shared.reset_stream_id);
}

test "HTTP/2 batch deadlines validate before stream or wire mutation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var connection = Connection{
        .io = threaded.io(),
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
        .authority = "localhost",
    }};
    const body_requests = [_]RequestOptions{.{
        .method = "POST",
        .authority = "localhost",
        .body = "body",
    }};
    var responses: [1]OwnedResponse = undefined;
    var streaming_responses: [1]StreamingResponse = undefined;
    const noopConsume = struct {
        fn consume(_: void, _: usize, _: []const u8) !void {}
    }.consume;
    try std.testing.expectError(
        error.Timeout,
        connection.requestBatchIntoWithTimeout(
            &requests,
            &responses,
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchIntoWithDeadline(
            &body_requests,
            4,
            &responses,
            .fromNow(connection.io, .{
                .raw = .fromSeconds(1),
                .clock = .real,
            }),
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBatchStreamingIntoWithTimeout(
            &requests,
            &streaming_responses,
            .zero,
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBatchStreamingWithInformationalIntoWithDeadline(
            &requests,
            &streaming_responses,
            null,
            .fromNow(connection.io, .{
                .raw = .fromSeconds(1),
                .clock = .real,
            }),
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchStreamingIntoWithTimeout(
            &body_requests,
            4,
            &streaming_responses,
            .zero,
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchStreamingWithInformationalIntoWithDeadline(
            &body_requests,
            4,
            &streaming_responses,
            null,
            .fromNow(connection.io, .{
                .raw = .fromSeconds(1),
                .clock = .real,
            }),
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchStreamingWithInformationalIntoWithTimeout(
            &body_requests,
            4,
            &streaming_responses,
            null,
            .zero,
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        connection.requestBodyBatchStreamingWithInformationalInto(
            &body_requests,
            0,
            &streaming_responses,
            null,
            {},
            noopConsume,
        ),
    );
    connection.role = .server;
    var inbound_requests: [1]StreamingRequest = undefined;
    try std.testing.expectError(
        error.Timeout,
        connection.readRequestBatchStreamingIntoWithTimeout(
            &inbound_requests,
            .zero,
            {},
            struct {
                fn consume(_: void, _: u31, _: []const u8) !void {}
            }.consume,
        ),
    );
    try std.testing.expectEqual(@as(u31, 1), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expectEqual(@as(u31, 0), connection.last_peer_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
    try std.testing.expectEqual(@as(usize, 0), connection.write_batch.items.len);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);
}

test "HTTP/2 bodyless request batch partial HEADERS write fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
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

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
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
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.NetworkDown,
        connection.requestBatchInto(&requests, &responses),
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

test "HTTP/2 single request partial HEADERS write fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
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

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
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

    try std.testing.expectError(
        error.NetworkDown,
        connection.sendCompleteRequest(.{ .authority = "localhost" }),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendCompleteRequest(.{ .authority = "localhost" }),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 single HEADERS encode failure preserves live HPACK state" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
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

    _ = try connection.hpack_encoder.encodeBlockRetained(allocator, &.{.{
        .name = "x-live",
        .value = "one",
    }});
    const live_entries =
        connection.hpack_encoder.dynamic_table.entries.items.len;
    try connection.addActiveLocalStream(1);
    {
        var failing = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = 0 },
        );
        connection.allocator = failing.allocator();
        defer connection.allocator = allocator;
        try std.testing.expectError(
            error.OutOfMemory,
            connection.writeHeaders(1, &.{.{
                .name = "x-staged",
                .value = "two",
            }}, true),
        );
        try std.testing.expect(failing.has_induced_failure);
    }
    try std.testing.expectEqual(
        live_entries,
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    try std.testing.expect(connection.outboundStreamIsActive(1));
}

test "HTTP/2 PUSH_PROMISE partial write rolls back state and fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
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

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }
    try connection.addActivePeerStream(1);

    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/pushed" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-push-dynamic", .value = "one" },
    };
    try std.testing.expectError(
        error.NetworkDown,
        connection.promisePush(1, &headers),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.push_state.localStatus(2) == null);
    try std.testing.expect(!connection.response_semantics_index.contains(2));
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.promisePush(1, &headers),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 partial DATA frame write fails connection closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
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

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
    }
    try connection.addActiveLocalStream(1);

    try std.testing.expectError(
        error.NetworkDown,
        connection.writeData(1, "payload", false),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.writeData(1, "retry", false),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 partial extension control write fails connection closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
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

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.deinitPeerMetadata();
    }

    try std.testing.expectError(
        error.NetworkDown,
        connection.sendOrigins(&.{"https://example.com"}),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendAlternativeService(
            0,
            "https://example.com",
            "h3=\":443\"",
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 application batch reset partial write fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        var active: std.atomic.Value(?*@This()) = .init(null);
        writes: std.atomic.Value(usize) = .init(0),

        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self = active.load(.acquire).?;
            if (self.writes.fetchAdd(1, .monotonic) == 0) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    errdefer stream.close(io);
    const peer = try listener.accept(io);
    defer peer.close(io);
    var writer: PartialWriter = .{};
    PartialWriter.active.store(&writer, .release);
    defer PartialWriter.active.store(null, .release);
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = threaded.io().userdata, .vtable = &vtable },
        .allocator = allocator,
        .stream = stream,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 0 },
    };
    defer {
        connection.io = io;
        connection.close();
    }

    const states = [_]Connection.BatchResponseState{
        .{
            .stream_id = 1,
            .request_method = "GET",
            .extended_connect = false,
        },
        .{
            .stream_id = 3,
            .request_method = "GET",
            .extended_connect = false,
        },
    };
    try std.testing.expectError(
        error.NetworkDown,
        connection.writeBatchResponseResets(&states),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes.load(.acquire));
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendGoAway(0, .no_error, &.{}),
    );
    var responses: [1]OwnedResponse = undefined;
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.requestBatchInto(
            &.{.{ .authority = "localhost" }},
            &responses,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes.load(.acquire));
}

test "HTTP/2 adaptive window partial write fails closed without local commit" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
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

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
    }

    const target: u32 = 100_000;
    try std.testing.expectError(
        error.NetworkDown,
        connection.sendAdaptiveWindowUpdate(target),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_connection_window_target,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_stream_window_target,
    );
    try std.testing.expect(!connection.awaiting_settings_ack);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendWindowUpdate(0, 1),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 internal error GOAWAY bypasses public fail-fast guard" {
    if (comptime builtin.os.tag != .linux) return;
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        var active: std.atomic.Value(?*@This()) = .init(null);
        bytes: [128]u8 = undefined,
        len: usize = 0,
        writes: usize = 0,

        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self = active.load(.acquire).?;
            self.writes += 1;
            const count = @min(header.len, self.bytes.len - self.len);
            if (count == 0) return error.SocketUnconnected;
            @memcpy(self.bytes[self.len..][0..count], header[0..count]);
            self.len += count;
            return count;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    RecordingWriter.active.store(&writer, .release);
    defer RecordingWriter.active.store(null, .release);
    const io = threaded.io();
    var fixture = try @import("testing/blocked_output.zig").BlockedOutput.init(io, .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    var vtable = io.vtable.*;
    vtable.netWrite = RecordingWriter.write;
    connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer connection.io = io;
    connection.serve_read_connection_error = .frame_sequence;

    connection.sendServeReadError(error.UnexpectedFrame);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(writer.len != 0);
    const frame = try http2.Frame.parse(writer.bytes[0..writer.len]);
    try std.testing.expectEqual(http2.FrameType.goaway, frame.header.frame_type);
    const goaway = try http2.GoAwayPayload.parse(frame);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, goaway.error_code);
    try std.testing.expectEqualStrings("frame-sequence", goaway.debug_data);

    const writes = writer.writes;
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendGoAway(0, .no_error, &.{}),
    );
    try std.testing.expectEqual(writes, writer.writes);
}

test "HTTP/2 streaming request batch partial HEADERS write fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
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

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
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
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
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

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
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
    const allocator = std.testing.allocator;
    const PartialDataWriter = struct {
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

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialDataWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialDataWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
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
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
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

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
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

test "HTTP/2 DATA receive releases WINDOW_UPDATE capacity" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 128 * 1024 },
    );
    defer server.deinit();

    const request_body = try allocator.alloc(u8, 40_000);
    defer allocator.free(request_body);
    @memset(request_body, 'q');

    const response_body = try allocator.alloc(u8, 40_000);
    defer allocator.free(response_body);
    @memset(response_body, 'r');

    const Shared = struct {
        server: *Server,
        expected_request: []const u8,
        response_body: []const u8,
        response_window_updates: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings("/release-capacity", request.path);
            try std.testing.expectEqualSlices(u8, shared.expected_request, request.body);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = shared.response_body,
            });

            var conn_update = try connection.readWindowUpdate();
            defer conn_update.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 0), conn_update.window_update.stream_id);
            try std.testing.expect(conn_update.window_update.increment > 0);
            shared.response_window_updates += 1;

            var stream_update = try connection.readWindowUpdate();
            defer stream_update.deinit(shared.server.allocator);
            try std.testing.expectEqual(request.stream_id, stream_update.window_update.stream_id);
            try std.testing.expect(stream_update.window_update.increment > 0);
            shared.response_window_updates += 1;
        }
    };

    var shared = Shared{
        .server = &server,
        .expected_request = request_body,
        .response_body = response_body,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 128 * 1024,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "POST",
        .path = "/release-capacity",
        .authority = "localhost",
        .body = request_body,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualSlices(u8, response_body, response.body);
    try std.testing.expect(client.send_connection_window.value > default_flow_window - @as(i64, @intCast(request_body.len)));

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.response_window_updates);
}

test "HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE updates stream send windows" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    const first = try connection.sendStreamWindow(1);
    try std.testing.expectEqual(@as(?usize, 0), connection.send_stream_window_index.get(1));
    try first.reserve(1024);
    try std.testing.expectEqual(@as(i64, default_flow_window - 1024), first.value);

    const settings = [_]http2.Setting{.{ .id = .initial_window_size, .value = 70_000 }};
    try connection.applySettings(&settings);
    try std.testing.expectEqual(@as(i64, 70_000), connection.peer_initial_stream_window);
    try std.testing.expectEqual(@as(i64, 70_000 - 1024), (try connection.sendStreamWindow(1)).value);
    try std.testing.expectEqual(@as(i64, 70_000), (try connection.sendStreamWindow(3)).value);
    try std.testing.expectEqual(@as(?usize, 1), connection.send_stream_window_index.get(3));

    (try connection.sendStreamWindow(1)).value = max_flow_window;
    try std.testing.expectError(error.FlowControlViolation, connection.applySettings(&.{
        .{ .id = .initial_window_size, .value = std.math.maxInt(i31) },
    }));
    try std.testing.expectEqual(@as(i64, 70_000), connection.peer_initial_stream_window);
    try std.testing.expectEqual(max_flow_window, (try connection.sendStreamWindow(1)).value);

    (try connection.sendStreamWindow(1)).value = 100;
    (try connection.sendStreamWindow(3)).value = max_flow_window;
    try std.testing.expectError(error.FlowControlViolation, connection.applySettings(&.{
        .{ .id = .initial_window_size, .value = std.math.maxInt(i31) },
    }));
    try std.testing.expectEqual(@as(i64, 70_000), connection.peer_initial_stream_window);
    try std.testing.expectEqual(@as(i64, 100), (try connection.sendStreamWindow(1)).value);
    try std.testing.expectEqual(max_flow_window, (try connection.sendStreamWindow(3)).value);
}

test "HTTP/2 adaptive window queues behind initial SETTINGS ACK" {
    const allocator = std.testing.allocator;
    const adaptive_target: u32 = 100_000;
    const sample_bytes: usize = adaptive_target / 2;
    const final_bytes: usize = 1;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 64 * 1024,
            .max_body_bytes = 128 * 1024,
            .adaptive_window = true,
            .adaptive_window_max = 1024 * 1024,
        },
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
            try std.testing.expect(connection.awaiting_settings_ack);

            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings(
                "/adaptive-window",
                request.path,
            );
            try std.testing.expectEqual(
                sample_bytes + final_bytes,
                request.body.len,
            );

            // The BDP ACK arrived before the initial SETTINGS ACK. Processing
            // the latter emitted exactly one merged adaptive update and began
            // a fresh SETTINGS acknowledgement wait.
            try std.testing.expect(connection.awaiting_settings_ack);
            try std.testing.expectEqual(
                @as(?u32, adaptive_target),
                connection.adaptive_pending_stream_target,
            );
            try std.testing.expectEqual(
                @as(?u32, null),
                connection.adaptive_queued_target,
            );
            try std.testing.expectEqual(
                adaptive_target,
                connection.recv_connection_window_target,
            );
            try std.testing.expectEqual(
                adaptive_target,
                connection.recv_stream_window_target,
            );
            try std.testing.expectEqual(
                @as(u32, adaptive_target / 2),
                connection.dataFrameBudgetMaximum(),
            );
            try std.testing.expect(
                (try connection.recvStreamWindow(1)).value >
                    default_flow_window,
            );
            try std.testing.expectEqual(
                @as(i64, adaptive_target),
                (try connection.recvStreamWindow(3)).value,
            );

            const user_ping = [_]u8{ 6, 2, 6, 4, 3, 3, 8, 3 };
            const observed = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &user_ping, &observed);
            try std.testing.expect(!connection.awaiting_settings_ack);
            try std.testing.expectEqual(
                @as(?u32, null),
                connection.adaptive_pending_stream_target,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream, http2.connection_preface);
    try writeFrame(allocator, io, stream, .settings, 0, 0, &.{});

    var server_settings = try readFrame(allocator, io, stream, .{});
    defer server_settings.deinit(allocator);
    try std.testing.expectEqual(
        http2.FrameType.settings,
        server_settings.frame.header.frame_type,
    );
    try std.testing.expectEqual(
        @as(u8, 0),
        server_settings.frame.header.flags & flag_ack,
    );
    var server_ack = try readFrame(allocator, io, stream, .{});
    defer server_ack.deinit(allocator);
    try std.testing.expectEqual(
        http2.FrameType.settings,
        server_ack.frame.header.frame_type,
    );
    try std.testing.expect(server_ack.frame.header.flags & flag_ack != 0);

    var request_block: std.ArrayList(u8) = .empty;
    defer request_block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&request_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/adaptive-window" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "50001" },
    });
    try writeFrame(
        allocator,
        io,
        stream,
        .headers,
        flag_end_headers,
        1,
        request_block.items,
    );
    var data: [default_max_frame_size]u8 = undefined;
    @memset(&data, 'd');
    try writeFrame(allocator, io, stream, .data, 0, 1, &data);
    try writeFrame(allocator, io, stream, .data, 0, 1, &data);
    try writeFrame(allocator, io, stream, .data, 0, 1, &data);
    try writeFrame(
        allocator,
        io,
        stream,
        .data,
        0,
        1,
        data[0 .. sample_bytes - 3 * default_max_frame_size],
    );

    var probe_payload: ?[8]u8 = null;
    while (probe_payload == null) {
        var frame = try readFrame(allocator, io, stream, .{});
        defer frame.deinit(allocator);
        if (frame.frame.header.frame_type == .ping) {
            try std.testing.expectEqual(
                @as(u8, 0),
                frame.frame.header.flags & flag_ack,
            );
            probe_payload = (try http2.PingPayload.parse(frame.frame)).data;
            try std.testing.expect(bdp.isProbePayload(probe_payload.?));
        }
    }

    // Deliberately acknowledge the probe before the server's initial
    // SETTINGS. The target must remain queued until that older transaction is
    // acknowledged. The final DATA keeps readRequest alive long enough to
    // process both control frames first.
    try writeFrame(
        allocator,
        io,
        stream,
        .ping,
        flag_ack,
        0,
        &probe_payload.?,
    );
    try writeFrame(allocator, io, stream, .settings, flag_ack, 0, &.{});
    try writeFrame(
        allocator,
        io,
        stream,
        .data,
        flag_end_stream,
        1,
        "!",
    );

    var saw_connection_growth = false;
    var saw_adaptive_settings = false;
    while (!saw_adaptive_settings) {
        var frame = try readFrame(allocator, io, stream, .{});
        defer frame.deinit(allocator);
        switch (frame.frame.header.frame_type) {
            .window_update => {
                const update = try http2.WindowUpdatePayload.parse(
                    frame.frame,
                );
                if (update.stream_id == 0 and
                    update.increment ==
                        adaptive_target - default_flow_window)
                {
                    saw_connection_growth = true;
                }
            },
            .settings => {
                try std.testing.expectEqual(
                    @as(u8, 0),
                    frame.frame.header.flags & flag_ack,
                );
                const settings = try http2.parseSettings(
                    allocator,
                    frame.frame.payload,
                );
                defer allocator.free(settings);
                for (settings) |setting| {
                    if (setting.id == .initial_window_size and
                        setting.value == adaptive_target)
                    {
                        saw_adaptive_settings = true;
                    }
                }
            },
            else => {},
        }
    }
    try std.testing.expect(saw_connection_growth);

    try writeFrame(allocator, io, stream, .settings, flag_ack, 0, &.{});
    // Internal probe-shaped requests are acknowledged as connection control
    // and cannot escape through the public user-PING receive API.
    try writeFrame(
        allocator,
        io,
        stream,
        .ping,
        0,
        0,
        &probe_payload.?,
    );
    const user_ping = [_]u8{ 6, 2, 6, 4, 3, 3, 8, 3 };
    try writeFrame(allocator, io, stream, .ping, 0, 0, &user_ping);
    while (true) {
        var frame = try readFrame(allocator, io, stream, .{});
        defer frame.deinit(allocator);
        if (frame.frame.header.frame_type != .ping or
            frame.frame.header.flags & flag_ack == 0) continue;
        const echoed = (try http2.PingPayload.parse(frame.frame)).data;
        if (bdp.isProbePayload(echoed)) continue;
        try std.testing.expectEqualSlices(u8, &user_ping, &echoed);
        break;
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 adaptive window coalesces pending targets" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .awaiting_settings_ack = true,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.queueAdaptiveWindowTarget(100_000);
    try connection.queueAdaptiveWindowTarget(80_000);
    try connection.queueAdaptiveWindowTarget(120_000);
    try std.testing.expectEqual(
        @as(?u32, 120_000),
        connection.adaptive_queued_target,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_connection_window_target,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_stream_window_target,
    );
}

test "HTTP/2 user PING rejects the adaptive probe namespace" {
    var estimator = bdp.Estimator.init(65_535, bdp.default_max_window);
    const probe = estimator.recordData(1, 0) orelse
        return error.TestUnexpectedResult;
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(error.InvalidFrame, connection.ping(probe));
}

test "HTTP/2 client connect handles interleaved PING before settings" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(shared.io, stream, &preface);
            try http2.validateClientPreface(&preface);
            var client_settings = try readFrame(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 });
            defer client_settings.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_settings.frame.header.frame_type);

            const ping_payload = [_]u8{ 7, 0, 7, 0, 7, 0, 7, 0 };
            try writeFrame(shared.allocator, shared.io, stream, .ping, 0, 0, &ping_payload);
            try writeInitialSettings(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 }, .server);
            try writeFrame(shared.allocator, shared.io, stream, .settings, flag_ack, 0, &.{});

            while (true) {
                var frame = try readFrame(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 });
                defer frame.deinit(shared.allocator);
                if (frame.frame.header.frame_type == .settings and (frame.frame.header.flags & flag_ack) != 0) continue;
                try std.testing.expectEqual(http2.FrameType.ping, frame.frame.header.frame_type);
                try std.testing.expect((frame.frame.header.flags & flag_ack) != 0);
                try std.testing.expectEqualSlices(u8, &ping_payload, frame.frame.payload);
                break;
            }
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, listener.socket.address, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();
    try std.testing.expect(!client.awaiting_settings_ack);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 server clears settings ACK on first control read" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
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
            try std.testing.expect(connection.awaiting_settings_ack);

            const observed = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &[_]u8{ 3, 1, 4, 1, 5, 9, 2, 6 }, &observed);
            try std.testing.expect(!connection.awaiting_settings_ack);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();
    _ = try client.ping(.{ 3, 1, 4, 1, 5, 9, 2, 6 });

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client connect clears initial settings ACK wait" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
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
            // The server has not read the client's ACK yet after accept returns.
            std.testing.expect(connection.awaiting_settings_ack) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();
    try std.testing.expect(!client.awaiting_settings_ack);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 rejects unexpected SETTINGS ACK" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    const ack = http2.Frame{
        .header = .{ .length = 0, .frame_type = .settings, .flags = flag_ack, .stream_id = 0 },
        .payload = &.{},
    };
    try std.testing.expectError(error.InvalidFrame, connection.handleConnectionFrame(ack));
    connection.awaiting_settings_ack = true;
    try std.testing.expect(try connection.handleConnectionFrame(ack));
    try std.testing.expect(!connection.awaiting_settings_ack);
    try std.testing.expectError(error.InvalidFrame, connection.handleConnectionFrame(ack));
}

test "HTTP/2 sendGoAway enforces non-increasing boundaries" {
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
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.validateLocalGoAway(7);
    connection.local_goaway_last_stream_id = 7;
    try connection.validateLocalGoAway(5);
    connection.local_goaway_last_stream_id = 5;
    try std.testing.expectError(error.InvalidFrame, connection.validateLocalGoAway(7));
    try std.testing.expectEqual(@as(?u31, 5), connection.local_goaway_last_stream_id);
}

test "HTTP/2 readGoAway records monotonic peer boundary" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.response_semantics.deinit(std.testing.allocator);
        connection.response_semantics_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.rememberResponseSemantics(
        1,
        "HEAD",
        null,
        .{},
    );
    try std.testing.expectEqual(@as(?usize, 0), connection.response_semantics_index.get(1));
    try std.testing.expect((connection.responseSemanticsFor(1, .{})).head);
    connection.forgetResponseSemantics(1);
    try std.testing.expectEqual(@as(usize, 0), connection.response_semantics_index.count());
    try std.testing.expect(!(connection.responseSemanticsFor(1, .{})).head);
    connection.forgetResponseSemantics(1);

    try connection.recordPeerGoAway(.{ .last_stream_id = 7, .error_code = .no_error, .debug_data = &.{} });
    try std.testing.expectEqual(@as(?u31, 7), connection.peer_goaway_last_stream_id);
    try std.testing.expect(!connection.peerGoAwayTooManyPings());
    try connection.recordPeerGoAway(.{ .last_stream_id = 5, .error_code = .enhance_your_calm, .debug_data = "too_many_pings" });
    try std.testing.expectEqual(@as(?u31, 5), connection.peer_goaway_last_stream_id);
    try std.testing.expect(connection.peerGoAwayTooManyPings());
    try connection.recordPeerGoAway(.{ .last_stream_id = 5, .error_code = .no_error, .debug_data = &.{} });
    try std.testing.expect(connection.peerGoAwayTooManyPings());
    try std.testing.expectError(error.InvalidFrame, connection.recordPeerGoAway(.{ .last_stream_id = 7, .error_code = .no_error, .debug_data = &.{} }));
    try std.testing.expectEqual(@as(?u31, 5), connection.peer_goaway_last_stream_id);
}

test "HTTP/2 stream idle classification follows initiator cursors" {
    var server_connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .last_peer_client_stream_id = 3,
    };
    defer server_connection.push_state.deinit(std.testing.allocator);

    try std.testing.expect(!server_connection.streamIsIdle(1));
    try std.testing.expect(!server_connection.streamIsIdle(3));
    try std.testing.expect(server_connection.streamIsIdle(5));
    try std.testing.expect(server_connection.streamIsIdle(2));
    const reserved = try server_connection.push_state.reserveLocal(
        std.testing.allocator,
    );
    try std.testing.expectEqual(@as(u31, 2), reserved);
    try std.testing.expect(!server_connection.streamIsIdle(2));
    try std.testing.expect(server_connection.streamIsIdle(4));

    var client_connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .next_client_stream_id = 5,
    };
    try std.testing.expect(!client_connection.streamIsIdle(1));
    try std.testing.expect(!client_connection.streamIsIdle(3));
    try std.testing.expect(client_connection.streamIsIdle(5));
    try std.testing.expect(client_connection.streamIsIdle(2));
}

test "HTTP/2 continues after RST_STREAM on a half-closed request" {
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
            try std.testing.expectEqual(@as(u31, 1), request.stream_id);
            request.deinit(server_ptr.allocator);

            // readRequest must consume the intervening reset rather than
            // terminating the connection before the next request stream.
            var next_request = try connection.readRequest();
            defer next_request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 3), next_request.stream_id);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const first = try client.sendCompleteRequest(.{
        .path = "/reset",
        .authority = "localhost",
    });
    try client.sendResetStream(first.stream_id, .cancel);
    const second = try client.sendCompleteRequest(.{
        .path = "/after-reset",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u31, 3), second.stream_id);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client ignores in-flight frames after local reset" {
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
            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);

            try connection.writeHeaders(first.stream_id, &.{.{
                .name = ":status",
                .value = "200",
            }}, false);
            try writeFrame(
                server_ptr.allocator,
                server_ptr.io,
                connection.stream,
                .data,
                0,
                first.stream_id,
                "late",
            );
            try connection.writeHeaders(first.stream_id, &.{.{
                .name = "x-late-trailer",
                .value = "discarded",
            }}, true);
            try connection.writeResponse(second.stream_id, .{
                .status = 200,
                .body = "ok",
                .request_method = second.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const first = try client.sendCompleteRequest(.{
        .path = "/cancel",
        .authority = "localhost",
    });
    const second = try client.sendCompleteRequest(.{
        .path = "/sibling",
        .authority = "localhost",
    });
    try client.sendResetStream(first.stream_id, .cancel);

    var response = try client.readResponse(
        second.stream_id,
        second.request_method,
        second.extended_connect,
        null,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expectEqual(
        @as(i64, default_flow_window - "ok".len),
        client.recv_connection_window.value,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client drains buffered sibling after reset peer close" {
    const allocator = std.testing.allocator;

    // Model the exact race deterministically: one transport read has already
    // retained both streams, then the peer closes before the client returns
    // connection credit for DATA that raced with its RST_STREAM.
    var buffered_frames: std.ArrayList(u8) = .empty;
    try appendFrameBytes(
        &buffered_frames,
        allocator,
        .data,
        0,
        1,
        "late",
    );
    try appendFrameBytes(
        &buffered_frames,
        allocator,
        .headers,
        flag_end_headers,
        3,
        &.{0x88}, // HPACK static-table index for `:status: 200`.
    );
    try appendFrameBytes(
        &buffered_frames,
        allocator,
        .data,
        flag_end_stream,
        3,
        "ok",
    );

    const ClosedWriter = struct {
        writes: usize = 0,
        fail_with_network_down: bool = false,

        fn now(
            _: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            return .zero;
        }

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.fail_with_network_down) return error.NetworkDown;
            return error.SocketUnconnected;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: ClosedWriter = .{};
    var closed_vtable = threaded.io().vtable.*;
    closed_vtable.now = ClosedWriter.now;
    closed_vtable.netWrite = ClosedWriter.write;
    const closed_io = std.Io{
        .userdata = &writer,
        .vtable = &closed_vtable,
    };

    var connection = Connection{
        .io = closed_io,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .frame_reader = .{ .buffer = buffered_frames },
    };
    defer {
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.frame_reader.deinit(allocator);
    }
    try connection.prepareLocallyResetStreamsAt(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);

    var response = try connection.readResponse(3, "GET", false, null);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), writer.writes);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expectEqual(
        @as(i64, default_flow_window - "ok".len),
        connection.recv_connection_window.value,
    );

    connection.recv_connection_window.value -= 7;
    writer.fail_with_network_down = true;
    try std.testing.expectError(
        error.NetworkDown,
        connection.releaseLateResetConnectionCapacity(7),
    );
    // Non-terminal transport failures remain observable and the generic
    // WINDOW_UPDATE transaction must roll its optimistic accounting back.
    try std.testing.expectEqual(
        @as(i64, default_flow_window - "ok".len - 7),
        connection.recv_connection_window.value,
    );
}

test "HTTP/2 ignores unknown extension connection frames" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };

    try std.testing.expect(try connection.handleConnectionFrame(.{
        .header = .{
            .length = 3,
            .frame_type = @enumFromInt(0xff),
            .flags = 0xa5,
            .stream_id = 0,
        },
        .payload = "ext",
    }));
    try std.testing.expect(!try connection.handleConnectionFrame(.{
        .header = .{
            .length = 0,
            .frame_type = .data,
            .flags = flag_end_stream,
            .stream_id = 1,
        },
        .payload = &.{},
    }));
}

test "HTTP/2 ignores WINDOW_UPDATE for inactive streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .next_client_stream_id = 3,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    const inactive_update = http2.Frame{
        .header = .{ .length = 4, .frame_type = .window_update, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 10 },
    };
    try std.testing.expect(try connection.handleConnectionFrame(inactive_update));
    try std.testing.expectEqual(@as(usize, 0), connection.send_stream_windows.items.len);

    try connection.addActiveLocalStream(1);
    try std.testing.expect(try connection.handleConnectionFrame(inactive_update));
    try std.testing.expectEqual(@as(usize, 1), connection.send_stream_windows.items.len);
    try std.testing.expectEqual(@as(i64, default_flow_window + 10), (try connection.sendStreamWindow(1)).value);

    const peer_update = http2.Frame{
        .header = .{ .length = 4, .frame_type = .window_update, .flags = 0, .stream_id = 3 },
        .payload = &.{ 0, 0, 0, 7 },
    };
    try connection.addActivePeerStream(3);
    try std.testing.expect(try connection.handleConnectionFrame(peer_update));
    try std.testing.expectEqual(@as(i64, default_flow_window + 7), (try connection.sendStreamWindow(3)).value);
}

test "HTTP/2 stream window helpers reject connection stream id" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(error.InvalidStreamId, connection.sendStreamWindow(0));
    try std.testing.expectError(error.InvalidStreamId, connection.recvStreamWindow(0));
    try std.testing.expectEqual(@as(usize, 0), connection.send_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
}

test "HTTP/2 reset retirement clears both stream windows" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    _ = try connection.sendStreamWindow(1);
    _ = try connection.recvStreamWindow(1);
    connection.forgetStreamWindows(1);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.send_stream_windows.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.recv_stream_windows.items.len,
    );
    try std.testing.expect(!connection.send_stream_window_index.contains(1));
    try std.testing.expect(!connection.recv_stream_window_index.contains(1));
}

test "HTTP/2 local reset history honors capacity and retention duration" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 2 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    const second: i96 = std.time.ns_per_s;
    try connection.prepareLocallyResetStreamsAt(3, 0);
    try std.testing.expect(connection.locally_reset_streams.capacity >= 2);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(3, 0);
    try std.testing.expectEqual(
        connection.locallyResetStreamCount(),
        connection.locally_reset_stream_index.count(),
    );
    // Duplicate resets do not consume another slot.
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, second / 2);
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.locallyResetStreamCount(),
    );
    // Capacity pressure cannot evict IDs before their minimum retention time.
    connection.rememberLocallyResetStreamAtAssumeCapacity(5, second / 2);
    try std.testing.expectEqual(
        connection.locallyResetStreamCount(),
        connection.locally_reset_stream_index.count(),
    );
    try std.testing.expect(connection.wasLocallyResetAt(1, second));
    try std.testing.expect(connection.wasLocallyResetAt(3, second));
    try std.testing.expect(!connection.wasLocallyResetAt(5, second));

    // Expiration is strict: exactly one second remains tolerated, while the
    // first later nanosecond reclaims both FIFO entries for new resets.
    connection.rememberLocallyResetStreamAtAssumeCapacity(5, second + 1);
    connection.rememberLocallyResetStreamAtAssumeCapacity(7, second + 1);
    try std.testing.expectEqual(
        connection.locallyResetStreamCount(),
        connection.locally_reset_stream_index.count(),
    );
    try std.testing.expect(!connection.wasLocallyResetAt(1, second + 1));
    try std.testing.expect(!connection.wasLocallyResetAt(3, second + 1));
    try std.testing.expect(connection.wasLocallyResetAt(5, second + 1));
    try std.testing.expect(connection.wasLocallyResetAt(7, second + 1));

    // An expired duplicate is a fresh reset and receives a new retention
    // deadline instead of being discarded by a stale hash hit.
    connection.rememberLocallyResetStreamAtAssumeCapacity(5, 2 * second + 2);
    try std.testing.expect(connection.wasLocallyResetAt(5, 3 * second + 2));
    try std.testing.expect(!connection.wasLocallyResetAt(5, 3 * second + 3));
}

test "HTTP/2 local reset history may be disabled" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 0 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    try connection.prepareLocallyResetStreamsAt(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.locally_reset_streams.capacity,
    );
    try std.testing.expect(!connection.wasLocallyResetAt(1, 0));
}

test "HTTP/2 configured reset history controls late-frame tolerance" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }

    try connection.prepareLocallyResetStreamsAt(2, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(3, 0);
    const reset_payload = [_]u8{ 0, 0, 0, 8 };
    try std.testing.expect(try connection
        .discardLateFrameForLocallyResetStreamAt(.{
        .header = .{
            .length = reset_payload.len,
            .frame_type = .rst_stream,
            .flags = 0,
            .stream_id = 1,
        },
        .payload = &reset_payload,
    }, 0));
    try std.testing.expect(!try connection
        .discardLateFrameForLocallyResetStreamAt(.{
        .header = .{
            .length = reset_payload.len,
            .frame_type = .rst_stream,
            .flags = 0,
            .stream_id = 3,
        },
        .payload = &reset_payload,
    }, 0));
}

test "HTTP/2 local protocol error reset budget emits terminal GOAWAY" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        var active: std.atomic.Value(?*@This()) = .init(null);
        bytes: std.ArrayList(u8) = .empty,

        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) net.Stream.Writer.Error!usize {
            const self = active.load(.acquire).?;
            var total = header.len;
            self.bytes.appendSlice(allocator, header) catch
                return error.SystemResources;
            for (data[0 .. data.len - 1]) |part| {
                total += part.len;
                self.bytes.appendSlice(allocator, part) catch
                    return error.SystemResources;
            }
            var repeated: usize = 0;
            while (repeated < splat) : (repeated += 1) {
                total += data[data.len - 1].len;
                self.bytes.appendSlice(
                    allocator,
                    data[data.len - 1],
                ) catch return error.SystemResources;
            }
            return total;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    defer writer.bytes.deinit(allocator);
    RecordingWriter.active.store(&writer, .release);
    defer RecordingWriter.active.store(null, .release);
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = threaded.io().userdata, .vtable = &vtable },
        .allocator = allocator,
        .stream = test_socket.stream(),
        .role = .server,
        .limits = .{ .max_local_error_reset_streams = 1 },
        .last_peer_processed_stream_id = 3,
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    try connection.writeLocalErrorResetStream(
        1,
        .flow_control_error,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.local_error_reset_streams,
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);

    const reset_frame = try http2.Frame.parse(writer.bytes.items);
    try std.testing.expectEqual(
        http2.FrameType.rst_stream,
        reset_frame.header.frame_type,
    );
    const reset = try http2.ResetStreamPayload.parse(reset_frame);
    try std.testing.expectEqual(@as(u31, 1), reset.stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.flow_control_error,
        reset.error_code,
    );

    try std.testing.expectError(
        error.ConnectionGoAway,
        connection.writeLocalErrorResetStream(3, .protocol_error),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.local_error_reset_streams,
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);

    const goaway_frame = try http2.Frame.parse(
        writer.bytes.items[reset_frame.consumed()..],
    );
    try std.testing.expectEqual(
        http2.FrameType.goaway,
        goaway_frame.header.frame_type,
    );
    const goaway = try http2.GoAwayPayload.parse(goaway_frame);
    try std.testing.expectEqual(@as(u31, 3), goaway.last_stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        goaway.error_code,
    );
    try std.testing.expectEqualStrings(
        "too_many_internal_resets",
        goaway.debug_data,
    );
    try std.testing.expectEqual(
        writer.bytes.items.len,
        reset_frame.consumed() + goaway_frame.consumed(),
    );
}

test "HTTP/2 excessive padded empty DATA emits terminal GOAWAY" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        var active: std.atomic.Value(?*@This()) = .init(null);
        bytes: std.ArrayList(u8) = .empty,

        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) net.Stream.Writer.Error!usize {
            const self = active.load(.acquire).?;
            var total = header.len;
            self.bytes.appendSlice(allocator, header) catch
                return error.SystemResources;
            for (data[0 .. data.len - 1]) |part| {
                total += part.len;
                self.bytes.appendSlice(allocator, part) catch
                    return error.SystemResources;
            }
            for (0..splat) |_| {
                const part = data[data.len - 1];
                total += part.len;
                self.bytes.appendSlice(allocator, part) catch
                    return error.SystemResources;
            }
            return total;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    defer writer.bytes.deinit(allocator);
    RecordingWriter.active.store(&writer, .release);
    defer RecordingWriter.active.store(null, .release);
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = threaded.io().userdata, .vtable = &vtable },
        .allocator = allocator,
        .stream = test_socket.stream(),
        .role = .server,
        .last_peer_processed_stream_id = 1,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }
    connection.applyLocalLimits();

    // PADDED with Pad Length 1 and one padding octet has no application
    // payload. Flow control still charges both bytes, while the independent
    // lifetime frame-count guard rejects the 101st non-final empty DATA.
    const padded_empty = [_]u8{ 1, 0 };
    const frame = http2.Frame{
        .header = .{
            .length = padded_empty.len,
            .frame_type = .data,
            .flags = 0x08,
            .stream_id = 1,
        },
        .payload = &padded_empty,
    };
    for (0..data_frame_budget.max_empty_frames) |_| {
        const data = try connection.receiveDataPayload(1, frame);
        defer connection.releaseDataFrameBudget(data);
        try std.testing.expectEqual(@as(usize, 0), data.data.len);
    }
    try std.testing.expectError(
        error.ConnectionGoAway,
        connection.receiveDataPayload(1, frame),
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);

    const goaway_frame = try http2.Frame.parse(writer.bytes.items);
    try std.testing.expectEqual(
        http2.FrameType.goaway,
        goaway_frame.header.frame_type,
    );
    const goaway = try http2.GoAwayPayload.parse(goaway_frame);
    try std.testing.expectEqual(@as(u31, 1), goaway.last_stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        goaway.error_code,
    );
    try std.testing.expectEqualStrings(
        "too_many_data_frames",
        goaway.debug_data,
    );
}

test "HTTP/2 application reset does not consume protocol error budget" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        bytes: [http2.ResetStreamPayload.encoded_len]u8 = undefined,
        len: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = @min(header.len, self.bytes.len - self.len);
            if (count == 0) return error.SocketUnconnected;
            @memcpy(self.bytes[self.len..][0..count], header[0..count]);
            self.len += count;
            return count;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_local_error_reset_streams = 0 },
    };
    defer {
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }
    try connection.addActiveLocalStream(1);

    try connection.sendResetStream(1, .cancel);
    try std.testing.expectEqual(@as(usize, 0), connection.local_error_reset_streams);
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    const frame = try http2.Frame.parse(writer.bytes[0..writer.len]);
    const reset = try http2.ResetStreamPayload.parse(frame);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
}

test "HTTP/2 local protocol error reset budget may be disabled" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        bytes: [2 * http2.ResetStreamPayload.encoded_len]u8 = undefined,
        len: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = @min(header.len, self.bytes.len - self.len);
            if (count == 0) return error.SocketUnconnected;
            @memcpy(self.bytes[self.len..][0..count], header[0..count]);
            self.len += count;
            return count;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_local_error_reset_streams = null },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    try connection.writeLocalErrorResetStream(1, .protocol_error);
    try connection.writeLocalErrorResetStream(3, .flow_control_error);
    try std.testing.expectEqual(@as(usize, 2), connection.local_error_reset_streams);
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@sizeOf(@TypeOf(writer.bytes)), writer.len);
}

test "HTTP/2 failed protocol error reset write is terminal and uncounted" {
    const FailingWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var writer: FailingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = FailingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.locally_reset_streams.deinit(std.testing.allocator);
        connection.locally_reset_stream_index.deinit(std.testing.allocator);
    }

    try std.testing.expectError(
        error.NetworkDown,
        connection.writeLocalErrorResetStream(1, .protocol_error),
    );
    try std.testing.expectEqual(@as(usize, 0), connection.local_error_reset_streams);
    try std.testing.expect(connection.aggregate_timeout_unusable);
}

test "HTTP/2 abandoning peer request releases state after reset write failure" {
    if (comptime builtin.os.tag != .linux) return;
    const allocator = std.testing.allocator;
    const FailingWriter = struct {
        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try @import("testing/blocked_output.zig").BlockedOutput.init(io, .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    var vtable = io.vtable.*;
    vtable.netWrite = FailingWriter.write;
    connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer connection.io = io;
    connection.limits = .{
        .max_concurrent_streams = 1,
        .max_reset_stream_history = 0,
    };

    try connection.reservePeerStream(1);
    try connection.rememberResponseSemantics(1, "POST", null, .{});
    _ = try connection.sendStreamWindow(1);
    _ = try connection.recvStreamWindow(1);
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(connection.hasRecvStreamWindow(1));

    connection.abandonPeerRequest(1, .internal_error);
    try std.testing.expect(!connection.outboundStreamIsActive(1));
    try std.testing.expect(!connection.hasRecvStreamWindow(1));
    try std.testing.expect(!connection.response_semantics_index.contains(1));
    try std.testing.expect(connection.priority_state.get(1) == null);

    // The failed best-effort RST must not strand the sole concurrency slot.
    try connection.reservePeerStream(3);
    try std.testing.expect(connection.outboundStreamIsActive(3));
}

test "HTTP/2 reset history allocation failure precedes wire write" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            return error.SocketUnconnected;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var recording_vtable = threaded.io().vtable.*;
    recording_vtable.netWrite = RecordingWriter.write;
    const recording_io = std.Io{
        .userdata = &writer,
        .vtable = &recording_vtable,
    };
    var connection = Connection{
        .io = recording_io,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }
    try connection.addActiveLocalStream(1);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.sendResetStream(1, .cancel),
    );
    connection.allocator = allocator;
    try std.testing.expectEqual(@as(usize, 0), writer.writes);
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(!connection.wasLocallyResetAt(1, 0));
}

test "HTTP/2 refusal reserves reset history before consuming headers" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            return error.SocketUnconnected;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{
            .max_concurrent_streams = 1,
            .max_reset_stream_history = 1,
        },
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }
    try connection.active_peer_streams.ensureUnusedCapacity(allocator, 1);
    try connection.active_peer_index.ensureUnusedCapacity(allocator, 1);
    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.admitted,
        try connection.claimPeerRequestStream(1),
    );
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.claimPeerRequestStream(3),
    );
    connection.allocator = allocator;
    try std.testing.expectEqual(@as(usize, 0), writer.writes);
    try std.testing.expectEqual(@as(u31, 1), connection.last_peer_client_stream_id);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.wasLocallyResetAt(3, 0));
}

test "HTTP/2 refusal write failure makes later request reads terminal" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/refused" },
        .{ .name = ":scheme", .value = "https" },
    });
    try std.testing.expectError(
        error.NetworkDown,
        connection.refusePeerRequestStreamUntil(
            3,
            .{
                .header = .{
                    .length = @intCast(block.items.len),
                    .frame_type = .headers,
                    .flags = flag_end_headers,
                    .stream_id = 3,
                },
                .payload = block.items,
            },
            null,
            false,
        ),
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(error.ConnectionClosed, connection.readRequest());
    try std.testing.expect(!connection.wasLocallyResetAt(3, 0));
}

test "HTTP/2 refusal decode failure makes later request reads terminal" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }

    try std.testing.expectError(
        error.MessageTooLarge,
        connection.refusePeerRequestStreamUntil(
            3,
            .{
                .header = .{
                    .length = 1,
                    .frame_type = .headers,
                    .flags = flag_end_headers,
                    .stream_id = 3,
                },
                // An indexed integer whose continuation byte is missing.
                .payload = &.{0xff},
            },
            null,
            false,
        ),
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(error.ConnectionClosed, connection.readRequest());
}

test "HTTP/2 sendWindowUpdate rejects idle streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    // h2 only releases capacity for streams that exist in the state machine.
    // Sending WINDOW_UPDATE on an idle stream is a protocol error, so the
    // helper refuses before it mutates receive-window bookkeeping or writes.
    try std.testing.expectError(error.InvalidStreamId, connection.sendWindowUpdate(1, 1));
    try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
}

test "HTTP/2 local initial window config seeds receive stream windows" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .initial_window_size = 1024 },
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(i64, 1024), (try connection.recvStreamWindow(1)).value);
    try std.testing.expectEqual(@as(?usize, 0), connection.recv_stream_window_index.get(1));
}

test "HTTP/2 peer max concurrent streams limits locally opened streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .peer_max_concurrent_streams = 1,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activeLocalStreamCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activePeerStreamCount(),
    );
    try std.testing.expect(!connection.peerExtendedConnectEnabled());

    const first = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 1), first);
    try std.testing.expectEqual(@as(usize, 1), connection.active_local_streams.items.len);
    try std.testing.expectEqual(@as(?usize, 0), connection.active_local_index.get(first));
    try std.testing.expectEqual(
        @as(?u32, 0),
        connection.availableLocalStreamCapacity(),
    );
    try std.testing.expectError(error.FlowControlBlocked, connection.reserveNextClientStreamId());
    try std.testing.expectEqual(@as(u31, 3), connection.next_client_stream_id);

    connection.releaseLocalStream(first);
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    const second = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 3), second);
    try std.testing.expectEqual(@as(usize, 1), connection.active_local_streams.items.len);
    try std.testing.expectEqual(@as(?usize, 0), connection.active_local_index.get(second));
    connection.releaseLocalStream(second);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_index.count());
    connection.releaseLocalStream(second);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);

    const third = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 5), third);
    try std.testing.expectError(error.ConnectionGoAway, connection.handleGoAwayForStream(third, .{
        .last_stream_id = 3,
        .error_code = .no_error,
        .debug_data = &.{},
    }));
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
    try std.testing.expectError(error.InvalidFrame, connection.handleGoAwayForStream(1, .{
        .last_stream_id = 5,
        .error_code = .no_error,
        .debug_data = &.{},
    }));
}

test "HTTP/2 available local stream capacity matches priority reservations" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .peer_max_concurrent_streams = 2,
    };
    defer {
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
    }

    try std.testing.expectEqual(
        @as(?u32, 2),
        connection.availableLocalStreamCapacity(),
    );
    try connection.priority_state.reserveIdleRequest(
        allocator,
        3,
        connection.activeLocalStreamCount(),
        connection.peerMaxConcurrentStreams(),
        connection.limits.max_idle_priority_updates,
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    try connection.priority_state.reserveIdleRequest(
        allocator,
        connection.next_client_stream_id,
        connection.activeLocalStreamCount(),
        connection.peerMaxConcurrentStreams(),
        connection.limits.max_idle_priority_updates,
    );
    // The next request consumes its existing reservation rather than charging
    // the peer limit twice. One later unreserved stream also still fits.
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    const first = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 1), first);
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    const second = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 3), second);
    try std.testing.expectEqual(
        @as(?u32, 0),
        connection.availableLocalStreamCapacity(),
    );
}

test "HTTP/2 public peer capabilities track SETTINGS updates" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn writeSettingsUpdate(
            self: *@This(),
            stream: net.Stream,
            settings: []const http2.Setting,
        ) !void {
            var payload: std.ArrayList(u8) = .empty;
            defer payload.deinit(self.allocator);
            try http2.writeSettings(&payload, self.allocator, settings);
            try writeFrame(
                self.allocator,
                self.io,
                stream,
                .settings,
                0,
                0,
                payload.items,
            );
        }

        fn waitForSettingsAckAndPing(
            self: *@This(),
            stream: net.Stream,
            expected_ping: [8]u8,
        ) !void {
            var saw_settings_ack = false;
            var saw_ping = false;
            while (!saw_settings_ack or !saw_ping) {
                var frame = try readFrame(
                    self.allocator,
                    self.io,
                    stream,
                    .{},
                );
                defer frame.deinit(self.allocator);
                switch (frame.frame.header.frame_type) {
                    .settings => {
                        try std.testing.expect(
                            frame.frame.header.flags & flag_ack != 0,
                        );
                        saw_settings_ack = true;
                    },
                    .ping => {
                        try std.testing.expectEqual(
                            @as(u8, 0),
                            frame.frame.header.flags & flag_ack,
                        );
                        const ping = try http2.PingPayload.parse(frame.frame);
                        try std.testing.expectEqualSlices(
                            u8,
                            &expected_ping,
                            &ping.data,
                        );
                        try writeFrame(
                            self.allocator,
                            self.io,
                            stream,
                            .ping,
                            flag_ack,
                            0,
                            &ping.data,
                        );
                        saw_ping = true;
                    },
                    else => return error.UnexpectedFrame,
                }
            }
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(self.io, stream, &preface);
            try http2.validateClientPreface(&preface);

            var client_settings = try readFrame(
                self.allocator,
                self.io,
                stream,
                .{},
            );
            defer client_settings.deinit(self.allocator);
            try std.testing.expectEqual(
                http2.FrameType.settings,
                client_settings.frame.header.frame_type,
            );
            try std.testing.expectEqual(
                @as(u8, 0),
                client_settings.frame.header.flags & flag_ack,
            );

            try self.writeSettingsUpdate(stream, &.{
                .{
                    .id = .max_concurrent_streams,
                    .value = 3,
                },
                // RFC 9113 permits a server to make its effective zero value
                // explicit; the client must reject only value 1.
                .{ .id = .enable_push, .value = 0 },
            });
            try writeFrame(
                self.allocator,
                self.io,
                stream,
                .settings,
                flag_ack,
                0,
                &.{},
            );
            var initial_ack = try readFrame(
                self.allocator,
                self.io,
                stream,
                .{},
            );
            defer initial_ack.deinit(self.allocator);
            try std.testing.expectEqual(
                http2.FrameType.settings,
                initial_ack.frame.header.frame_type,
            );
            try std.testing.expect(
                initial_ack.frame.header.flags & flag_ack != 0,
            );

            try self.writeSettingsUpdate(stream, &.{
                .{ .id = .max_concurrent_streams, .value = 1 },
                .{ .id = .enable_connect_protocol, .value = 1 },
            });
            const first_ping = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
            try self.waitForSettingsAckAndPing(stream, first_ping);

            try self.writeSettingsUpdate(stream, &.{.{
                .id = .max_concurrent_streams,
                .value = 4,
            }});
            const second_ping = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
            try self.waitForSettingsAckAndPing(stream, second_ping);
        }
    };

    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{},
    );
    defer client.close();
    try std.testing.expectEqual(
        @as(?u32, 3),
        client.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 3),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(!client.peerExtendedConnectEnabled());

    const first_ping = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try std.testing.expectEqualSlices(u8, &first_ping, &(try client.ping(first_ping)));
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(client.peerExtendedConnectEnabled());

    const second_ping = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    try std.testing.expectEqualSlices(
        u8,
        &second_ping,
        &(try client.ping(second_ping)),
    );
    try std.testing.expectEqual(
        @as(?u32, 4),
        client.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 4),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(client.peerExtendedConnectEnabled());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client stream id allocation detects overflow" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .next_client_stream_id = std.math.maxInt(u31),
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    // Rust h2's StreamId::next_id returns an overflow error instead of wrapping
    // once the 31-bit stream-id space is exhausted.  Keep the same invariant so
    // long-lived clients cannot wrap to an invalid/previously-used stream id.
    try std.testing.expectError(error.InvalidStreamId, connection.reserveNextClientStreamId());
    try std.testing.expectEqual(@as(u31, std.math.maxInt(u31)), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
}

test "HTTP/2 active stream releases skip empty indexes" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.push_state.deinit(std.testing.allocator);
        connection.priority_state.deinit(std.testing.allocator);
        connection.response_semantics.deinit(std.testing.allocator);
        connection.response_semantics_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    // Release paths are frequently called from reset/cleanup code for streams
    // that may already be gone.  With empty indexes they should stay as cheap
    // no-ops and avoid probing the hash maps.
    try std.testing.expect(!connection.removeActiveLocalStream(1));
    try std.testing.expect(!connection.removeActivePeerStream(1));
    connection.releaseLocalStream(1);
    connection.releasePeerStream(1);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_index.count());
    try std.testing.expectEqual(@as(usize, 0), connection.active_peer_index.count());
}

test "HTTP/2 local max concurrent streams limits peer opened streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_concurrent_streams = 1 },
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.locally_reset_streams.deinit(std.testing.allocator);
        connection.locally_reset_stream_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.reservePeerStream(1);
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);
    try std.testing.expectEqual(@as(?usize, 0), connection.active_peer_index.get(1));
    try std.testing.expectError(error.FlowControlViolation, connection.reservePeerStream(3));
    connection.releasePeerStream(1);
    try connection.reservePeerStream(3);
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);

    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(3, .{
        .status = 204,
        .body = "must not send",
    }));
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);
    try std.testing.expectError(error.FlowControlViolation, connection.reservePeerStream(5));

    connection.releasePeerStream(3);
    try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
    try connection.reservePeerStream(5);
    try std.testing.expectError(error.InvalidStatus, connection.rejectExtendedConnect(5, 200, &.{}));
    try std.testing.expectError(
        error.InvalidContentLength,
        connection.rejectExtendedConnectWithBody(
            5,
            304,
            &.{},
            "not allowed",
            &.{},
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);
    connection.releasePeerStream(5);
    try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
}

test "HTTP/2 refused request advances observed but not processed boundary" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{
            .max_concurrent_streams = 1,
            .max_reset_stream_history = 0,
        },
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
    }

    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.admitted,
        try connection.claimPeerRequestStream(1),
    );
    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.refused,
        try connection.claimPeerRequestStream(3),
    );
    try std.testing.expectEqual(@as(u31, 3), connection.last_peer_client_stream_id);
    try std.testing.expectEqual(@as(u31, 1), connection.lastPeerProcessedStreamId());
    connection.releasePeerStream(1);
    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.admitted,
        try connection.claimPeerRequestStream(5),
    );
    try std.testing.expectEqual(@as(u31, 5), connection.lastPeerProcessedStreamId());
}

test "HTTP/2 SETTINGS_MAX_FRAME_SIZE controls outbound DATA splitting" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        data_lengths: [4]usize = [_]usize{0} ** 4,
        data_count: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);
            const limits = Limits{ .max_frame_payload = 64 * 1024, .max_body_bytes = 128 * 1024, .max_frame_size = 20_000 };

            var preface_buf: [http2.connection_preface.len]u8 = undefined;
            try readExact(shared.io, stream, &preface_buf);
            try http2.validateClientPreface(&preface_buf);

            var client_settings = try readFrame(shared.allocator, shared.io, stream, limits);
            defer client_settings.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_settings.frame.header.frame_type);
            try std.testing.expectEqual(@as(u8, 0), client_settings.frame.header.flags & flag_ack);

            var settings_payload: std.ArrayList(u8) = .empty;
            defer settings_payload.deinit(shared.allocator);
            try http2.writeSettings(&settings_payload, shared.allocator, &.{
                .{ .id = .max_frame_size, .value = 20_000 },
            });
            try writeFrame(shared.allocator, shared.io, stream, .settings, 0, 0, settings_payload.items);
            try writeFrame(shared.allocator, shared.io, stream, .settings, flag_ack, 0, &.{});

            var client_ack = try readFrame(shared.allocator, shared.io, stream, limits);
            defer client_ack.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_ack.frame.header.frame_type);
            try std.testing.expect((client_ack.frame.header.flags & flag_ack) != 0);

            var request_stream_id: u31 = 0;
            while (true) {
                var frame = try readFrame(shared.allocator, shared.io, stream, limits);
                defer frame.deinit(shared.allocator);
                switch (frame.frame.header.frame_type) {
                    .headers => {
                        request_stream_id = frame.frame.header.stream_id;
                    },
                    .data => {
                        const data = try http2.DataPayload.parse(frame.frame);
                        try std.testing.expect(shared.data_count < shared.data_lengths.len);
                        shared.data_lengths[shared.data_count] = data.data.len;
                        shared.data_count += 1;
                        if ((frame.frame.header.flags & flag_end_stream) != 0) break;
                    },
                    else => {},
                }
            }

            try std.testing.expectEqual(@as(u31, 1), request_stream_id);
            var response_block: std.ArrayList(u8) = .empty;
            defer response_block.deinit(shared.allocator);
            try http2.Hpack.encodeLiteralBlock(&response_block, shared.allocator, &.{
                .{ .name = ":status", .value = "200" },
            });
            try writeFrame(shared.allocator, shared.io, stream, .headers, flag_end_headers | flag_end_stream, request_stream_id, response_block.items);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const body = try allocator.alloc(u8, 45_000);
    defer allocator.free(body);
    @memset(body, 'x');

    var client = try Client.connect(allocator, io, listener.socket.address, .{ .max_frame_payload = 64 * 1024, .max_body_bytes = 128 * 1024 });
    defer client.close();
    var response = try client.request(.{
        .method = "POST",
        .path = "/split-data",
        .authority = "localhost",
        .body = body,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqual(@as(usize, 3), shared.data_count);
    try std.testing.expectEqual(@as(usize, 20_000), shared.data_lengths[0]);
    try std.testing.expectEqual(@as(usize, 20_000), shared.data_lengths[1]);
    try std.testing.expectEqual(@as(usize, 5_000), shared.data_lengths[2]);
}

test "HTTP/2 readFrame enforces inbound SETTINGS_MAX_FRAME_SIZE before payload read" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);
            try std.testing.expectError(error.MessageTooLarge, readFrame(shared.allocator, shared.io, stream, .{
                .max_frame_payload = 64 * 1024,
                .max_frame_size = default_max_frame_size,
            }));
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    // Send only the header.  A compliant receiver can reject this frame from
    // the advertised size alone and must not allocate or block waiting for the
    // oversized payload bytes.
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    try (http2.FrameHeader{
        .length = @intCast(default_max_frame_size + 1),
        .frame_type = .data,
        .flags = 0,
        .stream_id = 1,
    }).write(&raw, allocator);
    try writeAll(io, stream, raw.items);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime rejects invalid local SETTINGS limits" {
    if (@sizeOf(usize) > @sizeOf(u32)) {
        const beyond_settings_value = @as(usize, std.math.maxInt(u32)) + 1;
        try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
            .header_table_size = beyond_settings_value,
        }));
        try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
            .max_header_list_size = beyond_settings_value,
        }));
    }
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .initial_window_size = @as(u32, std.math.maxInt(i31)) + 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .initial_connection_window_size = @as(u32, @intCast(default_flow_window)) - 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .initial_connection_window_size = @as(u32, std.math.maxInt(i31)) + 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_frame_size = default_max_frame_size - 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_frame_size = max_max_frame_size + 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_idle_priority_updates = 0,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_pending_ping_frames = 0,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .reset_stream_duration = .fromNanoseconds(-1),
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .adaptive_window = true,
        .adaptive_window_max = 1024,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .adaptive_window = true,
        .adaptive_window_max = @as(u32, std.math.maxInt(i31)) + 1,
    }));
    try validateLocalLimits(.{
        .header_table_size = std.math.maxInt(u32),
        .initial_window_size = std.math.maxInt(i31),
        .initial_connection_window_size = std.math.maxInt(i31),
        .max_frame_size = max_max_frame_size,
        .max_header_list_size = std.math.maxInt(u32),
    });
}

test "HTTP/2 local SETTINGS preserve maximum 32-bit header limits" {
    const settings = try settingsForLimits(.{
        .header_table_size = std.math.maxInt(u32),
        .max_header_list_size = std.math.maxInt(u32),
    }, .server);
    var header_table_size: ?u32 = null;
    var header_list_size: ?u32 = null;
    for (settings.buf[0..settings.count]) |setting| switch (setting.id) {
        .header_table_size => header_table_size = setting.value,
        .max_header_list_size => header_list_size = setting.value,
        else => {},
    };
    try std.testing.expectEqual(
        @as(?u32, std.math.maxInt(u32)),
        header_table_size,
    );
    try std.testing.expectEqual(
        @as(?u32, std.math.maxInt(u32)),
        header_list_size,
    );
}

test "HTTP/2 constructors reject unrepresentable SETTINGS before I/O" {
    if (@sizeOf(usize) <= @sizeOf(u32)) return;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const unreachable_address = net.IpAddress{ .ip4 = .loopback(1) };
    const beyond_settings_value = @as(usize, std.math.maxInt(u32)) + 1;

    try std.testing.expectError(
        error.InvalidSetting,
        Server.listen(allocator, io, unreachable_address, .{
            .header_table_size = beyond_settings_value,
        }),
    );
    try std.testing.expectError(
        error.InvalidSetting,
        Client.connect(allocator, io, unreachable_address, .{
            .max_header_list_size = beyond_settings_value,
        }),
    );
}

test "HTTP/2 runtime validates SETTINGS frame-size and window bounds" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }
    try std.testing.expect(!connection.peerPushEnabled());

    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = default_max_frame_size - 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = max_max_frame_size + 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .initial_window_size, .value = @as(u32, std.math.maxInt(i31)) + 1 },
    }));
    try connection.applySettings(&.{
        .{ .id = .enable_push, .value = 0 },
        .{ .id = .no_rfc7540_priorities, .value = 1 },
    });
    try std.testing.expect(!connection.peer_enable_push);
    try std.testing.expect(connection.peer_no_rfc7540_priorities);
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .enable_push, .value = 1 },
    }));
    try std.testing.expect(!connection.peer_enable_push);

    try connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = 32_768 },
        .{ .id = .max_concurrent_streams, .value = 7 },
        .{ .id = .header_table_size, .value = 128 },
    });
    try std.testing.expectEqual(@as(usize, 32_768), connection.peer_max_frame_size);
    try std.testing.expectEqual(
        @as(?u32, 7),
        connection.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(@as(usize, 128), connection.hpack_encoder.dynamic_table.size_limit);
    try std.testing.expect(connection.peer_no_rfc7540_priorities);

    // A peer setting is permission, not an instruction to retain up to 4 GiB
    // of encoder state. The default local ceiling remains 4 KiB.
    try connection.applySettings(&.{.{
        .id = .header_table_size,
        .value = std.math.maxInt(u32),
    }});
    try std.testing.expectEqual(
        http2.Hpack.default_dynamic_table_size,
        connection.hpack_encoder.dynamic_table.size_limit,
    );

    try connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 0 },
    });
    try std.testing.expect(!connection.peerExtendedConnectEnabled());
    try connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 1 },
    });
    try std.testing.expect(connection.peerExtendedConnectEnabled());
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 0 },
    }));
    try std.testing.expect(connection.peerExtendedConnectEnabled());
    try connection.applySettings(&.{
        .{ .id = .no_rfc7540_priorities, .value = 1 },
    });
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .no_rfc7540_priorities, .value = 0 },
    }));

    var server_connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        server_connection.send_stream_windows.deinit(std.testing.allocator);
        server_connection.recv_stream_windows.deinit(std.testing.allocator);
        server_connection.hpack_decoder.deinit(std.testing.allocator);
        server_connection.hpack_encoder.deinit(std.testing.allocator);
    }
    try server_connection.applySettings(&.{.{ .id = .enable_push, .value = 0 }});
    try std.testing.expect(!server_connection.peer_enable_push);
    try server_connection.applySettings(&.{.{ .id = .enable_push, .value = 1 }});
    try std.testing.expect(server_connection.peer_enable_push);
    try std.testing.expectError(error.InvalidSetting, server_connection.applySettings(&.{
        .{ .id = .enable_push, .value = 2 },
    }));
}

test "HTTP/2 runtime applies independent local HPACK table limits" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{
            .header_table_size = 32,
            .max_encoder_table_size = 128,
        },
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }
    connection.applyLocalLimits();
    try std.testing.expectEqual(@as(usize, 32), connection.hpack_decoder.max_dynamic_table_size);
    try std.testing.expectEqual(
        @as(usize, 128),
        connection.hpack_encoder.dynamic_table.size_limit,
    );
    try connection.applySettings(&.{.{
        .id = .header_table_size,
        .value = 1024,
    }});
    try std.testing.expectEqual(
        @as(usize, 128),
        connection.hpack_encoder.dynamic_table.size_limit,
    );

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(std.testing.allocator);
    try block.appendSlice(std.testing.allocator, &.{ 0x3f, 0x02 }); // Dynamic table size update value 33 > local limit.
    try std.testing.expectError(error.InvalidEncoding, connection.hpack_decoder.decodeBlock(std.testing.allocator, block.items));
}

test "HTTP/2 runtime enforces header list size limits" {
    const allocator = std.testing.allocator;

    const oversized = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "x-large", .value = "0123456789" },
    };
    try std.testing.expectError(error.MessageTooLarge, validateHeaderListSize(&oversized, 172));
    try validateHeaderListSize(&oversized, 173);

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &oversized);
    var decoder = http2.Hpack.Decoder{};
    defer decoder.deinit(allocator);
    try std.testing.expectError(error.MessageTooLarge, decodeOwnedHeaders(allocator, block.items, .{
        .max_header_fields = 16,
        .max_header_list_size = 120,
    }, &decoder));
    var no_alloc_block: std.ArrayList(u8) = .empty;
    defer no_alloc_block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(
        &no_alloc_block,
        allocator,
        &.{.{
            .name = "authorization",
            .value = "compressible-value",
        }},
    );
    var no_alloc_decoder = http2.Hpack.Decoder{};
    defer no_alloc_decoder.deinit(allocator);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        decodeOwnedHeaders(
            no_alloc.allocator(),
            no_alloc_block.items,
            .{
                .max_header_fields = 16,
                .max_header_list_size = 1,
            },
            &no_alloc_decoder,
        ),
    );
    try std.testing.expect(!no_alloc.has_induced_failure);

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }
    try connection.applySettings(&.{.{ .id = .max_header_list_size, .value = 120 }});
    try std.testing.expectEqual(@as(usize, 120), connection.peer_max_header_list_size);
    try std.testing.expectError(error.MessageTooLarge, connection.writeHeaders(1, &oversized, true));
}

test "HTTP/2 runtime decodes owned headers into one allocation" {
    const allocator = std.testing.allocator;
    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-first", .value = "one", .never_index = true },
        .{ .name = "x-second", .value = "two", .never_index = true },
    };
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &fields);
    var decoder = http2.Hpack.Decoder{};
    defer decoder.deinit(allocator);
    const cloned = try decodeOwnedHeaders(
        allocator,
        block.items,
        .{ .max_header_fields = 8 },
        &decoder,
    );
    defer freeHeaders(allocator, cloned);

    try std.testing.expect(cloned[0].block_storage != null);
    try std.testing.expect(cloned[1].block_storage == null);
    try std.testing.expectEqual(
        @intFromPtr(cloned.ptr),
        @intFromPtr(cloned[0].block_storage.?.ptr),
    );
    try std.testing.expectEqualStrings("x-second", cloned[2].name);
    const storage = cloned[0].block_storage.?;
    for (cloned) |field| {
        try std.testing.expect(@intFromPtr(field.name.ptr) >= @intFromPtr(storage.ptr));
        try std.testing.expect(@intFromPtr(field.value.ptr) >= @intFromPtr(storage.ptr));
        try std.testing.expect(
            @intFromPtr(field.value.ptr) + field.value.len <=
                @intFromPtr(storage.ptr) + storage.len,
        );
    }

    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    var tracked_decoder = http2.Hpack.Decoder{};
    defer tracked_decoder.deinit(tracking.allocator());
    const before = tracking.allocations;
    const tracked_headers = try decodeOwnedHeaders(
        tracking.allocator(),
        block.items,
        .{ .max_header_fields = 8 },
        &tracked_decoder,
    );
    defer freeHeaders(tracking.allocator(), tracked_headers);
    // The plan list stays on the stack; the final fields and strings share one
    // aligned allocation for a static/literal application result.
    try std.testing.expectEqual(before + 1, tracking.allocations);
}

test "HTTP/2 runtime advertises configured initial SETTINGS" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        header_table_size: ?u32 = null,
        initial_window_size: ?u32 = null,
        max_concurrent_streams: ?u32 = null,
        max_frame_size: ?u32 = null,
        max_header_list_size: ?u32 = null,
        enable_push: ?u32 = null,
        enable_connect_protocol: ?u32 = null,
        no_rfc7540_priorities: ?u32 = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var frame = try readFrame(shared.allocator, shared.io, stream, .{});
            defer frame.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, frame.frame.header.frame_type);
            const settings = try http2.parseSettings(shared.allocator, frame.frame.payload);
            defer shared.allocator.free(settings);
            for (settings) |setting| switch (setting.id) {
                .header_table_size => shared.header_table_size = setting.value,
                .initial_window_size => shared.initial_window_size = setting.value,
                .max_concurrent_streams => shared.max_concurrent_streams = setting.value,
                .max_frame_size => shared.max_frame_size = setting.value,
                .max_header_list_size => shared.max_header_list_size = setting.value,
                .enable_push => shared.enable_push = setting.value,
                .enable_connect_protocol => shared.enable_connect_protocol = setting.value,
                .no_rfc7540_priorities => shared.no_rfc7540_priorities = setting.value,
                else => {},
            };
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeInitialSettings(allocator, io, stream, .{
        .header_table_size = 1024,
        .initial_window_size = 70_000,
        .max_concurrent_streams = 11,
        .max_frame_size = 20_000,
        .max_header_list_size = 4096,
        .enable_connect_protocol = true,
        .no_rfc7540_priorities = true,
    }, .client);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(?u32, 1024), shared.header_table_size);
    try std.testing.expectEqual(@as(?u32, 70_000), shared.initial_window_size);
    try std.testing.expectEqual(@as(?u32, 11), shared.max_concurrent_streams);
    try std.testing.expectEqual(@as(?u32, 20_000), shared.max_frame_size);
    try std.testing.expectEqual(@as(?u32, 4096), shared.max_header_list_size);
    try std.testing.expectEqual(@as(?u32, 0), shared.enable_push);
    try std.testing.expectEqual(@as(?u32, 1), shared.enable_connect_protocol);
    try std.testing.expectEqual(
        @as(?u32, 1),
        shared.no_rfc7540_priorities,
    );
}

test {
    _ = @import("connect/rejection_tests.zig");
    _ = @import("frame/retention_tests.zig");
    _ = @import("headers/limit_reuse_tests.zig");
    _ = @import("headers/reset_deadline_tests.zig");
    _ = @import("reset/header_failure_tests.zig");
    _ = @import("request/batch_error_tests.zig");
    _ = @import("response/credit_lifecycle_tests.zig");
    _ = @import("response/credit_failure_tests.zig");
    _ = @import("response/allocation_failure_tests.zig");
    _ = @import("response/forbidden_body_tests.zig");
    _ = @import("response/batch_trailer_sync_tests.zig");
    _ = @import("response/batch_trailer_failure_tests.zig");
    _ = @import("response/padding_credit_tests.zig");
    _ = @import("response/padding_failure_tests.zig");
    _ = @import("request/padding_credit_tests.zig");
    _ = @import("flow/tests/padding.zig");
    _ = @import("push/padding_credit_tests.zig");
    _ = @import("push/credit_failure_tests.zig");
    _ = @import("push/credit_refill_tests.zig");
    _ = @import("push/credit_fault_tests.zig");
    _ = @import("push/credit_transport_tests.zig");
    _ = @import("push/late_credit_tests.zig");
    _ = @import("request/body_length_tests.zig");
    _ = @import("request/credit_failure_tests.zig");
    _ = @import("request/allocation_failure_tests.zig");
    _ = @import("response/body_length_tests.zig");
    _ = @import("frame/tests/io.zig");
    _ = @import("frame/tests/wire.zig");
    _ = @import("flow/tests/window.zig");
    _ = @import("flow/tests/data.zig");
    _ = @import("headers/tests/message.zig");
    _ = @import("../../http/field_value_tests.zig");
    _ = @import("headers/value_reuse_tests.zig");
    _ = @import("tls_tests.zig");
    _ = @import("push_tests.zig");
    _ = @import("priority_tests.zig");
    _ = @import("priority/legacy_tests.zig");
    _ = @import("priority/dictionary_tests.zig");
    _ = @import("priority/metadata_tests.zig");
    _ = @import("priority/legacy_shutdown_tests.zig");
    _ = @import("streaming_response_tests.zig");
    _ = @import("response_batch_tests.zig");
    _ = @import("informational_batch_tests.zig");
    _ = @import("response_writer_tests.zig");
    _ = @import("request_writer_tests.zig");
    _ = @import("ping_timeout_tests.zig");
    _ = @import("refusal_tests.zig");
    _ = @import("connect_udp_tests.zig");
    _ = @import("connect_udp_relay_tests.zig");
    _ = @import("connect_ip_tests.zig");
    _ = @import("handshake_timeout_tests.zig");
    _ = @import("proxy_tests.zig");
    _ = @import("redirect_tests.zig");
    _ = @import("server_lifecycle_tests.zig");
    _ = @import("unix_tests.zig");
}

test {
    _ = @import("push/receive_tests.zig");
    _ = @import("push/receive_order_tests.zig");
    _ = @import("push/receive_lifecycle_tests.zig");
    _ = @import("push/receive_error_tests.zig");
    _ = @import("push/receive_store_tests.zig");
}
