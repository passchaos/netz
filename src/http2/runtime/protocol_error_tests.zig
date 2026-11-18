//! HTTP/2 protocol-error, GOAWAY, and push-validation tests.

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

test "HTTP/2 client maps SETTINGS on a stream to PROTOCOL_ERROR GOAWAY" {
    try expectClientConnectionErrorGoAway(
        .settings,
        1,
        &.{},
        error.InvalidFrame,
        .protocol_error,
        "frame-envelope",
    );
}

test "HTTP/2 server maps invalid initial SETTINGS envelope to GOAWAY" {
    try expectServerInitialConnectionErrorGoAway(
        .settings,
        1,
        &.{},
        error.InvalidFrame,
        .protocol_error,
        "frame-envelope",
    );
}

test "HTTP/2 server maps invalid initial window setting to FLOW_CONTROL_ERROR" {
    var payload: [6]u8 = undefined;
    std.mem.writeInt(
        u16,
        payload[0..2],
        @intFromEnum(http2.SettingId.initial_window_size),
        .big,
    );
    std.mem.writeInt(u32, payload[2..6], 0x8000_0000, .big);
    try expectServerInitialConnectionErrorGoAway(
        .settings,
        0,
        &payload,
        error.InvalidSetting,
        .flow_control_error,
        "settings-value",
    );
}

test "HTTP/2 client maps invalid peer settings to precise GOAWAY codes" {
    var initial_window: [6]u8 = undefined;
    std.mem.writeInt(
        u16,
        initial_window[0..2],
        @intFromEnum(http2.SettingId.initial_window_size),
        .big,
    );
    std.mem.writeInt(u32, initial_window[2..6], 0x8000_0000, .big);
    try expectClientConnectionErrorGoAway(
        .settings,
        0,
        &initial_window,
        error.InvalidSetting,
        .flow_control_error,
        "settings-value",
    );

    var enable_push: [6]u8 = undefined;
    std.mem.writeInt(
        u16,
        enable_push[0..2],
        @intFromEnum(http2.SettingId.enable_push),
        .big,
    );
    std.mem.writeInt(u32, enable_push[2..6], 1, .big);
    try expectClientConnectionErrorGoAway(
        .settings,
        0,
        &enable_push,
        error.InvalidSetting,
        .protocol_error,
        "settings-value",
    );
}

test "HTTP/2 client maps malformed PING length to FRAME_SIZE_ERROR GOAWAY" {
    try expectClientConnectionErrorGoAway(
        .ping,
        0,
        &.{ 0, 1, 2, 3, 4, 5, 6 },
        error.InvalidFrame,
        .frame_size_error,
        "frame-envelope",
    );
}

test "HTTP/2 client resets zero WINDOW_UPDATE stream and keeps connection" {
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
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .window_update,
                0,
                first.stream_id,
                &.{ 0, 0, 0, 0 },
            );
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(2),
            );
            defer reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(first.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.protocol_error,
                reset.reset.error_code,
            );

            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try connection.writeResponse(second.stream_id, .{
                .status = 200,
                .body = "reused",
                .request_method = second.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    try std.testing.expectError(error.InvalidFrame, client.request(.{
        .path = "/zero-window",
        .authority = "localhost",
    }));
    try std.testing.expect(client.isReusable());

    var response = try client.request(.{
        .path = "/after-zero-window",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("reused", response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client maps malformed response HPACK to COMPRESSION_ERROR GOAWAY" {
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
        saw_goaway: bool = false,
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
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .headers,
                flag_end_headers | flag_end_stream,
                request.stream_id,
                &.{0x80},
            );
            var goaway = try connection.readGoAway();
            defer goaway.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                http2.ErrorCode.compression_error,
                goaway.goaway.error_code,
            );
            shared.saw_goaway = true;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    try std.testing.expectError(error.InvalidEncoding, client.request(.{
        .path = "/bad-response-hpack",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_goaway);
}

test "HTTP/2 client maps cross-stream response CONTINUATION to PROTOCOL_ERROR GOAWAY" {
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
            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .headers,
                0,
                request.stream_id,
                &.{0x88},
            );
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .continuation,
                flag_end_headers,
                request.stream_id + 2,
                &.{},
            );
            var wire_error = try readFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                connection.limits,
            );
            defer wire_error.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                http2.FrameType.goaway,
                wire_error.frame.header.frame_type,
            );
            try std.testing.expectEqual(
                http2.ErrorCode.protocol_error,
                (try http2.GoAwayPayload.parse(wire_error.frame)).error_code,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    try std.testing.expectError(error.UnexpectedFrame, client.request(.{
        .path = "/bad-response-continuation",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 informational callback cannot reenter frame reader" {
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
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try connection.writeInformationalResponse(
                first.stream_id,
                103,
                &.{.{ .name = "link", .value = "</next>" }},
            );
            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 3), second.stream_id);
            try connection.writeResponse(first.stream_id, .{
                .body = "one",
                .request_method = first.method,
            });
            try connection.writeResponse(second.stream_id, .{
                .body = "two",
                .request_method = second.method,
            });
        }
    };

    const Observer = struct {
        connection: *Connection,
        second: ?Connection.PendingResponse = null,
        error_seen: ?anyerror = null,
        reset_error_seen: ?anyerror = null,
        unexpectedly_read: bool = false,

        fn observe(
            raw: *anyopaque,
            head: StreamingResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (head.status != 103) @panic("unexpected interim status");
            self.second = self.connection.sendCompleteRequest(.{
                .path = "/second",
                .authority = "localhost",
            }) catch |err| {
                self.error_seen = err;
                return;
            };
            var nested = self.connection.readResponse(
                self.second.?.stream_id,
                self.second.?.request_method,
                self.second.?.extended_connect,
                null,
            ) catch |err| {
                self.error_seen = err;
                self.probeReset();
                return;
            };
            self.unexpectedly_read = true;
            nested.deinit(self.connection.allocator);
            self.probeReset();
        }

        fn probeReset(self: *@This()) void {
            self.connection.sendResetStream(
                self.second.?.stream_id,
                .cancel,
            ) catch |err| {
                self.reset_error_seen = err;
                return;
            };
            self.unexpectedly_read = true;
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
    const first = try client.sendCompleteRequest(.{
        .path = "/first",
        .authority = "localhost",
    });
    var observer = Observer{ .connection = &client };
    var first_response = try client.readResponse(
        first.stream_id,
        first.request_method,
        first.extended_connect,
        .{ .context = &observer, .on_response = Observer.observe },
    );
    defer first_response.deinit(allocator);
    try std.testing.expect(!observer.unexpectedly_read);
    switch (observer.error_seen orelse return error.TestUnexpectedResult) {
        error.UnexpectedFrame => {},
        else => return error.TestUnexpectedResult,
    }
    switch (observer.reset_error_seen orelse return error.TestUnexpectedResult) {
        error.UnexpectedFrame => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualStrings("one", first_response.body);

    const second = observer.second orelse return error.TestUnexpectedResult;
    var second_response = try client.readResponse(
        second.stream_id,
        second.request_method,
        second.extended_connect,
        null,
    );
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings("two", second_response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client rejects END_STREAM on informational response" {
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
            try std.testing.expectEqualStrings("/bad-interim-h2", request.path);
            try connection.writeHeaders(request.stream_id, &.{
                .{ .name = ":status", .value = "103" },
            }, true);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.UnexpectedFrame, client.request(.{
        .method = "GET",
        .path = "/bad-interim-h2",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client rejects content-length on informational response" {
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
            try std.testing.expectEqualStrings("/bad-interim-length-h2", request.path);
            // HTTP semantics forbid Content-Length on informational responses.
            // Validate before skipping 1xx HEADERS; otherwise this invalid
            // response could be silently ignored before the final response.
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

    try std.testing.expectError(error.InvalidContentLength, client.request(.{
        .method = "GET",
        .path = "/bad-interim-length-h2",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client rejects PUSH_PROMISE after disabling push" {
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
            try std.testing.expectEqualStrings("/push-disabled", request.path);

            var promised_block: std.ArrayList(u8) = .empty;
            defer promised_block.deinit(server_ptr.allocator);
            try http2.Hpack.encodeLiteralBlock(&promised_block, server_ptr.allocator, &.{
                .{ .name = ":method", .value = "GET" },
                .{ .name = ":path", .value = "/pushed" },
                .{ .name = ":scheme", .value = "https" },
            });
            var promise: std.ArrayList(u8) = .empty;
            defer promise.deinit(server_ptr.allocator);
            try http2.PushPromisePayload.write(&promise, server_ptr.allocator, request.stream_id, 2, promised_block.items, .{});
            try writeAll(server_ptr.io, connection.stream, promise.items);

            var goaway = try connection.readGoAway();
            defer goaway.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                http2.ErrorCode.protocol_error,
                goaway.goaway.error_code,
            );
            try std.testing.expectEqualStrings(
                "push-disabled",
                goaway.goaway.debug_data,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidFrame, client.request(.{
        .method = "GET",
        .path = "/push-disabled",
        .authority = "localhost",
    }));
    try std.testing.expect(!client.isReusable());
    try std.testing.expect(client.push_state.state == null);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 validates PUSH_PROMISE parent and promised stream ids" {
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

    const valid_parent_even_promise = http2.Frame{
        .header = .{ .length = 4, .frame_type = .push_promise, .flags = flag_end_headers, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 2 },
    };
    try std.testing.expectError(error.InvalidFrame, connection.validatePushPromiseForClientStream(valid_parent_even_promise));

    try connection.addActiveLocalStream(1);
    const promise = try connection.validatePushPromiseForClientStream(valid_parent_even_promise);
    try std.testing.expectEqual(@as(u31, 1), promise.stream_id);
    try std.testing.expectEqual(@as(u31, 2), promise.promised_stream_id);

    const odd_promised_stream = http2.Frame{
        .header = .{ .length = 4, .frame_type = .push_promise, .flags = flag_end_headers, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 3 },
    };
    try std.testing.expectError(error.InvalidStreamId, connection.validatePushPromiseForClientStream(odd_promised_stream));
}

test "HTTP/2 client fails active request rejected by GOAWAY" {
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
            try std.testing.expectEqualStrings("/goaway-reject", request.path);
            try connection.sendGoAway(0, .no_error, "draining");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try std.testing.expectEqual(
        GoAwayRetryDisposition.no_goaway,
        client.goAwayRetryDisposition(1),
    );

    try std.testing.expectError(error.ConnectionGoAway, client.request(.{
        .method = "GET",
        .path = "/goaway-reject",
        .authority = "localhost",
    }));
    try std.testing.expectEqual(
        @as(?u31, 0),
        client.peerGoAwayLastStreamId(),
    );
    try std.testing.expectEqual(
        GoAwayRetryDisposition.safe_to_retry,
        client.goAwayRetryDisposition(1),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client continues active request allowed by GOAWAY" {
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
            try std.testing.expectEqualStrings("/goaway-allowed", request.path);
            try connection.sendGoAway(request.stream_id, .no_error, "draining");
            try connection.writeResponse(request.stream_id, .{ .body = "still-ok" });
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
        .path = "/goaway-allowed",
        .authority = "localhost",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("still-ok", response.body);
    try std.testing.expectEqual(
        GoAwayRetryDisposition.may_have_been_processed,
        client.goAwayRetryDisposition(1),
    );
}

test "HTTP/2 client refuses new request after peer GOAWAY" {
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
            try std.testing.expectEqualStrings("/first-before-goaway", request.path);
            try connection.sendGoAway(request.stream_id, .no_error, "draining");
            try connection.writeResponse(request.stream_id, .{ .body = "first" });

            // If the client incorrectly opens stream 3 after GOAWAY, this read
            // would eventually observe it.  The test expects the client to
            // reject locally instead, so the server can simply return.
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
        .path = "/first-before-goaway",
        .authority = "localhost",
    });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.body);

    try std.testing.expectError(error.ConnectionGoAway, client.request(.{
        .method = "GET",
        .path = "/second-after-goaway",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}
