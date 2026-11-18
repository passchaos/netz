//! HTTP/2 CONTINUATION, priority, and stream-ordering tests.

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

test "HTTP/2 runtime reads and writes CONTINUATION header blocks" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 24, .max_body_bytes = 4096, .max_frame_size = 16 * 1024 },
    );
    defer server.deinit();

    const long_header_value = "abcdefghijklmnopqrstuvwxyz0123456789";
    const Shared = struct {
        server: *Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server, shared.expected) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server, expected: []const u8) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/continuation", request.path);
            try std.testing.expectEqualStrings(expected, findHeader(request.headers, "x-long").?);
            const scratch_capacity = connection.header_block_scratch.capacity;
            const scratch_ptr = connection.header_block_scratch
                .allocatedSlice().ptr;
            try std.testing.expect(scratch_capacity != 0);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{
                    .{ .name = "content-type", .value = "text/plain" },
                    .{ .name = "x-long-response", .value = expected },
                },
                .body = "ok",
            });

            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "/continuation-two",
                second.path,
            );
            try std.testing.expectEqualStrings(
                expected,
                findHeader(second.headers, "x-long").?,
            );
            try std.testing.expectEqual(
                scratch_capacity,
                connection.header_block_scratch.capacity,
            );
            try std.testing.expectEqual(
                scratch_ptr,
                connection.header_block_scratch.allocatedSlice().ptr,
            );
            try connection.writeResponse(second.stream_id, .{
                .status = 204,
            });
        }
    };

    var shared = Shared{ .server = &server, .expected = long_header_value };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 24,
        .max_body_bytes = 4096,
        .max_frame_size = 16 * 1024,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/continuation",
        .authority = "localhost",
        .headers = &.{.{ .name = "x-long", .value = long_header_value }},
    });
    defer response.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expectEqualStrings(long_header_value, findHeader(response.headers, "x-long-response").?);

    var second = try client.request(.{
        .method = "GET",
        .path = "/continuation-two",
        .authority = "localhost",
        .headers = &.{.{ .name = "x-long", .value = long_header_value }},
    });
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), second.status);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 single-frame HEADERS bypass continuation scratch" {
    const allocator = std.testing.allocator;
    var encoder = http2.Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/single" },
        .{ .name = ":scheme", .value = "http" },
    });
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.hpack_decoder.deinit(allocator);
        connection.header_block_scratch.deinit(allocator);
    }
    const headers = try connection.readHeaderBlock(.{
        .header = .{
            .length = @intCast(block.items.len),
            .frame_type = .headers,
            .flags = flag_end_headers | flag_end_stream,
            .stream_id = 1,
        },
        .payload = block.items,
    });
    defer freeHeaders(allocator, headers);
    try std.testing.expectEqualStrings("/single", findHeader(headers, ":path").?);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.header_block_scratch.capacity,
    );
}

test "HTTP/2 runtime bounds CONTINUATION frame chains" {
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
            .max_continuation_frames = 2,
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
            try std.testing.expectError(error.MessageTooLarge, connection.readRequest());
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
        .{ .name = ":path", .value = "/continuation-flood" },
        .{ .name = ":scheme", .value = "https" },
    });
    try writeFrame(allocator, io, client.stream, .headers, 0, 1, block.items);
    try writeFrame(allocator, io, client.stream, .continuation, 0, 1, &.{});
    try writeFrame(allocator, io, client.stream, .continuation, 0, 1, &.{});
    try writeFrame(allocator, io, client.stream, .continuation, flag_end_headers, 1, &.{});

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime decodes padded priority HEADERS payloads" {
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
            try std.testing.expectEqualStrings("/padded-priority", request.path);
            try std.testing.expectEqualStrings("hello", request.body);

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

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/padded-priority" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "content-length", .value = "5" },
    });

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.append(allocator, 2); // Pad Length.
    try payload.appendSlice(allocator, &.{ 0, 0, 0, 0, 16 }); // PRIORITY: dependency 0, weight 16.
    try payload.appendSlice(allocator, block.items);
    try payload.appendSlice(allocator, &.{ 0, 0 });

    const flags = flag_end_headers | @as(u8, (@as(http2.Flags, .{ .padded = true, .priority = true })).byte());
    try writeFrame(allocator, io, client.stream, .headers, flags, 1, payload.items);
    try client.addActiveLocalStream(1);
    try client.writeData(1, "hello", true);

    var response = try client.readResponse(1, "POST", false, null);
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
}

test "HTTP/2 runtime ignores HEADERS priority self dependency" {
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
                shared.err = err;
                return;
            };
            defer request.deinit(shared.server.allocator);
            shared.saw_expected = std.mem.eql(
                u8,
                request.path,
                "/self-priority",
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

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/self-priority" },
        .{ .name = ":scheme", .value = "https" },
    });

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.appendSlice(allocator, &.{ 0, 0, 0, 1, 16 }); // PRIORITY depends on stream 1 itself.
    try payload.appendSlice(allocator, block.items);
    const flags = flag_end_headers | flag_end_stream |
        @as(u8, (@as(http2.Flags, .{ .priority = true })).byte());
    try writeFrame(allocator, io, client.stream, .headers, flags, 1, payload.items);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 runtime answers PING while reading request body" {
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
            try std.testing.expectEqualStrings("/interleaved-ping", request.path);
            try std.testing.expectEqualStrings("hello", request.body);
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

    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/interleaved-ping" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "content-length", .value = "5" },
    };
    try client.writeHeaders(1, &headers, false);
    try client.writeData(1, "he", false);
    const ping_payload = [_]u8{ 1, 3, 3, 7, 0, 0, 0, 1 };
    try writeFrame(allocator, io, client.stream, .ping, 0, 0, &ping_payload);

    var ping_ack = try readFrame(allocator, io, client.stream, client.limits);
    defer ping_ack.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.ping, ping_ack.frame.header.frame_type);
    try std.testing.expect((ping_ack.frame.header.flags & flag_ack) != 0);
    try std.testing.expectEqualSlices(u8, &ping_payload, ping_ack.frame.payload);

    try client.writeData(1, "llo", true);
    var response = try client.readResponse(1, "POST", false, null);
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
}

test "HTTP/2 runtime ignores PRIORITY while reading request body" {
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
            try std.testing.expectEqualStrings("/priority-body", request.path);
            try std.testing.expectEqualStrings("hello", request.body);
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

    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/priority-body" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "content-length", .value = "5" },
    };
    try client.writeHeaders(1, &headers, false);
    try client.writeData(1, "he", false);

    var priority_bytes: std.ArrayList(u8) = .empty;
    defer priority_bytes.deinit(allocator);
    try http2.PriorityPayload.write(&priority_bytes, allocator, 1, false, 0, 32);
    try writeAll(io, client.stream, priority_bytes.items);
    try client.writeData(1, "llo", true);

    var response = try client.readResponse(1, "POST", false, null);
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
}

test "HTTP/2 runtime handles pre-request stream frame ordering" {
    const allocator = std.testing.allocator;

    {
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
        try writeFrame(allocator, io, client.stream, .data, flag_end_stream, 1, "body-before-headers");

        thread.join();
        if (shared.err) |err| return err;
        try std.testing.expect(shared.saw_expected);
    }

    {
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
                try std.testing.expectEqualStrings("/after-priority", request.path);
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

        var priority: std.ArrayList(u8) = .empty;
        defer priority.deinit(allocator);
        try http2.PriorityPayload.write(&priority, allocator, 1, false, 0, 16);
        try writeAll(io, client.stream, priority.items);

        var response = try client.request(.{
            .method = "GET",
            .path = "/after-priority",
            .authority = "localhost",
        });
        defer response.deinit(allocator);

        thread.join();
        if (shared.err) |err| return err;
        try std.testing.expectEqualStrings("ok", response.body);
    }
}
