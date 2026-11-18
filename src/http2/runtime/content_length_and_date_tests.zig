//! HTTP/2 content-length validation and Date-header tests.

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

test "HTTP/2 runtime validates request content-length" {
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
                if (err == error.InvalidContentLength) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.InvalidContentLength;
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
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/bad-length" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "+5" },
    };
    try client.writeHeaders(1, &fields, false);
    try client.writeData(1, "ping", true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 request writer defaults content-length for known body" {
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
            try std.testing.expectEqualStrings("/default-request-length", request.path);
            try std.testing.expectEqualStrings("ping", request.body);
            try std.testing.expectEqualStrings("4", findHeader(request.headers, "content-length") orelse return error.MissingPseudoHeader);
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
        .method = "POST",
        .path = "/default-request-length",
        .authority = "localhost",
        .body = "ping",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
}

test "HTTP/2 request writer defaults zero content-length for payload methods" {
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

            var post = try connection.readRequest();
            defer post.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/default-empty-post-length", post.path);
            try std.testing.expectEqualStrings("", post.body);
            try std.testing.expectEqualStrings("0", findHeader(post.headers, "content-length") orelse return error.MissingPseudoHeader);
            try connection.writeResponse(post.stream_id, .{ .body = "post" });

            var get = try connection.readRequest();
            defer get.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/default-empty-get-length", get.path);
            try std.testing.expectEqualStrings("", get.body);
            try std.testing.expect(findHeader(get.headers, "content-length") == null);
            try connection.writeResponse(get.stream_id, .{ .body = "get" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var post_response = try client.request(.{
        .method = "POST",
        .path = "/default-empty-post-length",
        .authority = "localhost",
    });
    defer post_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), post_response.status);
    try std.testing.expectEqualStrings("post", post_response.body);

    var get_response = try client.request(.{
        .method = "GET",
        .path = "/default-empty-get-length",
        .authority = "localhost",
    });
    defer get_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), get_response.status);
    try std.testing.expectEqualStrings("get", get_response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime validates request content-length before accepting trailers" {
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
                if (err == error.InvalidContentLength) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.InvalidContentLength;
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
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/bad-length-trailers" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "5" },
    };
    try client.writeHeaders(1, &fields, false);
    try client.writeData(1, "ping", false);
    try client.writeHeaders(1, &.{.{ .name = "request-checksum", .value = "ok" }}, true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 runtime validates response content-length and method body rules" {
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
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var mismatch = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer mismatch.deinit(shared.server.allocator);
            connection.writeHeaders(mismatch.stream_id, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "5" },
            }, false) catch |err| {
                shared.err = err;
                return;
            };
            connection.writeData(mismatch.stream_id, "pong", true) catch |err| {
                shared.err = err;
                return;
            };

            var head = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer head.deinit(shared.server.allocator);
            connection.writeResponse(head.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-length", .value = "5" }},
            }) catch |err| {
                shared.err = err;
                return;
            };

            var no_content = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer no_content.deinit(shared.server.allocator);
            connection.writeHeaders(no_content.stream_id, &.{
                .{ .name = ":status", .value = "204" },
                .{ .name = "content-length", .value = "0" },
            }, true) catch |err| {
                shared.err = err;
                return;
            };

            var connect = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer connect.deinit(shared.server.allocator);
            connection.writeResponse(connect.stream_id, .{
                .status = 200,
            }) catch |err| {
                shared.err = err;
                return;
            };
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
        .path = "/mismatch",
        .authority = "localhost",
    }));

    var head_response = try client.request(.{
        .method = "HEAD",
        .path = "/head",
        .authority = "localhost",
    });
    defer head_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head_response.status);
    try std.testing.expectEqualStrings("", head_response.body);

    try std.testing.expectError(error.InvalidContentLength, client.request(.{
        .method = "GET",
        .path = "/no-content-cl",
        .authority = "localhost",
    }));

    var connect_response = try client.request(.{
        .method = "CONNECT",
        .path = "example.com:443",
        .authority = "example.com:443",
    });
    defer connect_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), connect_response.status);
    try std.testing.expectEqualStrings("", connect_response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client consumes framed 205 content and reuses connection" {
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
            // Bypass the high-level sender to model a non-conforming peer.
            // A recipient still follows HTTP/2 framing and consumes DATA up
            // to END_STREAM instead of treating 205 like 204 or 304.
            try connection.writeHeaders(first.stream_id, &.{
                .{ .name = ":status", .value = "205" },
                .{ .name = "content-length", .value = "4" },
            }, false);
            try connection.writeData(first.stream_id, "body", true);
            connection.releasePeerStream(first.stream_id);

            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);
            try connection.writeResponse(second.stream_id, .{
                .body = "after",
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

    var reset = try client.request(.{
        .path = "/reset",
        .authority = "localhost",
    });
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 205), reset.status);
    try std.testing.expectEqualStrings("body", reset.body);

    var after = try client.request(.{
        .path = "/after",
        .authority = "localhost",
    });
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("after", after.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 response writer defaults content-length for known body" {
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
        observed_content_length: ?[]u8 = null,

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
            try std.testing.expectEqualStrings("/default-response-length", request.path);
            try connection.writeResponse(request.stream_id, .{
                .body = "known-body",
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
        .path = "/default-response-length",
        .authority = "localhost",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("known-body", response.body);
    try std.testing.expectEqualStrings("10", findHeader(response.headers, "content-length") orelse return error.MissingPseudoHeader);
    const date = findHeader(response.headers, "date") orelse
        return error.MissingPseudoHeader;
    try std.testing.expectEqual(@as(usize, http_date.value_len), date.len);
    try std.testing.expectEqualStrings("GMT", date[26..]);
}

test "HTTP/2 server preserves explicit Date and can disable automatic Date" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
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
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            try connection.writeResponse(first.stream_id, .{
                .headers = &.{.{
                    .name = "date",
                    .value = "Sun, 06 Nov 1994 08:49:37 GMT",
                }},
            });
            connection.limits.auto_date_header = false;
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);
            try connection.writeResponse(second.stream_id, .{});
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var explicit = try client.request(.{
        .path = "/explicit-date",
        .authority = "localhost",
    });
    defer explicit.deinit(allocator);
    try std.testing.expectEqualStrings(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        findHeader(explicit.headers, "date").?,
    );
    var disabled = try client.request(.{
        .path = "/disabled-date",
        .authority = "localhost",
    });
    defer disabled.deinit(allocator);
    try std.testing.expect(findHeader(disabled.headers, "date") == null);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 automatic Date appends without allocation after HPACK warmup" {
    const allocator = std.testing.allocator;
    var encoder = http2.Hpack.Encoder{};
    defer encoder.deinit(allocator);
    const date = "Sun, 06 Nov 1994 08:49:37 GMT".*;
    var fields_storage: [2]http2.Hpack.HeaderField = undefined;
    var fields: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(&fields_storage);

    fields.appendAssumeCapacity(.{ .name = ":status", .value = "200" });
    appendAutomaticDateHeaderValue(&fields, &date);
    _ = try encoder.encodeBlockRetained(allocator, fields.items);

    fields.clearRetainingCapacity();
    fields.appendAssumeCapacity(.{ .name = ":status", .value = "200" });
    appendAutomaticDateHeaderValue(&fields, &date);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    _ = try encoder.encodeBlockRetained(no_alloc.allocator(), fields.items);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 2), fields.items.len);
    try std.testing.expectEqualStrings("date", fields.items[1].name);
    try std.testing.expectEqualStrings(&date, fields.items[1].value);
}

test "HTTP/2 batch Date preflight reports only missing retained fields" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.response_semantics.deinit(std.testing.allocator);
        connection.response_semantics_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expect(try connection.validateResponseBatchMember(
        1,
        .{},
        true,
    ));
    try std.testing.expect(!(try connection.validateResponseBatchMember(
        1,
        .{ .headers = &.{.{
            .name = "date",
            .value = "Sun, 06 Nov 1994 08:49:37 GMT",
        }} },
        true,
    )));
    // A field nominated by Connection is removed before this decision.
    try std.testing.expect(try connection.validateResponseBatchMember(
        1,
        .{ .headers = &.{
            .{ .name = "connection", .value = "date" },
            .{
                .name = "date",
                .value = "Sun, 06 Nov 1994 08:49:37 GMT",
            },
        } },
        true,
    ));

    connection.limits.auto_date_header = false;
    try std.testing.expect(!(try connection.validateResponseBatchMember(
        1,
        .{},
        true,
    )));
}

test "HTTP/2 client accepts zero Content-Length on successful CONNECT tunnel" {
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

            // Hyper accepts a zero Content-Length from peers on a successful
            // CONNECT response even though the stream switches to tunnel mode
            // after the 2xx HEADERS.  Non-zero lengths remain rejected below.
            try connection.writeHeaders(request.stream_id, &.{
                .{ .name = ":status", .value = "200" },
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

    var response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("0", findHeader(response.headers, "content-length") orelse return error.MissingPseudoHeader);
}
