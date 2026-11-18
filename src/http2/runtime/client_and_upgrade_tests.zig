//! HTTP/2 client URI and h2c-upgrade tests.

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

test "HTTP/2 client connects by host name" {
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
            try std.testing.expectEqualStrings("http", request.scheme);
            var expected_authority: [32]u8 = undefined;
            const rendered_authority = try std.fmt.bufPrint(&expected_authority, "localhost:{d}", .{server_ptr.address().ip4.port});
            try std.testing.expectEqualStrings(rendered_authority, request.authority.?);
            try connection.writeResponse(request.stream_id, .{ .body = "h2-dns-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/dns",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("h2-dns-ok", response.body);
}

test "HTTP/2 client sends request to URI" {
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
            try std.testing.expectEqualStrings("/h2-uri?x=1", request.path);
            try std.testing.expectEqualStrings("http", request.scheme);
            var expected_authority: [32]u8 = undefined;
            const rendered_authority = try std.fmt.bufPrint(&expected_authority, "localhost:{d}", .{server_ptr.address().ip4.port});
            try std.testing.expectEqualStrings(rendered_authority, request.authority.?);
            try connection.writeResponse(request.stream_id, .{ .body = "h2-uri-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://localhost:{d}/h2-uri?x=1", .{server.address().ip4.port});
    defer allocator.free(uri);
    var response = try Client.requestUri(allocator, io, uri, .{}, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("h2-uri-ok", response.body);

    try std.testing.expectError(error.UnsupportedScheme, Client.requestUri(allocator, io, "ftp://localhost/", .{}, .{}));
    try std.testing.expectError(error.InvalidUri, Client.requestUri(allocator, io, "http:///missing-host", .{}, .{}));
}

test "HTTP/2 client sends request to bracketed IPv6 URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.listen(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    ) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
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
            try std.testing.expectEqualStrings("/h2-ipv6?x=1", request.path);
            try std.testing.expectEqualStrings("http", request.scheme);
            var expected_authority: [64]u8 = undefined;
            const rendered_authority = try std.fmt.bufPrint(&expected_authority, "[::1]:{d}", .{server_ptr.address().ip6.port});
            try std.testing.expectEqualStrings(rendered_authority, request.authority.?);
            try connection.writeResponse(request.stream_id, .{ .body = "h2-ipv6-uri-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://[::1]:{d}/h2-ipv6?x=1", .{server.address().ip6.port});
    defer allocator.free(uri);
    var response = try Client.requestUri(allocator, io, uri, .{}, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("h2-ipv6-uri-ok", response.body);
}

test "HTTP/2 h2c upgrade carries request body and trailers on stream one" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try net.IpAddress.listen(&.{ .ip4 = .loopback(0) }, io, .{ .reuse_address = true });
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

            var request = try http1_runtime.readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer request.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/upgrade?x=1", request.request.target);
            try std.testing.expectEqualStrings("h2c", request.request.header("upgrade").?);
            try std.testing.expect(containsHttpToken(request.request.header("connection").?, "http2-settings"));
            try std.testing.expect(request.request.header("http2-settings") != null);
            try std.testing.expectEqualStrings("upgrade-body", request.request.body);
            try std.testing.expectEqual(@as(usize, 1), request.request.trailers.len);
            try std.testing.expectEqualStrings(
                "x-upload-complete",
                request.request.trailers[0].name,
            );
            try std.testing.expectEqualStrings(
                "yes",
                request.request.trailers[0].value,
            );

            try writeAll(shared.io, stream, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n");

            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(shared.io, stream, &preface);
            try http2.validateClientPreface(&preface);
            var client_settings = try readFrame(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 });
            defer client_settings.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_settings.frame.header.frame_type);

            var server_settings_payload: std.ArrayList(u8) = .empty;
            defer server_settings_payload.deinit(shared.allocator);
            try http2.writeSettings(&server_settings_payload, shared.allocator, &.{.{ .id = .max_frame_size, .value = 16_384 }});
            try writeFrame(shared.allocator, shared.io, stream, .settings, 0, 0, server_settings_payload.items);
            try writeFrame(shared.allocator, shared.io, stream, .settings, flag_ack, 0, &.{});
            var client_ack = try readFrame(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 });
            defer client_ack.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_ack.frame.header.frame_type);
            try std.testing.expect((client_ack.frame.header.flags & flag_ack) != 0);

            var response_block: std.ArrayList(u8) = .empty;
            defer response_block.deinit(shared.allocator);
            try http2.Hpack.encodeLiteralBlock(&response_block, shared.allocator, &.{.{ .name = ":status", .value = "200" }});
            try writeFrame(shared.allocator, shared.io, stream, .headers, flag_end_headers, 1, response_block.items);
            try writeFrame(shared.allocator, shared.io, stream, .data, flag_end_stream, 1, "upgraded");
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://localhost:{d}/upgrade?x=1", .{listener.socket.address.ip4.port});
    defer allocator.free(uri);
    var response = try Client.requestUriUpgrade(allocator, io, uri, .{
        .method = "POST",
        .body = "upgrade-body",
        .trailers = &.{.{
            .name = "x-upload-complete",
            .value = "yes",
        }},
    }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("upgraded", response.body);
}

test "HTTP/2 server accepts body-bearing h2c upgrade request" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
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
            var upgrade = try server_ptr.acceptUpgrade();
            defer upgrade.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 1), upgrade.stream_id);
            try std.testing.expect(upgrade.request.request.method == .POST);
            try std.testing.expectEqualStrings("/server-upgrade", upgrade.request.request.target);
            try std.testing.expectEqualStrings("request-body", upgrade.request.request.body);
            try std.testing.expectEqual(@as(usize, 1), upgrade.request.request.trailers.len);
            try std.testing.expectEqualStrings(
                "done",
                upgrade.request.request.trailers[0].value,
            );
            try upgrade.connection.writeResponse(upgrade.stream_id, .{ .body = "server-upgraded" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://localhost:{d}/server-upgrade", .{server.address().ip4.port});
    defer allocator.free(uri);
    var response = try Client.requestUriUpgrade(allocator, io, uri, .{
        .method = "POST",
        .body = "request-body",
        .trailers = &.{.{ .name = "x-upload-complete", .value = "done" }},
    }, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("server-upgraded", response.body);
}
