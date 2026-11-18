//! HTTP/2 control-reader tests moved out of the runtime test root.

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

test "HTTP/2 readPing ignores ACK frames" {
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
        observed: [8]u8 = undefined,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server, &shared.observed) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server, observed: *[8]u8) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            observed.* = try connection.readPing();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try writeFrame(allocator, io, client.stream, .ping, flag_ack, 0, &.{ 1, 1, 1, 1, 1, 1, 1, 1 });
    try writeFrame(allocator, io, client.stream, .ping, 0, 0, &.{ 2, 3, 5, 7, 11, 13, 17, 19 });

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 2, 3, 5, 7, 11, 13, 17, 19 }, &shared.observed);
}

test "HTTP/2 ping helpers handle interleaved control frames" {
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

            try connection.sendWindowUpdate(0, 321);
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .ping, flag_ack, 0, &.{ 9, 9, 9, 9, 9, 9, 9, 9 });
            const observed = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, &observed);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const ack = try client.ping(.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, &ack);
    try std.testing.expectEqual(@as(i64, default_flow_window + 321), client.send_connection_window.value);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 wait helpers reject unbuffered application frames" {
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
    const data_frame = http2.Frame{
        .header = .{ .length = 1, .frame_type = .data, .flags = 0, .stream_id = 1 },
        .payload = "x",
    };
    try std.testing.expect(!try connection.handleConnectionOrGoAwayFrame(data_frame));
}

test "HTTP/2 readWindowUpdate handles interleaved PING" {
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

            const ping_payload = [_]u8{ 4, 8, 15, 16, 23, 42, 0, 1 };
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .ping, 0, 0, &ping_payload);
            try connection.sendWindowUpdate(0, 777);

            while (true) {
                var frame = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
                defer frame.deinit(server_ptr.allocator);
                if (frame.frame.header.frame_type != .ping) continue;
                try std.testing.expect((frame.frame.header.flags & flag_ack) != 0);
                try std.testing.expectEqualSlices(u8, &ping_payload, frame.frame.payload);
                break;
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

    var update = try client.readWindowUpdate();
    defer update.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 0), update.window_update.stream_id);
    try std.testing.expectEqual(@as(u31, 777), update.window_update.increment);
    try std.testing.expectEqual(@as(i64, default_flow_window + 777), client.send_connection_window.value);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 owned control readers release unexpected frames exactly once" {
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
            for ([_]u31{ 1, 3, 5 }) |stream_id| {
                try writeFrame(
                    self.server.allocator,
                    self.server.io,
                    connection.stream,
                    .headers,
                    flag_end_headers | flag_end_stream,
                    stream_id,
                    &.{},
                );
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();

    try std.testing.expectError(error.UnexpectedFrame, client.readResetStream());
    try std.testing.expectError(error.UnexpectedFrame, client.readGoAway());
    try std.testing.expectError(error.UnexpectedFrame, client.readWindowUpdate());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 readWindowUpdate records interleaved GOAWAY" {
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
            try connection.sendGoAway(3, .no_error, "draining");
            try connection.sendWindowUpdate(0, 99);
            _ = try connection.readPing();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();

    var update = try client.readWindowUpdate();
    defer update.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 99), update.window_update.increment);
    try std.testing.expectEqual(@as(?u31, 3), client.peer_goaway_last_stream_id);
    _ = try client.ping(.{ 0, 1, 0, 1, 0, 1, 0, 1 });

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 readWindowUpdate enforces local error reset budget" {
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            const overflow = [_]u8{ 0, 0, 0, 1 };

            try writeFrame(
                self.server.allocator,
                self.server.io,
                connection.stream,
                .window_update,
                0,
                1,
                &overflow,
            );
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(2),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.flow_control_error,
                reset.reset.error_code,
            );

            try writeFrame(
                self.server.allocator,
                self.server.io,
                connection.stream,
                .window_update,
                0,
                3,
                &overflow,
            );
            var goaway = try connection.readGoAwayWithTimeout(
                .fromSeconds(2),
            );
            defer goaway.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 0), goaway.goaway.last_stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.enhance_your_calm,
                goaway.goaway.error_code,
            );
            try std.testing.expectEqualStrings(
                "too_many_internal_resets",
                goaway.goaway.debug_data,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), limits);
    defer client.close();
    try client.addActiveLocalStream(1);
    try client.addActiveLocalStream(3);
    (try client.sendStreamWindow(1)).value = max_flow_window;
    (try client.sendStreamWindow(3)).value = max_flow_window;

    var first = try client.readWindowUpdateWithTimeout(.fromSeconds(2));
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), first.window_update.stream_id);
    try std.testing.expectEqual(@as(usize, 1), client.local_error_reset_streams);

    try std.testing.expectError(
        error.ConnectionGoAway,
        client.readWindowUpdateWithTimeout(.fromSeconds(2)),
    );
    try std.testing.expect(client.aggregate_timeout_unusable);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 readGoAway handles interleaved PING" {
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

            const ping_payload = [_]u8{ 9, 9, 8, 8, 7, 7, 6, 6 };
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .ping, 0, 0, &ping_payload);
            try connection.sendGoAway(0, .no_error, "bye");

            while (true) {
                var frame = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
                defer frame.deinit(server_ptr.allocator);
                if (frame.frame.header.frame_type != .ping) continue;
                try std.testing.expect((frame.frame.header.flags & flag_ack) != 0);
                try std.testing.expectEqualSlices(u8, &ping_payload, frame.frame.payload);
                break;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();

    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.no_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("bye", goaway.goaway.debug_data);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 readResetStream handles interleaved PING" {
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

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            const ping_payload = [_]u8{ 1, 4, 1, 4, 2, 1, 3, 5 };
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .ping, 0, 0, &ping_payload);
            try connection.sendResetStream(request.stream_id, .cancel);

            while (true) {
                var frame = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
                defer frame.deinit(server_ptr.allocator);
                if (frame.frame.header.frame_type != .ping) continue;
                try std.testing.expect((frame.frame.header.flags & flag_ack) != 0);
                try std.testing.expectEqualSlices(u8, &ping_payload, frame.frame.payload);
                break;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();

    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/reset-interleaved-ping" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try client.writeHeaders(1, &fields, true);

    var reset = try client.readResetStream();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);

    thread.join();
    if (shared.err) |err| return err;
}
